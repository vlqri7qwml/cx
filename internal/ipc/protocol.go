// Package ipc 定义托盘与后台服务之间的命名管道协议。
//
// 服务以 LocalSystem 身份运行，托盘以登录用户身份运行，两者权限相差很大。
// 所有特权操作（改配置、退出保护）都必须经由这里的协议提交，
// 并由服务端校验管理员密码 —— 托盘自己拿不到配置里的明文密码，
// 也无法绕过断网保护。
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vlqri7qwml/cx/internal/checker"
	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/tunnel"
)

// Op 是请求操作名。
type Op string

const (
	// OpStatus 查询当前状态，无需密码。
	OpStatus Op = "status"
	// OpConnect 连接当前选中的节点。
	OpConnect Op = "connect"
	// OpDisconnect 断开代理（断网保护仍然生效，整机随即无网）。
	OpDisconnect Op = "disconnect"
	// OpSelectNode 切换节点并立即重连。
	OpSelectNode Op = "select_node"
	// OpTestNode 测试某个节点的连通性与延迟。
	OpTestNode Op = "test_node"
	// OpCheckExitIP 经代理探测出口 IP 与归属地。
	OpCheckExitIP Op = "check_exit_ip"
	// OpGetConfig 读取脱敏后的配置。
	OpGetConfig Op = "get_config"
	// OpSaveConfig 保存配置，需要管理员密码。
	OpSaveConfig Op = "save_config"
	// OpSetPassword 设置或修改管理员密码；已设置时需提供旧密码。
	OpSetPassword Op = "set_password"
	// OpExit 校验管理员密码后拆除断网保护并停止服务，恢复直连。
	OpExit Op = "exit"
)

// State 是服务的运行状态。
type State string

const (
	// StateDisconnected 代理未连接。此时断网保护仍在，整机无法上网。
	StateDisconnected State = "disconnected"
	// StateConnecting 正在连接。
	StateConnecting State = "connecting"
	// StateConnected 已连接，流量正经代理出网。
	StateConnected State = "connected"
	// StateError 连接失败。整机依旧无网，等待重试。
	StateError State = "error"
	// StateStopping 正在退出保护。
	StateStopping State = "stopping"
)

// Label 返回状态的中文说明。
func (s State) Label() string {
	switch s {
	case StateDisconnected:
		return "已断开（整机无网）"
	case StateConnecting:
		return "正在连接…"
	case StateConnected:
		return "已连接"
	case StateError:
		return "连接失败（整机无网）"
	case StateStopping:
		return "正在退出保护…"
	}
	return string(s)
}

// NodeBrief 是节点在状态里的精简表示（不含任何密码）。
type NodeBrief struct {
	Index int    `json:"index"`
	Label string `json:"label"`
	Addr  string `json:"addr"`
	// LatencyMS 为上次测速结果，-1 表示未测或失败。
	LatencyMS int `json:"latency_ms"`
	// Region 为上次探测到的出口地区。
	Region string `json:"region,omitempty"`
}

// Status 是服务状态快照。
type Status struct {
	State   State  `json:"state"`
	Message string `json:"message,omitempty"`

	NodeIndex int         `json:"node_index"`
	NodeLabel string      `json:"node_label,omitempty"`
	Nodes     []NodeBrief `json:"nodes,omitempty"`

	// KillSwitch 表示持久化断网保护规则当前是否在位。
	KillSwitch bool `json:"kill_switch"`
	AllowLAN   bool `json:"allow_lan"`
	BlockQUIC  bool `json:"block_quic"`

	HasPassword bool   `json:"has_password"`
	TunName     string `json:"tun_name,omitempty"`
	ProxyAddr   string `json:"proxy_addr,omitempty"`

	Exit  *checker.ExitInfo `json:"exit,omitempty"`
	Stats tunnel.Snapshot   `json:"stats"`

	Since   time.Time `json:"since"`
	Version string    `json:"version,omitempty"`
	LogDir  string    `json:"log_dir,omitempty"`
}

// Request 是托盘发往服务的一条请求。
type Request struct {
	Op Op `json:"op"`

	// Password 用于需要鉴权的操作。
	Password string `json:"password,omitempty"`
	// NewPassword 仅用于 OpSetPassword。
	NewPassword string `json:"new_password,omitempty"`

	// Index 用于 OpSelectNode / OpTestNode。
	Index int `json:"index,omitempty"`

	// Config 用于 OpSaveConfig。
	Config *config.Config `json:"config,omitempty"`
}

// Response 是服务的应答。
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	Status *Status           `json:"status,omitempty"`
	Config *config.Config    `json:"config,omitempty"`
	Exit   *checker.ExitInfo `json:"exit,omitempty"`
	// LatencyMS 用于 OpTestNode。
	LatencyMS int `json:"latency_ms,omitempty"`
}

// Err 返回应答里的错误（OK 为 true 时返回 nil）。
func (r *Response) Err() error {
	if r == nil {
		return errors.New("服务没有返回任何应答")
	}
	if r.OK {
		return nil
	}
	if r.Error == "" {
		return errors.New("服务返回未知错误")
	}
	return errors.New(r.Error)
}

// Fail 构造失败应答。
func Fail(err error) Response {
	if err == nil {
		return Response{OK: false, Error: "未知错误"}
	}
	return Response{OK: false, Error: err.Error()}
}

// Failf 构造失败应答。
func Failf(format string, args ...any) Response {
	return Response{OK: false, Error: fmt.Sprintf(format, args...)}
}

// maxMessageSize 限制单条消息大小，避免恶意客户端耗尽内存。
const maxMessageSize = 1 << 20

// Codec 在一条连接上读写 JSON 消息（每条消息一行）。
//
// 它与具体传输无关，因此可以在任何平台上用 net.Pipe 做单元测试。
// 读取按行进行并限制单行长度：托盘会在同一条连接上长期轮询状态，
// 因此上限必须是“每条消息”的，而不是整条连接的累计字节数。
type Codec struct {
	rwc io.ReadWriteCloser
	sc  *bufio.Scanner
	enc *json.Encoder
}

// NewCodec 基于一条连接创建编解码器。
func NewCodec(rwc io.ReadWriteCloser) *Codec {
	sc := bufio.NewScanner(rwc)
	sc.Buffer(make([]byte, 0, 64<<10), maxMessageSize)
	return &Codec{rwc: rwc, sc: sc, enc: json.NewEncoder(rwc)}
}

// readMessage 读取一行并返回其原始字节。
func (c *Codec) readMessage() ([]byte, error) {
	for {
		if !c.sc.Scan() {
			if err := c.sc.Err(); err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		if line := bytes.TrimSpace(c.sc.Bytes()); len(line) > 0 {
			return line, nil
		}
	}
}

// WriteRequest 发送一条请求。
func (c *Codec) WriteRequest(r Request) error { return c.enc.Encode(r) }

// ReadRequest 读取一条请求。
func (c *Codec) ReadRequest() (Request, error) {
	var r Request
	line, err := c.readMessage()
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return r, fmt.Errorf("请求格式错误: %w", err)
	}
	return r, nil
}

// WriteResponse 发送一条应答。
func (c *Codec) WriteResponse(r Response) error { return c.enc.Encode(r) }

// ReadResponse 读取一条应答。
func (c *Codec) ReadResponse() (Response, error) {
	var r Response
	line, err := c.readMessage()
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return r, fmt.Errorf("应答格式错误: %w", err)
	}
	return r, nil
}

// Close 关闭底层连接。
func (c *Codec) Close() error { return c.rwc.Close() }

// Handler 由服务端实现，处理单条请求。
type Handler interface {
	Handle(req Request) Response
}

// HandlerFunc 让普通函数满足 Handler。
type HandlerFunc func(Request) Response

// Handle 实现 Handler。
func (f HandlerFunc) Handle(r Request) Response { return f(r) }

// ServeConn 在一条连接上循环处理请求，直到对端断开。
func ServeConn(rwc io.ReadWriteCloser, h Handler) {
	c := NewCodec(rwc)
	defer c.Close()
	for {
		req, err := c.ReadRequest()
		if err != nil {
			return
		}
		resp := h.Handle(req)
		if err := c.WriteResponse(resp); err != nil {
			return
		}
	}
}
