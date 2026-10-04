// Package checker 经代理探测出口 IP 与归属地。
//
// 这是运维上最关键的一次确认：公司要求所有流量从 Texas 出口，
// 托盘里直接显示出口 IP 与州/城市，便于一眼看出当前节点是否符合要求。
package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ExitInfo 描述一次出口探测结果。
type ExitInfo struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	City      string    `json:"city"`
	ISP       string    `json:"isp"`
	Source    string    `json:"source"`
	CheckedAt time.Time `json:"checked_at"`
}

// Label 返回适合显示在托盘提示里的一行文本。
func (e *ExitInfo) Label() string {
	if e == nil || e.IP == "" {
		return "出口未知"
	}
	parts := make([]string, 0, 3)
	if e.Region != "" {
		parts = append(parts, e.Region)
	}
	if e.City != "" {
		parts = append(parts, e.City)
	}
	if len(parts) == 0 {
		if e.Country != "" {
			return e.IP + " · " + e.Country
		}
		return e.IP
	}
	return e.IP + " · " + strings.Join(parts, ", ")
}

// InRegion 判断出口是否落在期望的州/地区（大小写与缩写不敏感）。
func (e *ExitInfo) InRegion(want string) bool {
	if e == nil || want == "" {
		return false
	}
	want = strings.ToLower(strings.TrimSpace(want))
	return strings.ToLower(e.Region) == want ||
		strings.Contains(strings.ToLower(e.Region), want)
}

// DialFunc 经代理建立到 target 的 TCP 连接。
type DialFunc func(ctx context.Context, target string) (net.Conn, error)

// Endpoint 是一个可用的查询接口。
type Endpoint struct {
	Name  string
	URL   string
	Parse func([]byte) (*ExitInfo, error)
}

// DefaultEndpoints 按顺序尝试；HTTP 的放前面，TLS 失败时还有退路。
func DefaultEndpoints() []Endpoint {
	return []Endpoint{
		{Name: "ip-api.com", URL: "http://ip-api.com/json/?fields=status,message,country,regionName,city,isp,query", Parse: parseIPAPI},
		{Name: "ipinfo.io", URL: "https://ipinfo.io/json", Parse: parseIPInfo},
	}
}

// ErrAllEndpointsFailed 表示所有探测接口都失败了。
var ErrAllEndpointsFailed = errors.New("所有出口探测接口均不可用")

// Check 依次尝试各接口，返回第一个成功的结果。
func Check(ctx context.Context, dial DialFunc, endpoints []Endpoint, timeout time.Duration) (*ExitInfo, error) {
	if dial == nil {
		return nil, errors.New("checker: 未提供代理 Dial")
	}
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints()
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial(ctx, addr)
			},
			// 探测请求很短，不值得维护连接池。
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
		},
	}

	var errs []string
	for _, ep := range endpoints {
		info, err := fetch(ctx, client, ep)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ep.Name, err))
			continue
		}
		info.Source = ep.Name
		info.CheckedAt = time.Now()
		return info, nil
	}
	return nil, fmt.Errorf("%w (%s)", ErrAllEndpointsFailed, strings.Join(errs, "; "))
}

func fetch(ctx context.Context, client *http.Client, ep Endpoint) (*ExitInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CXProxy/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 限制读取量，防止接口异常时拉回超大响应。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return ep.Parse(body)
}

func parseIPAPI(b []byte) (*ExitInfo, error) {
	var r struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Query      string `json:"query"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("应答不是合法 JSON: %w", err)
	}
	if r.Status != "" && r.Status != "success" {
		if r.Message != "" {
			return nil, fmt.Errorf("接口返回失败: %s", r.Message)
		}
		return nil, fmt.Errorf("接口返回状态 %q", r.Status)
	}
	if r.Query == "" {
		return nil, errors.New("应答缺少 IP 字段")
	}
	return &ExitInfo{
		IP:      r.Query,
		Country: r.Country,
		Region:  r.RegionName,
		City:    r.City,
		ISP:     r.ISP,
	}, nil
}

func parseIPInfo(b []byte) (*ExitInfo, error) {
	var r struct {
		IP      string `json:"ip"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"`
		Org     string `json:"org"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("应答不是合法 JSON: %w", err)
	}
	if r.IP == "" {
		return nil, errors.New("应答缺少 IP 字段")
	}
	return &ExitInfo{
		IP:      r.IP,
		Country: r.Country,
		Region:  r.Region,
		City:    r.City,
		ISP:     r.Org,
	}, nil
}
