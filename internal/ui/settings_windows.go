package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/lxn/walk"

	"github.com/vlqri7qwml/cx/internal/config"
	"github.com/vlqri7qwml/cx/internal/ipc"
)

// nodeModel 是节点表格的数据源。
type nodeModel struct {
	walk.TableModelBase
	nodes   []config.Node
	latency map[int]int
	regions map[int]string
	active  int
}

func (m *nodeModel) RowCount() int { return len(m.nodes) }

func (m *nodeModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.nodes) {
		return ""
	}
	n := m.nodes[row]
	switch col {
	case 0:
		if row == m.active {
			return "●"
		}
		return ""
	case 1:
		return n.Name
	case 2:
		return n.Addr()
	case 3:
		if n.Username == "" {
			return "（无认证）"
		}
		return n.Username
	case 4:
		if n.NoUDP {
			return "否"
		}
		return "是"
	case 5:
		if ms, ok := m.latency[row]; ok && ms >= 0 {
			return fmt.Sprintf("%d ms", ms)
		}
		return "—"
	case 6:
		if r := m.regions[row]; r != "" {
			return r
		}
		return "—"
	}
	return ""
}

// settingsWindow 是设置窗口。
type settingsWindow struct {
	dlg    *walk.Dialog
	cli    *client
	model  *nodeModel
	table  *walk.TableView
	dns    *walk.LineEdit
	allow  *walk.CheckBox
	quic   *walk.CheckBox
	auto   *walk.CheckBox
	status *walk.Label

	cfg         *config.Config
	hasPassword bool
}

// showSettings 打开设置窗口。forcePassword 为 true 时（尚未设置管理员密码）
// 会先强制设置密码，否则没有密码的“退出保护”等于形同虚设。
func showSettings(owner walk.Form, cli *client, st *ipc.Status, forcePassword bool) {
	resp, err := cli.call(ipc.Request{Op: ipc.OpGetConfig})
	if err != nil {
		showError(owner, "读取配置失败", err)
		return
	}
	cfg := resp.Config
	if cfg == nil {
		showWarn(owner, "读取配置失败", "服务没有返回配置内容")
		return
	}

	w := &settingsWindow{cli: cli, cfg: cfg, hasPassword: st != nil && st.HasPassword}
	w.model = &nodeModel{
		nodes:   append([]config.Node(nil), cfg.Nodes...),
		latency: map[int]int{},
		regions: map[int]string{},
		active:  cfg.Active,
	}
	if st != nil {
		for _, n := range st.Nodes {
			if n.LatencyMS >= 0 {
				w.model.latency[n.Index] = n.LatencyMS
			}
			if n.Region != "" {
				w.model.regions[n.Index] = n.Region
			}
		}
	}

	if err := w.build(owner); err != nil {
		showError(owner, "打开设置失败", err)
		return
	}
	defer w.dlg.Dispose()

	if forcePassword || !w.hasPassword {
		w.dlg.Starting().Once(func() {
			showInfo(w.dlg, "请先设置管理员密码",
				"尚未设置管理员密码。在设置密码之前，无法保存配置，也无法退出断网保护。")
			w.changePassword()
		})
	}
	w.dlg.Run()
}

func (w *settingsWindow) build(owner walk.Form) error {
	dlg, err := walk.NewDialog(owner)
	if err != nil {
		return err
	}
	w.dlg = dlg
	dlg.SetTitle("CXProxy 设置")
	dlg.SetLayout(walk.NewVBoxLayout())
	if err := dlg.SetSize(walk.Size{Width: 860, Height: 560}); err != nil {
		return err
	}

	// ---- 节点列表 ----
	group, err := walk.NewGroupBox(dlg)
	if err != nil {
		return err
	}
	_ = group.SetTitle("SOCKS5 节点")
	group.SetLayout(walk.NewHBoxLayout())

	tv, err := walk.NewTableView(group)
	if err != nil {
		return err
	}
	w.table = tv
	tv.SetAlternatingRowBG(true)
	_ = tv.SetMultiSelection(false)
	for _, c := range []struct {
		title string
		width int
	}{
		{"当前", 44}, {"名称", 180}, {"地址", 190},
		{"用户名", 120}, {"UDP", 56}, {"延迟", 80}, {"出口地区", 120},
	} {
		col := walk.NewTableViewColumn()
		_ = col.SetTitle(c.title)
		_ = col.SetWidth(c.width)
		if err := tv.Columns().Add(col); err != nil {
			return err
		}
	}
	if err := tv.SetModel(w.model); err != nil {
		return err
	}
	tv.ItemActivated().Attach(w.setActive)

	btns, err := walk.NewComposite(group)
	if err != nil {
		return err
	}
	btns.SetLayout(walk.NewVBoxLayout())
	for _, b := range []struct {
		text string
		fn   func()
	}{
		{"批量导入…", w.importNodes},
		{"设为当前", w.setActive},
		{"测试连通性", w.testSelected},
		{"上移", func() { w.move(-1) }},
		{"下移", func() { w.move(1) }},
		{"删除", w.remove},
	} {
		pb, err := walk.NewPushButton(btns)
		if err != nil {
			return err
		}
		_ = pb.SetText(b.text)
		pb.Clicked().Attach(b.fn)
	}
	spacer, _ := walk.NewLabel(btns)
	_ = spacer.SetText("")

	// ---- 选项 ----
	opts, err := walk.NewGroupBox(dlg)
	if err != nil {
		return err
	}
	_ = opts.SetTitle("选项")
	opts.SetLayout(walk.NewVBoxLayout())

	dnsRow, _ := walk.NewComposite(opts)
	dnsRow.SetLayout(walk.NewHBoxLayout())
	dnsLabel, _ := walk.NewLabel(dnsRow)
	_ = dnsLabel.SetText("上游 DNS（逗号分隔，查询统一经代理以 TCP 发出）：")
	w.dns, err = walk.NewLineEdit(dnsRow)
	if err != nil {
		return err
	}
	_ = w.dns.SetText(strings.Join(w.cfg.DNSServers, ", "))

	w.allow, _ = walk.NewCheckBox(opts)
	_ = w.allow.SetText("断网时仍允许访问局域网（内网打印机、NAS、办公系统）")
	w.allow.SetChecked(w.cfg.AllowLAN)

	w.quic, _ = walk.NewCheckBox(opts)
	_ = w.quic.SetText("阻止 QUIC（UDP 443）—— 迫使浏览器回落 TCP，代理下更稳定")
	w.quic.SetChecked(w.cfg.BlockQUIC)

	w.auto, _ = walk.NewCheckBox(opts)
	_ = w.auto.SetText("服务启动时自动连接（开机即接管流量）")
	w.auto.SetChecked(w.cfg.AutoConnect)

	warn, _ := walk.NewLabel(opts)
	_ = warn.SetText("提示：断网保护始终生效。代理未连接时整机无法上网，\n" +
		"只有在托盘中输入管理员密码并选择「退出（恢复网络）」才会恢复直连。")

	// ---- 底部按钮 ----
	bottom, err := walk.NewComposite(dlg)
	if err != nil {
		return err
	}
	bottom.SetLayout(walk.NewHBoxLayout())

	w.status, _ = walk.NewLabel(bottom)
	_ = w.status.SetText("")

	pw, _ := walk.NewPushButton(bottom)
	_ = pw.SetText("修改管理员密码…")
	pw.Clicked().Attach(w.changePassword)

	save, err := walk.NewPushButton(bottom)
	if err != nil {
		return err
	}
	_ = save.SetText("保存")
	save.Clicked().Attach(w.save)

	cancel, err := walk.NewPushButton(bottom)
	if err != nil {
		return err
	}
	_ = cancel.SetText("取消")
	cancel.Clicked().Attach(dlg.Cancel)

	_ = dlg.SetDefaultButton(save)
	_ = dlg.SetCancelButton(cancel)
	return nil
}

func (w *settingsWindow) selected() int {
	if w.table == nil {
		return -1
	}
	return w.table.CurrentIndex()
}

func (w *settingsWindow) importNodes() {
	nodes, ok := askNodeLines(w.dlg)
	if !ok {
		return
	}
	added := 0
	for _, n := range nodes {
		dup := false
		for _, e := range w.model.nodes {
			if e.Equal(n) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		w.model.nodes = append(w.model.nodes, n)
		added++
	}
	if w.model.active < 0 && len(w.model.nodes) > 0 {
		w.model.active = 0
	}
	w.model.PublishRowsReset()
	_ = w.status.SetText(fmt.Sprintf("已导入 %d 条（跳过 %d 条重复），记得点「保存」",
		added, len(nodes)-added))
}

func (w *settingsWindow) setActive() {
	i := w.selected()
	if i < 0 {
		showWarn(w.dlg, "提示", "请先在列表中选中一个节点")
		return
	}
	w.model.active = i
	w.model.PublishRowsReset()
	_ = w.table.SetCurrentIndex(i)
	_ = w.status.SetText("已设为当前节点，点「保存」后生效")
}

func (w *settingsWindow) move(delta int) {
	i := w.selected()
	j := i + delta
	if i < 0 || j < 0 || j >= len(w.model.nodes) {
		return
	}
	w.model.nodes[i], w.model.nodes[j] = w.model.nodes[j], w.model.nodes[i]
	switch w.model.active {
	case i:
		w.model.active = j
	case j:
		w.model.active = i
	}
	// 延迟与地区是按序号记录的，交换后一并跟随。
	w.model.latency[i], w.model.latency[j] = w.model.latency[j], w.model.latency[i]
	w.model.regions[i], w.model.regions[j] = w.model.regions[j], w.model.regions[i]
	w.model.PublishRowsReset()
	_ = w.table.SetCurrentIndex(j)
}

func (w *settingsWindow) remove() {
	i := w.selected()
	if i < 0 {
		showWarn(w.dlg, "提示", "请先在列表中选中一个节点")
		return
	}
	n := w.model.nodes[i]
	if !confirm(w.dlg, "删除节点", fmt.Sprintf("确定删除节点「%s」吗？", n.Label())) {
		return
	}
	w.model.nodes = append(w.model.nodes[:i], w.model.nodes[i+1:]...)
	delete(w.model.latency, i)
	delete(w.model.regions, i)
	if w.model.active >= len(w.model.nodes) {
		w.model.active = len(w.model.nodes) - 1
	}
	w.model.PublishRowsReset()
	_ = w.status.SetText("已删除，点「保存」后生效")
}

// testSelected 测试选中节点。注意：测速走的是服务里已保存的配置，
// 因此新导入但尚未保存的节点需要先保存再测。
func (w *settingsWindow) testSelected() {
	i := w.selected()
	if i < 0 {
		showWarn(w.dlg, "提示", "请先在列表中选中一个节点")
		return
	}
	if i >= len(w.cfg.Nodes) || !w.model.nodes[i].Equal(w.cfg.Nodes[i]) {
		showWarn(w.dlg, "请先保存", "该节点尚未保存到服务，请先点「保存」再测试。")
		return
	}

	_ = w.status.SetText("正在测试…")
	resp, err := w.cli.callWithTimeout(ipc.Request{Op: ipc.OpTestNode, Index: i}, 20*time.Second)
	if err != nil {
		_ = w.status.SetText("测试失败")
		showError(w.dlg, "测试失败", err)
		return
	}
	w.model.latency[i] = resp.LatencyMS
	w.model.PublishRowsReset()
	_ = w.status.SetText(fmt.Sprintf("节点可用，握手延迟 %d ms", resp.LatencyMS))
}

func (w *settingsWindow) changePassword() {
	oldPW, newPW, ok := askNewPassword(w.dlg, w.hasPassword)
	if !ok {
		return
	}
	if _, err := w.cli.call(ipc.Request{
		Op:          ipc.OpSetPassword,
		Password:    oldPW,
		NewPassword: newPW,
	}); err != nil {
		showError(w.dlg, "设置密码失败", err)
		return
	}
	w.hasPassword = true
	showInfo(w.dlg, "完成", "管理员密码已设置。")
}

func (w *settingsWindow) save() {
	if !w.hasPassword {
		showWarn(w.dlg, "请先设置管理员密码", "保存配置前必须先设置管理员密码。")
		w.changePassword()
		if !w.hasPassword {
			return
		}
	}

	newCfg := *w.cfg
	newCfg.Nodes = append([]config.Node(nil), w.model.nodes...)
	newCfg.Active = w.model.active
	newCfg.AllowLAN = w.allow.Checked()
	newCfg.BlockQUIC = w.quic.Checked()
	newCfg.AutoConnect = w.auto.Checked()
	newCfg.DNSServers = splitList(w.dns.Text())

	if err := newCfg.Validate(); err != nil {
		showWarn(w.dlg, "配置有误", err.Error())
		return
	}
	if len(newCfg.Nodes) == 0 {
		if !confirm(w.dlg, "没有任何节点",
			"节点列表为空，保存后整机将一直处于断网状态。确定保存吗？") {
			return
		}
	}

	pw, ok := askPassword(w.dlg, "确认保存", "请输入管理员密码以保存配置：")
	if !ok {
		return
	}

	if _, err := w.cli.callWithTimeout(ipc.Request{
		Op:       ipc.OpSaveConfig,
		Password: pw,
		Config:   &newCfg,
	}, 60*time.Second); err != nil {
		showError(w.dlg, "保存失败", err)
		return
	}
	showInfo(w.dlg, "已保存", "配置已保存并生效。")
	w.dlg.Accept()
}
