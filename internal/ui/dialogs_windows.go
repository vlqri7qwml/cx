package ui

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"

	"github.com/vlqri7qwml/cx/internal/config"
)

func showInfo(owner walk.Form, title, msg string) {
	walk.MsgBox(owner, title, msg, walk.MsgBoxIconInformation)
}

func showWarn(owner walk.Form, title, msg string) {
	walk.MsgBox(owner, title, msg, walk.MsgBoxIconWarning)
}

func showError(owner walk.Form, title string, err error) {
	walk.MsgBox(owner, title, err.Error(), walk.MsgBoxIconError)
}

func confirm(owner walk.Form, title, msg string) bool {
	return walk.MsgBox(owner, title, msg,
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion|walk.MsgBoxDefButton2) == walk.DlgCmdYes
}

// askPassword 弹出管理员密码输入框。
func askPassword(owner walk.Form, title, prompt string) (string, bool) {
	dlg, err := walk.NewDialogWithFixedSize(owner)
	if err != nil {
		return "", false
	}
	defer dlg.Dispose()

	dlg.SetTitle(title)
	dlg.SetLayout(walk.NewVBoxLayout())
	_ = dlg.SetSize(walk.Size{Width: 400, Height: 170})

	label, _ := walk.NewLabel(dlg)
	_ = label.SetText(prompt)

	edit, _ := walk.NewLineEdit(dlg)
	edit.SetPasswordMode(true)

	row, _ := walk.NewComposite(dlg)
	row.SetLayout(walk.NewHBoxLayout())
	spacer, _ := walk.NewLabel(row)
	_ = spacer.SetText("")

	ok, _ := walk.NewPushButton(row)
	_ = ok.SetText("确定")
	cancel, _ := walk.NewPushButton(row)
	_ = cancel.SetText("取消")

	ok.Clicked().Attach(func() {
		if strings.TrimSpace(edit.Text()) == "" {
			showWarn(dlg, "提示", "请输入管理员密码")
			return
		}
		dlg.Accept()
	})
	cancel.Clicked().Attach(dlg.Cancel)
	_ = dlg.SetDefaultButton(ok)
	_ = dlg.SetCancelButton(cancel)

	if dlg.Run() != walk.DlgCmdOK {
		return "", false
	}
	return edit.Text(), true
}

// askNewPassword 设置或修改管理员密码。requireOld 为 true 时还需输入当前密码。
func askNewPassword(owner walk.Form, requireOld bool) (oldPW, newPW string, ok bool) {
	dlg, err := walk.NewDialogWithFixedSize(owner)
	if err != nil {
		return "", "", false
	}
	defer dlg.Dispose()

	title := "设置管理员密码"
	if requireOld {
		title = "修改管理员密码"
	}
	dlg.SetTitle(title)
	dlg.SetLayout(walk.NewVBoxLayout())
	_ = dlg.SetSize(walk.Size{Width: 430, Height: 280})

	hint, _ := walk.NewLabel(dlg)
	_ = hint.SetText("管理员密码用于保存配置与退出断网保护。\n" +
		"至少 8 位，且需同时包含字母与数字（或符号）。")

	var oldEdit *walk.LineEdit
	if requireOld {
		l, _ := walk.NewLabel(dlg)
		_ = l.SetText("当前密码：")
		oldEdit, _ = walk.NewLineEdit(dlg)
		oldEdit.SetPasswordMode(true)
	}

	l1, _ := walk.NewLabel(dlg)
	_ = l1.SetText("新密码：")
	e1, _ := walk.NewLineEdit(dlg)
	e1.SetPasswordMode(true)

	l2, _ := walk.NewLabel(dlg)
	_ = l2.SetText("确认新密码：")
	e2, _ := walk.NewLineEdit(dlg)
	e2.SetPasswordMode(true)

	row, _ := walk.NewComposite(dlg)
	row.SetLayout(walk.NewHBoxLayout())
	sp, _ := walk.NewLabel(row)
	_ = sp.SetText("")
	okBtn, _ := walk.NewPushButton(row)
	_ = okBtn.SetText("确定")
	cancelBtn, _ := walk.NewPushButton(row)
	_ = cancelBtn.SetText("取消")

	okBtn.Clicked().Attach(func() {
		if e1.Text() != e2.Text() {
			showWarn(dlg, "提示", "两次输入的新密码不一致")
			return
		}
		if err := config.CheckPasswordStrength(e1.Text()); err != nil {
			showWarn(dlg, "密码不符合要求", err.Error())
			return
		}
		if requireOld && strings.TrimSpace(oldEdit.Text()) == "" {
			showWarn(dlg, "提示", "请输入当前密码")
			return
		}
		dlg.Accept()
	})
	cancelBtn.Clicked().Attach(dlg.Cancel)
	_ = dlg.SetDefaultButton(okBtn)
	_ = dlg.SetCancelButton(cancelBtn)

	if dlg.Run() != walk.DlgCmdOK {
		return "", "", false
	}
	if requireOld {
		oldPW = oldEdit.Text()
	}
	return oldPW, e1.Text(), true
}

// askNodeLines 弹出多行输入框，用于批量粘贴代理。
func askNodeLines(owner walk.Form) ([]config.Node, bool) {
	dlg, err := walk.NewDialog(owner)
	if err != nil {
		return nil, false
	}
	defer dlg.Dispose()

	dlg.SetTitle("批量导入代理（每行一条）")
	dlg.SetLayout(walk.NewVBoxLayout())
	_ = dlg.SetSize(walk.Size{Width: 620, Height: 430})

	hint, _ := walk.NewLabel(dlg)
	_ = hint.SetText("支持以下任一写法，可在行尾用 # 加备注：\n" +
		"    socks5://用户:密码@地址:端口\n" +
		"    地址:端口:用户:密码\n" +
		"    用户:密码@地址:端口\n" +
		"    地址:端口\n" +
		"以 // 或 ; 开头的行会被忽略。")

	edit, _ := walk.NewTextEdit(dlg)
	_ = edit.SetReadOnly(false)

	row, _ := walk.NewComposite(dlg)
	row.SetLayout(walk.NewHBoxLayout())
	sp, _ := walk.NewLabel(row)
	_ = sp.SetText("")
	okBtn, _ := walk.NewPushButton(row)
	_ = okBtn.SetText("导入")
	cancelBtn, _ := walk.NewPushButton(row)
	_ = cancelBtn.SetText("取消")

	var parsed []config.Node
	okBtn.Clicked().Attach(func() {
		nodes, errs := config.ParseNodes(edit.Text())
		if len(nodes) == 0 {
			msg := "没有解析出任何可用的代理。"
			if len(errs) > 0 {
				msg += "\n\n" + joinErrors(errs, 10)
			}
			showWarn(dlg, "导入失败", msg)
			return
		}
		if len(errs) > 0 {
			if !confirm(dlg, "部分行无法解析",
				fmt.Sprintf("成功解析 %d 条，以下行被跳过：\n\n%s\n\n仍要导入吗？",
					len(nodes), joinErrors(errs, 10))) {
				return
			}
		}
		parsed = nodes
		dlg.Accept()
	})
	cancelBtn.Clicked().Attach(dlg.Cancel)
	_ = dlg.SetDefaultButton(okBtn)
	_ = dlg.SetCancelButton(cancelBtn)

	if dlg.Run() != walk.DlgCmdOK {
		return nil, false
	}
	return parsed, true
}
