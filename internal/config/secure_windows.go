package config

import "golang.org/x/sys/windows"

// 目录与配置文件采用两套不同的权限，兼顾“配置保密”与“日志可取”：
//
//   - dirSDDL：SYSTEM 与 Administrators 完全控制，普通用户只读。
//     只读是为了让员工能自己打开日志目录、把日志发给 IT。
//     （OICI 使该 ACE 向目录内新建的文件继承，日志文件因此可读。）
//   - fileSDDL：只有 SYSTEM 与 Administrators 能读写，且断开继承。
//     config.json 里有 SOCKS5 的明文密码，绝不能让登录用户读到 ——
//     否则托盘用户可以绕过本程序直接拿账号用。
const (
	dirSDDL  = "O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;BU)"
	fileSDDL = "O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	group, _, err := sd.Group()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, group, dacl, nil,
	)
}

func secureDir(path string) error  { return applySDDL(path, dirSDDL) }
func secureFile(path string) error { return applySDDL(path, fileSDDL) }
