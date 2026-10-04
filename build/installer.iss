; CXProxy 安装脚本（Inno Setup 6.3+）
;
; 安装流程：
;   1. 把 cxproxy.exe 与 wintun.dll 放到 Program Files
;   2. 执行 cxproxy.exe install —— 注册开机自启服务、登记托盘自启动、
;      并立刻装上断网保护规则
;   3. 拉起托盘并打开设置窗口，引导管理员设置密码与粘贴代理
;
; 卸载流程先执行 cxproxy.exe uninstall：它会先拆除断网保护再删除服务，
; 确保卸载之后机器一定有网。

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#define MyAppName "CXProxy"
#define MyAppExe  "cxproxy.exe"

[Setup]
AppId={{B7F1D4C6-9B32-4DE1-A457-637870726F78}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppName}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=no
OutputDir=dist
OutputBaseFilename=CXProxy-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; 安装服务、写 HKLM、装 WFP 规则都需要管理员权限。
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=none
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
Uninstallable=yes
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExe}
SetupIconFile=icon.ico

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\cxproxy.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\wintun.dll";  DestDir: "{app}"; Flags: ignoreversion
Source: "dist\README.txt";  DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#MyAppName} 设置"; Filename: "{app}\{#MyAppExe}"; Parameters: "--tray --settings"
Name: "{group}\卸载 {#MyAppName}";  Filename: "{uninstallexe}"

[Run]
; 注册服务并立即启用断网保护（--no-tray：托盘由下一条以普通用户身份拉起）。
Filename: "{app}\{#MyAppExe}"; Parameters: "install --no-tray"; \
    StatusMsg: "正在注册服务并启用断网保护…"; \
    Flags: runhidden waituntilterminated

; 以当前登录用户（而非管理员）身份启动托盘，否则托盘会带着管理员令牌运行。
Filename: "{app}\{#MyAppExe}"; Parameters: "--tray --settings"; \
    Description: "立即启动 CXProxy 并打开设置"; \
    Flags: postinstall nowait runasoriginaluser skipifsilent

[UninstallRun]
; 先拆断网保护再删服务；这一步失败会让机器留在无网状态，因此必须等它跑完。
Filename: "{app}\{#MyAppExe}"; Parameters: "uninstall"; \
    RunOnceId: "CXProxyUninstall"; \
    Flags: runhidden waituntilterminated

[Messages]
chinesesimplified.WelcomeLabel2=即将在此计算机上安装 {#MyAppName}。%n%n安装完成后，本机全部网络流量将经由公司指定的 SOCKS5 代理出网；代理未连接时本机将无法联网，这是预期行为。%n%n请先继续安装，随后在设置窗口中设置管理员密码并填入代理。

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    Log('CXProxy 服务安装完成');
  end;
end;
