<#
.SYNOPSIS
    构建 CXProxy：下载并校验 Wintun、生成图标与资源、编译 exe、（可选）打包安装程序。

.DESCRIPTION
    产物输出到 build\dist：
        cxproxy.exe   主程序（GUI 子系统，内含图标/版本信息/清单）
        wintun.dll    Wintun 驱动加载器（来自 wintun.net 官方发布包）
        CXProxy-Setup-<版本>.exe  安装程序（需要 Inno Setup 6.3+）

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build\build.ps1 -Version 1.0.0
#>
[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$WintunVersion = "0.14.1",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$BuildDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root     = Split-Path -Parent $BuildDir
$Dist     = Join-Path $BuildDir "dist"
$Work     = Join-Path $BuildDir "_work"

function Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

New-Item -ItemType Directory -Force -Path $Dist, $Work | Out-Null

# ---------------------------------------------------------------- Wintun
Step "获取 Wintun $WintunVersion"

$zipName = "wintun-$WintunVersion.zip"
$zipPath = Join-Path $Work $zipName

if (-not (Test-Path $zipPath)) {
    $url = "https://www.wintun.net/builds/$zipName"
    Write-Host "    下载 $url"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
}

$expected = $env:WINTUN_SHA256
if (-not $expected) {
    $expected = (Get-Content (Join-Path $BuildDir "wintun.sha256") |
                 Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' } |
                 Select-Object -First 1).Trim()
}
$actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()

if ($actual -ne $expected.ToLower()) {
    Write-Host ""
    Write-Host "Wintun 压缩包校验失败！" -ForegroundColor Red
    Write-Host "  期望: $expected"
    Write-Host "  实际: $actual"
    Write-Host ""
    Write-Host "请到 https://www.wintun.net 核对官方公布的 SHA256："
    Write-Host "  · 若官网值与「实际」一致，请更新 build\wintun.sha256 后重新构建；"
    Write-Host "  · 若都不一致，说明下载被篡改，绝不要继续构建。"
    Remove-Item $zipPath -Force
    throw "Wintun 校验失败"
}
Write-Host "    校验通过: $actual"

$extract = Join-Path $Work "wintun"
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extract -Force

$dll = Join-Path $extract "wintun\bin\amd64\wintun.dll"
if (-not (Test-Path $dll)) { throw "压缩包里找不到 wintun\bin\amd64\wintun.dll" }
Copy-Item $dll (Join-Path $Dist "wintun.dll") -Force

# ---------------------------------------------------------------- 图标与资源
Step "生成图标"
Push-Location $Root
try {
    foreach ($pair in @(@(256, "icon.png"), @(48, "icon48.png"), @(32, "icon32.png"), @(16, "icon16.png"))) {
        & go run ./build/mkicon -out ("build/" + $pair[1]) -size $pair[0]
        if ($LASTEXITCODE -ne 0) { throw "生成图标失败" }
    }
    # 安装程序与快捷方式要的是 .ico（多尺寸）。
    & go run ./build/mkicon -ico build/icon.ico
    if ($LASTEXITCODE -ne 0) { throw "生成 ICO 失败" }

    Step "生成 Windows 资源（图标 / 版本信息 / 清单）"
    $winres = Join-Path $env:GOPATH "bin\go-winres.exe"
    if (-not (Test-Path $winres)) {
        $winres = "go-winres"
        if (-not (Get-Command $winres -ErrorAction SilentlyContinue)) {
            Write-Host "    未找到 go-winres，正在安装…"
            & go install github.com/tc-hib/go-winres@latest
            if ($LASTEXITCODE -ne 0) { throw "安装 go-winres 失败" }
            $winres = Join-Path (& go env GOPATH) "bin\go-winres.exe"
        }
    }

    Push-Location $BuildDir
    try {
        & $winres make --in winres.json --out (Join-Path $Root "cmd\cxproxy\rsrc") --arch amd64
        if ($LASTEXITCODE -ne 0) { throw "go-winres 执行失败" }
    } finally { Pop-Location }

    # ------------------------------------------------------------ 编译
    Step "编译 cxproxy.exe ($Version)"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    $ldflags = "-H windowsgui -s -w -X github.com/vlqri7qwml/cx/internal/service.Version=$Version"
    & go build -trimpath -ldflags $ldflags -o (Join-Path $Dist "cxproxy.exe") ./cmd/cxproxy
    if ($LASTEXITCODE -ne 0) { throw "编译失败" }
} finally {
    # .syso 只是构建中间产物，留着会影响后续的 go test / go vet。
    Remove-Item (Join-Path $Root "cmd\cxproxy\rsrc_windows_amd64.syso") -Force -ErrorAction SilentlyContinue
    Pop-Location
}

Copy-Item (Join-Path $Root "README.md") (Join-Path $Dist "README.txt") -Force

# ---------------------------------------------------------------- 安装包
if (-not $SkipInstaller) {
    Step "打包安装程序"
    $iscc = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if (-not $iscc) {
        foreach ($p in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
            if (Test-Path $p) { $iscc = $p; break }
        }
    } else { $iscc = $iscc.Source }

    if (-not $iscc) {
        Write-Warning "未找到 Inno Setup（ISCC.exe），跳过安装包打包。"
        Write-Warning "可执行：choco install innosetup -y"
    } else {
        & $iscc "/DMyAppVersion=$Version" (Join-Path $BuildDir "installer.iss")
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup 打包失败" }
    }
}

Step "完成，产物在 $Dist"
Get-ChildItem $Dist | Format-Table Name, Length, LastWriteTime
