# 一键出单文件发行包：组装运行时 → 编译 → 追加 trailer
#
#   pwsh -File scripts/build-singlefile.ps1
#   pwsh -File scripts/build-singlefile.ps1 -SkipRuntime      # 复用已有 msfrt\runtime.zip
#
# 产物：artex-full.exe（含 portable Ruby + Metasploit，首次运行自解压到
# %LOCALAPPDATA%\ARTEX\runtime\<hash>\ 并自动拉起 msfrpcd）
param(
  [string]$Version = "v0.3.29",
  [switch]$SkipRuntime,
  [switch]$NoFrontend
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

if (-not (Test-Path "msfrt\runtime.zip") -and $SkipRuntime) {
  Fail "msfrt\runtime.zip 不存在，去掉 -SkipRuntime 先生成"
}

if (-not $SkipRuntime) {
  Info "1/3 组装便携运行时"
  & pwsh -NoProfile -File scripts\build-runtime.ps1
  if ($LASTEXITCODE -ne 0) { Fail "build-runtime.ps1 失败" }
} else {
  Info "1/3 复用 msfrt\runtime.zip"
}

Info "2/3 编译 artex.exe（$Version）"
$env:CGO_ENABLED = "0"
$tags = "embedui"
& go build -tags $tags -trimpath -ldflags "-s -w -buildid= -X main.version=$Version" -o artex.exe .\cmd\artex
if ($LASTEXITCODE -ne 0) { Fail "go build 失败" }

Info "3/3 追加运行时 trailer"
& pwsh -NoProfile -File scripts\append-payload.ps1 -Exe artex.exe -Payload msfrt\runtime.zip -Output artex-full.exe
if ($LASTEXITCODE -ne 0) { Fail "append-payload.ps1 失败" }

$full = (Get-Item artex-full.exe).Length
Write-Host ("[+] 单文件发行包：artex-full.exe（{0:N0} MB）" -f ($full / 1MB)) -ForegroundColor Green
