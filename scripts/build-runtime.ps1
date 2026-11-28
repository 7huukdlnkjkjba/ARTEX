# 组装便携 Metasploit 运行时（portable Ruby + framework + 预装 gems）
#
#   pwsh -File scripts/build-runtime.ps1
#   pwsh -File scripts/build-runtime.ps1 -MetasploitRoot D:\msf -Output msfrt\runtime.zip
#
# 产物是 msfrt\runtime.zip：解压后为 embedded\(ruby+framework+gems) + LICENSES\。
# append-payload.ps1 会把它作为 trailer 追加到 artex.exe 尾部，形成单文件发行包。
param(
  [string]$MetasploitRoot = $(if ($env:METASPLOIT_ROOT) { $env:METASPLOIT_ROOT } else { "C:\metasploit-framework" }),
  [string]$Output = "msfrt\runtime.zip",
  [string]$Stage = "build\runtime",
  [switch]$KeepStage
)

$ErrorActionPreference = "Stop"

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

$root = (Resolve-Path $MetasploitRoot).Path
$embedded = Join-Path $root "embedded"
$framework = Join-Path $embedded "framework"
foreach ($p in @(
    (Join-Path $embedded "bin\ruby.exe"),
    (Join-Path $framework "msfrpcd"),
    (Join-Path $framework "Gemfile")
  )) {
  if (-not (Test-Path $p)) { Fail "Metasploit 安装不完整，缺少 $p（用 -MetasploitRoot 指定正确目录）" }
}

$stageAbs = Join-Path (Get-Location) $Stage
Info "清理暂存目录 $stageAbs"
Remove-Item $stageAbs -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stageAbs | Out-Null

# 1) embedded（ruby + gems + framework）整树复制；只剔除体积大且运行期用不到的文档/头文件
$excludeDirs = @(
  "documentation", "spec", "docs", "test", ".github", "docker", "kubernetes",
  "include", "packages", "ridk_use"
)
Info "复制 embedded（约 700 MB，首次较慢）"
$rcArgs = @(
  $embedded, (Join-Path $stageAbs "embedded"), "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/XF", "*.pdb", "/XD"
)
foreach ($d in $excludeDirs) { $rcArgs += (Join-Path $embedded $d) }
foreach ($d in $excludeDirs) { $rcArgs += (Join-Path $embedded "framework\$d") }
& robocopy @rcArgs | Out-Null
if ($LASTEXITCODE -ge 8) { Fail "robocopy 失败（exit=$LASTEXITCODE）" }

# 2) share\doc、share\ri 是 Ruby/Gem 文档，几百 MB 里能省 50+ MB
foreach ($rel in @("embedded\share\doc", "embedded\share\ri")) {
  $p = Join-Path $stageAbs $rel
  if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
}

# 3) 许可证随包分发
foreach ($rel in @("LICENSES", "LICENSE.txt")) {
  $src = Join-Path $root $rel
  if (Test-Path $src) { Copy-Item $src (Join-Path $stageAbs $rel) -Recurse -Force }
}
$fwLicense = Join-Path $framework "LICENSE"
if (Test-Path $fwLicense) {
  Copy-Item $fwLicense (Join-Path $stageAbs "embedded\framework\LICENSE") -Force
}

$stageSize = (Get-ChildItem $stageAbs -Recurse -File | Measure-Object Length -Sum).Sum
Info ("暂存体积：{0:N0} MB" -f ($stageSize / 1MB))

# 4) 压缩（.NET 实现比 Compress-Archive 快得多）
$outAbs = Join-Path (Get-Location) $Output
New-Item -ItemType Directory -Force -Path (Split-Path $outAbs) | Out-Null
Remove-Item $outAbs -Force -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
Info "压缩到 $outAbs（Optimal，几分钟）"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
[System.IO.Compression.ZipFile]::CreateFromDirectory(
  $stageAbs, $outAbs,
  [System.IO.Compression.CompressionLevel]::Optimal,
  $false)
$sw.Stop()

$zipSize = (Get-Item $outAbs).Length
Info ("完成：{0}（{1:N0} MB，{2:N0}s，压缩率 {3:P0}）" -f $Output, ($zipSize / 1MB), $sw.Elapsed.TotalSeconds, ($zipSize / $stageSize))

if (-not $KeepStage) {
  Info "删除暂存目录（-KeepStage 可保留）"
  Remove-Item $stageAbs -Recurse -Force -ErrorAction SilentlyContinue
}
