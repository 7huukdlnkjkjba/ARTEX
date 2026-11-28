# 把 runtime.zip 作为 trailer 追加到 artex.exe 尾部，产出单文件发行包。
#
#   pwsh -File scripts/append-payload.ps1
#   pwsh -File scripts/append-payload.ps1 -Exe dist\artex.exe -Payload msfrt\runtime.zip -Output dist\artex-full.exe
#
# 尾部格式：[zip 字节][uint64 小端 长度][8 字节 magic "ARTEXRT1"]
# 运行期由 msfrt.Open() 读自身尾段定位 payload，不占编译期内存、不需要 go:embed。
param(
  [string]$Exe = "artex.exe",
  [string]$Payload = "msfrt\runtime.zip",
  [string]$Output = "artex-full.exe"
)

$ErrorActionPreference = "Stop"

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $Exe)) { Fail "找不到 $Exe（先 go build ./cmd/artex）" }
if (-not (Test-Path $Payload)) { Fail "找不到 $Payload（先 pwsh -File scripts/build-runtime.ps1）" }

$exeAbs = (Resolve-Path $Exe).Path
$payAbs = (Resolve-Path $Payload).Path

# 防止重复追加：已带 trailer 的 exe 不能再当基座
$tail = New-Object byte[] 8
$fsIn = [System.IO.File]::OpenRead($exeAbs)
try {
  if ($fsIn.Length -ge 16) {
    [void]$fsIn.Seek(-8, [System.IO.SeekOrigin]::End)
    [void]$fsIn.Read($tail, 0, 8)
  }
} finally { $fsIn.Close() }
if ([System.Text.Encoding]::ASCII.GetString($tail) -eq "ARTEXRT1") {
  Fail "$Exe 已经内含 trailer，请用干净的 artex.exe 作基座"
}

$exeLen = (Get-Item $exeAbs).Length
$payLen = (Get-Item $payAbs).Length
Info ("基座 {0:N0} MB + 运行时 {1:N0} MB → {2}" -f ($exeLen / 1MB), ($payLen / 1MB), $Output)

$outAbs = Join-Path (Get-Location) $Output
$out = [System.IO.File]::Create($outAbs)
try {
  $in = [System.IO.File]::OpenRead($exeAbs)
  try { $in.CopyTo($out) } finally { $in.Close() }
  $in = [System.IO.File]::OpenRead($payAbs)
  try { $in.CopyTo($out) } finally { $in.Close() }
  $lenBytes = [BitConverter]::GetBytes([int64]$payLen)
  $magic = [System.Text.Encoding]::ASCII.GetBytes("ARTEXRT1")
  $out.Write($lenBytes, 0, 8)
  $out.Write($magic, 0, 8)
} finally { $out.Close() }

$final = (Get-Item $outAbs).Length
$expect = $exeLen + $payLen + 16
if ($final -ne $expect) { Fail "大小不符：$final != $expect" }
Info ("完成：{0}（{1:N0} MB）" -f $Output, ($final / 1MB))
Info "验证：`$env:ARTEX_MSF_BACKEND='embedded'; .\$Output autopwn -targets 127.0.0.1 -ports 2121 -dry-run"
