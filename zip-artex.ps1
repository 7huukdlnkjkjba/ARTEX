# zip-artex.ps1
# 用途：压缩 ARTEX-main 目录，能正常处理“被其它进程占用（错误 32）”的文件。
# 原理：Windows 自带的 tar.exe (bsdtar) 以 FILE_SHARE_READ|WRITE|DELETE 打开源文件，
#       因此后端仍在写入 runtime\logs\*.log 时也能读取并打包；
#       而资源管理器“压缩为 ZIP”、Compress-Archive、7-Zip 等以独占/仅共享读方式打开，会报
#       “另一个程序正在使用此文件，进程无法访问。(32)”。
#
# 示例：
#   powershell -ExecutionPolicy Bypass -File .\zip-artex.ps1
#   powershell -ExecutionPolicy Bypass -File .\zip-artex.ps1 -Destination D:\ARTEX-main.zip
#   powershell -ExecutionPolicy Bypass -File .\zip-artex.ps1 -ExcludeLogs   # 跳过 runtime\logs，更快更小

[CmdletBinding()]
param(
    [string]$Source = $PSScriptRoot,
    [string]$Destination,
    [switch]$ExcludeLogs
)

$ErrorActionPreference = 'Stop'
$Source = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\')
$rootName = Split-Path -Leaf $Source
if (-not $Destination) {
    $Destination = Join-Path (Split-Path -Parent $Source) ($rootName + '.zip')
}
$Destination = [System.IO.Path]::GetFullPath($Destination)

$srcParent = Split-Path -Parent $Source
$destDir   = Split-Path -Parent $Destination
if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }

$tar = Join-Path $env:SystemRoot 'system32\tar.exe'
if (-not (Test-Path -LiteralPath $tar)) { throw "找不到 $tar（需要 Windows 10 1803+ 自带的 bsdtar）" }

$excludes = @("--exclude=$rootName/_zip_build")
# 如果 zip 输出在源目录内部，必须排除它，否则会把正在写的包打进自己
if ($Destination.StartsWith($Source + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    $rel = $Destination.Substring($Source.Length + 1).Replace('\', '/')
    $excludes += "--exclude=$rootName/$rel"
}
if ($ExcludeLogs) { $excludes += "--exclude=$rootName/pentest-ai/runtime/logs" }

Write-Host "源目录 : $Source"
Write-Host "目标   : $Destination"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }

& $tar -a -c -f $Destination @excludes -C $srcParent $rootName
$code = $LASTEXITCODE
$sw.Stop()

if ($code -ne 0) { throw "打包失败，tar 退出码 $code" }
$sizeMB = [math]::Round((Get-Item -LiteralPath $Destination).Length / 1MB, 1)
$entries = (& $tar -tf $Destination | Measure-Object).Count
Write-Host ("完成：{0} 项，{1} MB，耗时 {2:N1} 秒" -f $entries, $sizeMB, $sw.Elapsed.TotalSeconds)
