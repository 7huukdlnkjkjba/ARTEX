$ErrorActionPreference = 'Stop'
. "C:\Users\Administrator\Downloads\ARTEX-main\pentest-ai\scripts\lib.ps1"
"T0 {0}" -f (Get-Date -Format HH:mm:ss.fff)
$sw = [Diagnostics.Stopwatch]::StartNew()
$ok = Start-Pg
"Start-Pg -> {0} in {1}s" -f $ok, [math]::Round($sw.Elapsed.TotalSeconds,1)
$sw.Restart()
$ok2 = Start-Artex
"Start-Artex -> {0} in {1}s" -f $ok2, [math]::Round($sw.Elapsed.TotalSeconds,1)