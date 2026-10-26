# 一键准备 Metasploit MCP 闭环（Windows PowerShell）
#
#   pwsh -File scripts/setup-msf-mcp.ps1 -RpcPassword 'yourpass'
#
# 做三件事：确认 msfrpcd 可达、安装/升级 mcp-pymetasploit3、打印 ARTEX 侧配置步骤。
# 不修改 ARTEX 数据库（MCP 开关与工具可见性在 UI 里点）。

param(
  [string]$RpcPassword = $env:ARTEX_MSF_RPC_PASSWORD,
  [string]$RpcHost = "127.0.0.1",
  [int]$RpcPort = 55553,
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

Write-Host "== 1/3 检查 Metasploit RPC ==" -ForegroundColor Cyan
$tcp = Test-NetConnection -ComputerName $RpcHost -Port $RpcPort -WarningAction SilentlyContinue
if (-not $tcp.TcpTestSucceeded) {
  Write-Warning "无法连接 ${RpcHost}:${RpcPort}。请先启动：msfrpcd -P <pass> -p $RpcPort -n"
} else {
  Write-Host "RPC 端口可达：${RpcHost}:${RpcPort}"
}

Write-Host "== 2/3 安装 mcp-pymetasploit3 ==" -ForegroundColor Cyan
if ($SkipInstall) {
  Write-Host "跳过安装（-SkipInstall）"
} else {
  python -m pip install --upgrade mcp-pymetasploit3
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "pip 安装失败；可改用：uv tool install mcp-pymetasploit3"
  }
}

Write-Host "== 3/3 ARTEX 侧配置 ==" -ForegroundColor Cyan
@"
1) 启动 ARTEX，进入「系统 → MCP」。
2) 找到内置的 metasploit（默认停用），启用并点「发现工具」。
   - 若启动失败，把 command 改成 python、args 改成 ["-m","mcp_pymetasploit3"]，
     或填 venv 里的绝对路径。
3) 在「工具可见性」里把 mcp-pymetasploit3 的工具授权给 worker。
4) 配置 RPC 密码（任选其一）：
   - 环境变量 ARTEX_MSF_RPC_PASSWORD=$RpcPassword
   - 设置项：INSERT INTO settings(key,value) VALUES('msf_rpc_password','$RpcPassword')
             ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;
5) 回到任务，worker 依次调用：msf_plan → msf_execute（拿到会话自动取证并写回 fact）。
"@ | Write-Host

if (-not $RpcPassword) {
  Write-Warning "未提供 -RpcPassword：msf_execute 调用时必须传 rpc_password，或设置 ARTEX_MSF_RPC_PASSWORD。"
}
