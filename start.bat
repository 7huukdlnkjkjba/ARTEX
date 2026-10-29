@echo off
rem ARTEX one-click start (Windows): PostgreSQL first, then the ARTEX backend.
rem Usage: double-click this file, or run  start.bat  in a terminal.
rem Equivalent to: pwsh -File .\pentest-ai\scripts\start.ps1
chcp 65001 >nul 2>&1
setlocal
cd /d "%~dp0"

set "PA=%~dp0pentest-ai"
set "PGBIN=%PA%\runtime\pgsql\bin"
set "PGDATA=%PA%\runtime\pgdata"
set "LOGS=%PA%\runtime\logs"
set "STARTPS1=%PA%\scripts\start.ps1"

if not exist "%STARTPS1%" (
  echo [错误] 找不到启动脚本: %STARTPS1%
  goto :fail
)
if not exist "%PGBIN%\pg_ctl.exe" (
  echo [错误] 找不到 PostgreSQL: %PGBIN%\pg_ctl.exe
  goto :fail
)
if not exist "%PGDATA%\PG_VERSION" (
  echo [错误] 数据库尚未初始化: %PGDATA%
  echo        请先运行 pentest-ai\scripts\init.ps1
  goto :fail
)
if not exist "%LOGS%" mkdir "%LOGS%" >nul 2>&1

rem ---------- 1. PostgreSQL (127.0.0.1:5433) ----------
rem 输出必须重定向到 nul/文件，不能接管道: postgres 会继承管道句柄，导致等待不返回。
rem 用 pg_isready 判断"是否可连"：数据库以 Windows 服务(ARTEX-PG)运行时，
rem pg_ctl status 拿不到 SYSTEM 进程信息，会误报 "no server running" 并触发重复启动。
"%PGBIN%\pg_isready.exe" -h 127.0.0.1 -p 5433 >nul 2>&1
if errorlevel 1 (
  echo [pg] 正在启动 ...
  "%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -l "%LOGS%\pg.log" -w -t 60 start >nul 2>&1
  if errorlevel 1 (
    echo [错误] PostgreSQL 启动失败, 详见 "%LOGS%\pg.log"
    echo        若已注册服务，请用管理员执行: sc start ARTEX-PG
    goto :fail
  )
  echo [pg] 已启动 127.0.0.1:5433
) else (
  echo [pg] 已在运行 127.0.0.1:5433
)

rem ---------- 2. ARTEX backend (127.0.0.1:8787 / proxy 8788) ----------
where pwsh >nul 2>&1
if errorlevel 1 (
  echo [错误] 找不到 pwsh 7, 无法启动 ARTEX
  goto :fail
)
pwsh -NoProfile -ExecutionPolicy Bypass -File "%STARTPS1%"
if errorlevel 1 (
  echo [错误] ARTEX 启动失败, 详见 "%LOGS%\artex.err.log"
  goto :fail
)

rem ---------- 3. 打开控制台（仅 Firefox，后端就绪后再开，避免首个请求打空） ----------
start "" firefox.exe "http://127.0.0.1:8787/login"

echo.
echo   控制台 : http://127.0.0.1:8787   (用户名 ARTEX)
echo   录制代理: 127.0.0.1:8788
echo   停止    : pwsh -File .\pentest-ai\scripts\stop.ps1
echo   驾驶舱  : pwsh -File .\pentest-ai\scripts\status.ps1
echo   日志    : %LOGS%\artex.err.log
exit /b 0

:fail
echo.
echo 启动未完成。
pause
exit /b 1
