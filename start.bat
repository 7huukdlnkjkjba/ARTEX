@echo off
rem ARTEX one-click start (Windows): PostgreSQL first, then the ARTEX backend.
rem Usage: double-click this file, or run  start.bat  in a terminal.
rem First run initializes this machine's database and secrets through install.bat.
chcp 65001 >nul 2>&1
setlocal
cd /d "%~dp0"

set "PA=%~dp0pentest-ai"
set "PGBIN=%PA%\runtime\pgsql\bin"
set "PGDATA=%PA%\runtime\pgdata"
set "LOGS=%PA%\runtime\logs"
set "STARTPS1=%PA%\scripts\start.ps1"
set "PORTSELECTOR=%PA%\scripts\resolve-pg-port.ps1"
set "INSTALLBAT=%~dp0install.bat"

if not exist "%STARTPS1%" goto :missing_start_script
if not exist "%INSTALLBAT%" goto :missing_install_script
where pwsh >nul 2>&1
if errorlevel 1 goto :missing_pwsh
if not exist "%PORTSELECTOR%" goto :missing_port_selector
set "PORTFILE=%TEMP%\artex-pgport-%RANDOM%%RANDOM%.txt"
pwsh -NoProfile -File "%PORTSELECTOR%" -DataDirectory "%PGDATA%" >"%PORTFILE%"
set "PORTSELECT_RC=%ERRORLEVEL%"
if exist "%PORTFILE%" set /p PGPORT=<"%PORTFILE%"
if exist "%PORTFILE%" del "%PORTFILE%" >nul 2>&1
if not "%PORTSELECT_RC%"=="0" goto :port_selection_failed
if not defined PGPORT goto :port_selection_failed
echo [pg] 使用端口 %PGPORT%
if not exist "%PGBIN%\pg_ctl.exe" goto :first_run
if not exist "%PGBIN%\initdb.exe" goto :first_run
if not exist "%PGDATA%\PG_VERSION" goto :first_run
if not exist "%LOGS%" mkdir "%LOGS%" >nul 2>&1

rem ---------- 1. PostgreSQL (127.0.0.1:%PGPORT%) ----------
rem 输出必须重定向到 nul/文件，不能接管道: postgres 会继承管道句柄，导致等待不返回。
rem Use pg_isready to detect readiness; pg_ctl status cannot see a Windows service process.
rem This avoids incorrectly starting a second PostgreSQL instance.
"%PGBIN%\pg_isready.exe" -h 127.0.0.1 -p %PGPORT% >nul 2>&1
if errorlevel 1 goto :start_postgres
echo [pg] 已在运行 127.0.0.1:%PGPORT%
goto :postgres_ready

:start_postgres
echo [pg] 正在启动 ...
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -l "%LOGS%\pg.log" -w -t 60 start >nul 2>&1
if errorlevel 1 goto :postgres_failed
echo [pg] 已启动 127.0.0.1:%PGPORT%
goto :postgres_ready

:postgres_failed
echo [错误] PostgreSQL 启动失败, 详见 "%LOGS%\pg.log"
echo        若已注册服务，请用管理员执行: sc start ARTEX-PG
goto :fail

:postgres_ready
rem ---------- 2. ARTEX backend (127.0.0.1:8787 / proxy 8788) ----------
pwsh -NoProfile -ExecutionPolicy Bypass -File "%STARTPS1%"
if errorlevel 1 goto :backend_failed

rem ---------- 3. 自动登录并打开控制台 ----------
:open_ui
pwsh -NoProfile -ExecutionPolicy Bypass -File "%PA%\scripts\open-ui.ps1"
if errorlevel 1 goto :ui_failed
goto :complete

:first_run
echo [init] 首次启动：初始化本机数据库与密钥 ...
call "%INSTALLBAT%" -nobrowser -nopause
if errorlevel 1 goto :install_failed
goto :open_ui

:missing_start_script
echo [错误] 找不到启动脚本: %STARTPS1%
goto :fail

:missing_install_script
echo [错误] 找不到安装脚本: %INSTALLBAT%
goto :fail

:missing_port_selector
echo [错误] 找不到 PostgreSQL 端口选择脚本: %PORTSELECTOR%
goto :fail

:port_selection_failed
echo [错误] 无法选择可用的 PostgreSQL 端口（5544-5999）
goto :fail

:install_failed
echo [错误] 本机初始化失败，请检查 install.bat 输出和运行日志
goto :fail

:missing_pwsh
echo [错误] 找不到 pwsh 7, 无法启动 ARTEX
goto :fail

:backend_failed
echo [错误] ARTEX 启动失败, 详见 "%LOGS%\artex.err.log"
goto :fail

:ui_failed
echo [警告] 自动登录失败，打开手动登录页
start "" firefox.exe "http://127.0.0.1:8787/login"

:complete
echo.
echo   控制台 : http://127.0.0.1:8787   (用户名 ARTEX)
echo   数据库端口: %PGPORT%
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

