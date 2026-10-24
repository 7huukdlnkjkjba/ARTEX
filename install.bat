@echo off
for /f "tokens=2 delims=:" %%c in ('chcp') do set "OLDCP=%%c"
set "OLDCP=%OLDCP: =%"
chcp 65001 >nul
setlocal EnableExtensions
rem ============================================================================
rem  ARTEX / pentest-ai  Windows 免安装运行环境 —— 一键安装 + 启动
rem
rem  不装 Docker、不装 Go/Node、不装 PostgreSQL：直接用仓库里附带的便携环境
rem  （pentest-ai\runtime\pgsql + artex.exe）把系统跑起来。
rem
rem  首次运行：初始化数据库集群 → 创建角色/库 → 生成 config.json →
rem            初始化管理员密码
rem  之后运行：检查 + 启动（幂等，可反复执行）
rem
rem  用法：
rem    install.bat                       安装/启动，结束后打开浏览器
rem    install.bat -nobrowser            同上，但不打开浏览器
rem    install.bat -nobrowser -nopause   全自动（脚本/任务计划里用，不暂停）
rem    set PGPORT=5544 && install.bat    换端口（PGPORT / HTTPPORT / PROXYPORT）
rem
rem  停止：本脚本不常驻。停止用 pentest-ai\scripts\stop.ps1，
rem        或直接关掉那个最小化的「ARTEX 后端」窗口。
rem
rem  注：日常启停也可以继续用 pentest-ai\scripts\start.ps1 / stop.ps1 / status.ps1；
rem      本脚本多做的是「首次初始化」（initdb + 建角色/库 + 生成配置）。
rem ============================================================================

cd /d "%~dp0"

rem ---------- 可覆盖参数 ----------
if not defined PGHOST    set "PGHOST=127.0.0.1"
if not defined PGPORT    set "PGPORT=5433"
if not defined HTTPPORT  set "HTTPPORT=8787"
if not defined PROXYPORT set "PROXYPORT=8788"
if not defined PGSUPER   set "PGSUPER=postgres"
if not defined PGAPP     set "PGAPP=artex"
if not defined PGDB      set "PGDB=artex"
set "OPENBROWSER=1"

rem ---------- 命令行开关 ----------
set "PAUSE_ON_EXIT="
echo %CMDCMDLINE% | findstr /i /c:"/c" >nul
if not errorlevel 1 set "PAUSE_ON_EXIT=1"
:parseargs
if "%~1"=="" goto :afterparse
if /i "%~1"=="-nobrowser"   set "OPENBROWSER="
if /i "%~1"=="--no-browser" set "OPENBROWSER="
if /i "%~1"=="-nopause"     set "PAUSE_ON_EXIT="
if /i "%~1"=="--no-pause"   set "PAUSE_ON_EXIT="
shift
goto :parseargs
:afterparse

rem ---------- 路径（相对本文件所在目录） ----------
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PA=%ROOT%\pentest-ai"
set "RT=%PA%\runtime"
set "PGBIN=%RT%\pgsql\bin"
set "PGDATA=%RT%\pgdata"
set "SECRETS=%RT%\secrets"
set "LOGS=%RT%\logs"
set "STATE=%PA%\state"
set "CONFIG=%PA%\config\config.json"
set "ARTEXEXE=%RT%\artex.exe"
set "SKILLS=%ROOT%\skills"
set "BASEURL=http://%PGHOST%:%HTTPPORT%"
set "TMPDIR=%TEMP%\artex-install-%RANDOM%%RANDOM%"
set "TAILN=20"

echo.
echo ============================================================
echo   ARTEX 免安装运行环境  （安装 + 启动）
echo ============================================================
echo   仓库根目录 : %ROOT%
echo   运行环境   : %RT%
echo   控制台     : %BASEURL%
echo   数据库     : %PGHOST%:%PGPORT%/%PGDB%
echo ============================================================
echo.

if not exist "%PA%\" goto :err_nopa
mkdir "%TMPDIR%" 2>nul
mkdir "%SECRETS%" 2>nul
mkdir "%LOGS%" 2>nul
mkdir "%STATE%\data" 2>nul

rem ==========================================================================
rem [1/8] 便携 PostgreSQL
rem ==========================================================================
echo [1/8] 检查便携 PostgreSQL ...
if exist "%PGBIN%\pg_ctl.exe" goto :step1_ok
if exist "%RT%\pgsql" goto :err_pgsql_broken
set "PGZIP="
for %%z in ("%RT%\downloads\pgsql-*.zip") do set "PGZIP=%%~fz"
if not defined PGZIP goto :err_nopgsql
echo         未发现 runtime\pgsql，正在从压缩包展开（约 380 MB，需要几分钟）...
echo         来源: %PGZIP%
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory($env:PGZIP, $env:RT)"
if not exist "%PGBIN%\pg_ctl.exe" goto :err_nopgsql
:step1_ok
for /f "delims=" %%v in ('"%PGBIN%\pg_ctl.exe" --version 2^>nul') do echo          %%v

rem ==========================================================================
rem [2/8] ARTEX 单二进制
rem ==========================================================================
echo [2/8] 检查 artex.exe ...
if not exist "%ARTEXEXE%" goto :err_noartex
for %%f in ("%ARTEXEXE%") do echo          %%~nxf  %%~zf 字节

rem ==========================================================================
rem [3/8] 口令（幂等：已存在则复用）
rem ==========================================================================
echo [3/8] 准备口令文件 ...
rem 先用 HAVE_* 记录"文件里确实读到了口令"，再决定要不要落盘：
rem 不能用 if not defined PGPW 当写盘条件 —— 那时 PGPW 已被上一行赋值，条件恒假，文件永远写不出来。
set "PGPW="
set "HAVE_PGPW="
if exist "%SECRETS%\pg_super.txt" set /p PGPW=<"%SECRETS%\pg_super.txt"
if defined PGPW set "HAVE_PGPW=1"
if not defined PGPW call :genpass
if not defined PGPW set "PGPW=%GENPASS%"
if not defined HAVE_PGPW >"%SECRETS%\pg_super.txt" echo %PGPW%
echo         超级用户口令 : secrets\pg_super.txt
set "APPPW="
set "HAVE_APPPW="
if exist "%SECRETS%\artex_pg.txt" set /p APPPW=<"%SECRETS%\artex_pg.txt"
if defined APPPW set "HAVE_APPPW=1"
if not defined APPPW call :genpass
if not defined APPPW set "APPPW=%GENPASS%"
if not defined HAVE_APPPW >"%SECRETS%\artex_pg.txt" echo %APPPW%
echo         应用用户口令 : secrets\artex_pg.txt

rem ==========================================================================
rem [4/8] 数据目录（首次 initdb）+ 端口/监听
rem ==========================================================================
if exist "%PGDATA%\PG_VERSION" goto :step4_conf
echo [4/8] 首次运行：初始化数据库集群 ...
if exist "%PGDATA%" (
  echo         数据目录不完整（无 PG_VERSION），先清空 %PGDATA%
  rmdir /s /q "%PGDATA%" 2>nul
)
mkdir "%PGDATA%" 2>nul
set "PWTMP=%TMPDIR%\pgpw.txt"
>"%PWTMP%" echo %PGPW%
"%PGBIN%\initdb.exe" -D "%PGDATA%" -U %PGSUPER% -E UTF8 --locale=C -A scram-sha-256 --pwfile="%PWTMP%" >"%LOGS%\initdb.log" 2>&1
del "%PWTMP%" 2>nul
if exist "%PGDATA%\PG_VERSION" goto :initdb_ok
set "TAILFILE=%LOGS%\initdb.log"
goto :err_initdb
:initdb_ok
echo         集群已初始化: %PGDATA%
:step4_conf
if not exist "%PGDATA%\postgresql.conf" goto :err_initdb
call :pgconf "port = %PGPORT%"
call :pgconf "listen_addresses = '%PGHOST%'"
echo [4/8] 端口 %PGPORT%，监听 %PGHOST%（已写入 postgresql.conf）

rem ==========================================================================
rem [5/8] 启动 PostgreSQL
rem ==========================================================================
echo [5/8] 启动 PostgreSQL ...
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" status >nul 2>&1
if not errorlevel 1 goto :step5_ok
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -l "%LOGS%\pg.log" -w -t 60 start
if errorlevel 1 (
  set "TAILFILE=%LOGS%\pg.log"
  goto :err_pgstart
)
:step5_ok
echo         已在运行: %PGHOST%:%PGPORT%

rem ==========================================================================
rem [6/8] 角色与数据库
rem ==========================================================================
set "PGPASSWORD=%PGPW%"
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d postgres -w -tAc "select 1 from pg_roles where rolname='%PGAPP%'" >"%TMPDIR%\role.txt" 2>"%TMPDIR%\role.err"
if errorlevel 1 (
  set "TAILFILE=%TMPDIR%\role.err"
  set "TAILN=10"
  goto :err_pgauth
)
findstr /c:"1" "%TMPDIR%\role.txt" >nul
if not errorlevel 1 goto :step6_db
echo [6/8] 创建角色 %PGAPP% ...
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d postgres -w -c "create role %PGAPP% login password '%APPPW%'" >"%LOGS%\pg-init.log" 2>&1
if errorlevel 1 (
  set "TAILFILE=%LOGS%\pg-init.log"
  set "TAILN=10"
  goto :err_pgrole
)
:step6_db
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d postgres -w -tAc "select 1 from pg_database where datname='%PGDB%'" >"%TMPDIR%\db.txt" 2>nul
findstr /c:"1" "%TMPDIR%\db.txt" >nul
if not errorlevel 1 goto :step6_verify
echo [6/8] 创建数据库 %PGDB% ...
"%PGBIN%\createdb.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -w -O %PGAPP% %PGDB% >>"%LOGS%\pg-init.log" 2>&1
if errorlevel 1 (
  set "TAILFILE=%LOGS%\pg-init.log"
  set "TAILN=10"
  goto :err_pgdb
)
:step6_verify
set "PGPASSWORD=%APPPW%"
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGAPP% -d %PGDB% -w -tAc "select 1" >"%TMPDIR%\app.txt" 2>"%TMPDIR%\app.err"
if errorlevel 1 goto :warn_appauth
findstr /c:"1" "%TMPDIR%\app.txt" >nul
if errorlevel 1 goto :warn_appauth
echo [6/8] 角色与数据库就绪，连接自检通过
goto :step7

rem ==========================================================================
rem [7/8] config.json
rem ==========================================================================
:warn_appauth
echo [警告] 角色 %PGAPP% 无法用 secrets\artex_pg.txt 里的口令登录 %PGDB%。
echo        多半是该角色口令与文件不一致。两种修法：
echo          1) 用 psql 执行: ALTER ROLE %PGAPP% LOGIN PASSWORD '...';
echo             （口令填 secrets\artex_pg.txt 的内容）
echo          2) 或删除 %SECRETS%\artex_pg.txt 后重跑本脚本（会重新生成口令）
echo        脚本继续执行，但 ARTEX 可能连不上数据库。
goto :step7

:step7
echo [7/8] 检查 config.json ...
if exist "%CONFIG%" goto :step7_fix
mkdir "%PA%\config" 2>nul
>"%CONFIG%" echo {
>>"%CONFIG%" echo   "database": {
>>"%CONFIG%" echo     "host": "%PGHOST%",
>>"%CONFIG%" echo     "port": %PGPORT%,
>>"%CONFIG%" echo     "user": "%PGAPP%",
>>"%CONFIG%" echo     "password": "%APPPW%",
>>"%CONFIG%" echo     "dbname": "%PGDB%",
>>"%CONFIG%" echo     "sslmode": "disable"
>>"%CONFIG%" echo   },
>>"%CONFIG%" echo   "skill_dir": "%SKILLS:\=/%"
>>"%CONFIG%" echo }
echo         已生成: %CONFIG%
goto :step8
:step7_fix
rem skill_dir 优先级高于默认值，指向不存在的目录会让 skills 被静默跳过 —— 这里修掉
findstr /i /c:"%SKILLS:\=/%" "%CONFIG%" >nul
if not errorlevel 1 goto :step7_ok
echo         config.json 里的 skill_dir 不是当前仓库路径，修正中 ...
set "CONFIG_FIX=%CONFIG%"
set "SKILL_DIR_NEW=%SKILLS:\=/%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=$env:CONFIG_FIX; $j=Get-Content -Raw -LiteralPath $p | ConvertFrom-Json; $j.skill_dir=$env:SKILL_DIR_NEW; $t=($j | ConvertTo-Json -Depth 8); [System.IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding($false)))"
if errorlevel 1 goto :warn_config
echo         已修正 skill_dir = %SKILLS:\=/%（UTF-8 无 BOM）
goto :step8
:step7_ok
echo         已存在且 skill_dir 正确: %SKILLS:\=/%
goto :step8

:warn_config
echo [警告] config.json 自动修正失败（可能不是合法 JSON）。请手工把其中的
echo        "skill_dir" 改成: %SKILLS:\=/%"

rem ==========================================================================
rem [8/8] 启动 ARTEX + 初始化管理员
rem ==========================================================================
:step8
echo [8/8] 启动 ARTEX ...
call :health
if "%HEALTHY%"=="1" goto :artex_up
if not defined ARTEX_PLANNER_HEARTBEAT_FLOOR set "ARTEX_PLANNER_HEARTBEAT_FLOOR=300"
set "ARTEX_CONFIG=%CONFIG%"
set "PGPASSWORD="
start "ARTEX 后端" /min cmd /c ""%ARTEXEXE%" -addr %PGHOST%:%HTTPPORT% -data "%STATE%\data" -proxy %PGHOST%:%PROXYPORT% 1>>"%LOGS%\artex.out.log" 2>>"%LOGS%\artex.err.log""
echo         启动中（心跳下限 %ARTEX_PLANNER_HEARTBEAT_FLOOR%s），等待就绪 ...
set /a TRY=0
:waitloop
set /a TRY+=1
if %TRY% gtr 40 (
  set "TAILFILE=%LOGS%\artex.err.log"
  goto :err_artex
)
>nul ping -n 2 %PGHOST%
call :health
if "%HEALTHY%"=="1" goto :artex_up
goto :waitloop

:artex_up
echo         已就绪: %BASEURL%
echo.
echo         初始化管理员 ...
set "NEWPW="
powershell -NoProfile -Command "$r=(Invoke-RestMethod -Uri ($env:BASEURL + '/api/auth/status') -TimeoutSec 10).initialized; if($r){'INIT_YES'}else{'INIT_NO'}" >"%TMPDIR%\auth.txt" 2>nul
findstr /c:"INIT_YES" "%TMPDIR%\auth.txt" >nul
if not errorlevel 1 goto :auth_done
call :genpass
set "ADMINPW=%GENPASS%"
powershell -NoProfile -Command "$b=@{password=$env:ADMINPW} | ConvertTo-Json; try{ Invoke-RestMethod -Uri ($env:BASEURL + '/api/auth/init') -Method Post -Body $b -ContentType 'application/json' -TimeoutSec 30 | Out-Null; 'AUTH_OK' } catch { 'AUTH_FAIL ' + $_.Exception.Message }" >"%TMPDIR%\authinit.txt" 2>&1
findstr /c:"AUTH_OK" "%TMPDIR%\authinit.txt" >nul
if errorlevel 1 (
  set "TAILFILE=%TMPDIR%\authinit.txt"
  set "TAILN=5"
  goto :err_authinit
)
>"%SECRETS%\admin_password.txt" echo %ADMINPW%
set "NEWPW=%ADMINPW%"
echo         管理员已创建（用户名固定 ARTEX）
goto :summary
:auth_done
echo         管理员已初始化过，跳过（密码见 secrets\admin_password.txt）

:summary
echo.
echo ============================================================
echo   启动完成
echo ============================================================
echo   控制台      : %BASEURL%
echo   登录用户    : ARTEX
if defined NEWPW echo   登录密码    : %NEWPW%
echo   密码文件    : %SECRETS%\admin_password.txt
echo   录制代理    : %PGHOST%:%PROXYPORT%
echo   数据目录    : %STATE%\data
echo   日志        : %LOGS%\artex.err.log
echo   停止        : pwsh -File .\pentest-ai\scripts\stop.ps1
echo ============================================================
echo.
echo   提示：ARTEX 启动时会自动恢复数据库里所有「非终态且非排队」的任务。
echo         如不想让它立刻开跑，先在控制台把任务暂停。
echo.
if defined OPENBROWSER start "" "%BASEURL%"
goto :finish

rem ==========================================================================
rem 子过程
rem ==========================================================================
:genpass
set "GENPASS="
for /f "delims=" %%g in ('powershell -NoProfile -Command "([guid]::NewGuid().ToString()+[guid]::NewGuid().ToString()).Substring(0,28)"') do set "GENPASS=%%g"
if not defined GENPASS set "GENPASS=artex%RANDOM%%RANDOM%%RANDOM%%RANDOM%"
goto :eof

:health
set "HEALTHY="
powershell -NoProfile -Command "try{ (Invoke-WebRequest -Uri ($env:BASEURL + '/api/health') -UseBasicParsing -TimeoutSec 3).StatusCode } catch { 0 }" >"%TMPDIR%\health.txt" 2>nul
findstr /c:"200" "%TMPDIR%\health.txt" >nul
if not errorlevel 1 set "HEALTHY=1"
goto :eof

:pgconf
findstr /r /c:"^[ ]*%~1" "%PGDATA%\postgresql.conf" >nul
if not errorlevel 1 goto :eof
>>"%PGDATA%\postgresql.conf" echo %~1
goto :eof

:tail
powershell -NoProfile -Command "if(Test-Path -LiteralPath $env:TAILFILE){ Get-Content -LiteralPath $env:TAILFILE -Tail %TAILN% }" 2>nul
goto :eof

rem ==========================================================================
rem 错误分支
rem ==========================================================================
:err_nopa
echo [错误] 找不到 %PA%
echo        请把 install.bat 放在 ARTEX 仓库根目录（与 pentest-ai\ 同级）后重试。
goto :fail

:err_nopgsql
echo [错误] 便携 PostgreSQL 不可用：既没有 %PGBIN%\pg_ctl.exe，
echo        也没有可展开的 %RT%\downloads\pgsql-*.zip。
echo        请从项目 Releases 下载完整 zip 包（内含 runtime\pgsql），
echo        或改用 Docker：copy .env.example .env 后 docker compose up -d
goto :fail

:err_pgsql_broken
echo [错误] %RT%\pgsql 存在但没有 bin\pg_ctl.exe（疑似解压不完整）。
echo        请手动删除该目录后重新运行本脚本（会从 downloads 里的 zip 重新展开）。
goto :fail

:err_noartex
echo [错误] 找不到 %ARTEXEXE%
echo        请从项目 Releases 下载对应平台 zip（内含 artex.exe），或本地编译：
echo          cd web ^&^& npm ci ^&^& npm run build:static
echo          copy /y web\out\* server\webui\dist\
echo          go build -tags embedui -o pentest-ai\runtime\artex.exe .\cmd\artex
goto :fail

:err_initdb
echo [错误] 初始化数据库集群失败。日志末尾：
call :tail
goto :fail

:err_pgstart
echo [错误] PostgreSQL 启动失败。日志末尾：
call :tail
goto :fail

:err_pgauth
echo [错误] 用超级用户 %PGSUPER% 连接 PostgreSQL 失败（%PGHOST%:%PGPORT%）。
echo        脚本读取的口令来自 %SECRETS%\pg_super.txt。
echo        若该文件缺失或口令已改，请把正确的超级用户口令写入该文件后重试。
call :tail
goto :fail

:err_pgrole
echo [错误] 创建角色 %PGAPP% 失败。日志末尾：
call :tail
goto :fail

:err_pgdb
echo [错误] 创建数据库 %PGDB% 失败。日志末尾：
call :tail
goto :fail

:err_artex
echo [错误] ARTEX 在 80 秒内没有就绪，已中止等待。日志末尾：
call :tail
goto :fail

:err_authinit
echo [错误] 管理员初始化失败（接口返回错误）：
call :tail
echo        可以打开 %BASEURL%/setup 在浏览器里设置管理员密码。
goto :fail

rem ==========================================================================
rem 收尾
rem ==========================================================================
:fail
echo.
echo [失败] 安装/启动未完成。详细日志: %LOGS%
if defined TMPDIR if exist "%TMPDIR%" rmdir /s /q "%TMPDIR%" 2>nul
chcp %OLDCP% >nul 2>&1
if defined PAUSE_ON_EXIT pause
endlocal
exit /b 1

:finish
if defined TMPDIR if exist "%TMPDIR%" rmdir /s /q "%TMPDIR%" 2>nul
chcp %OLDCP% >nul 2>&1
if defined PAUSE_ON_EXIT pause
endlocal
exit /b 0
