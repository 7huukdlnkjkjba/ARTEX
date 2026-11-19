@echo off
for /f "tokens=2 delims=:" %%c in ('chcp') do set "OLDCP=%%c"
set "OLDCP=%OLDCP: =%"
chcp 65001 >nul
setlocal EnableExtensions

cd /d "%~dp0"

if not defined PGHOST    set "PGHOST=127.0.0.1"
if not defined HTTPPORT  set "HTTPPORT=8787"
if not defined PROXYPORT set "PROXYPORT=8788"
if not defined PGSUPER   set "PGSUPER=postgres"
if not defined PGAPP     set "PGAPP=artex"
if not defined PGDB      set "PGDB=artex"
set "AUTO_PGPORT_CHANGED="
set "OPENBROWSER=1"

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

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PA=%ROOT%\pentest-ai"
set "RT=%PA%\runtime"
set "PGBIN=%RT%\pgsql\bin"
set "PGDATA=%RT%\pgdata"
set "SECRETS=%RT%\secrets"
set "LOGS=%RT%\logs"
set "PGPORT_STATE=%RT%\pg_port.txt"
if not defined PGPORT if exist "%PGPORT_STATE%" set /p PGPORT=<"%PGPORT_STATE%"
if defined PGPORT for /f "delims=0123456789" %%x in ("%PGPORT%") do set "PGPORT="
if not defined PGPORT set "PGPORT=5544"
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

echo [1/8] 检查便携 PostgreSQL ...
if exist "%PGBIN%\pg_ctl.exe" if exist "%PGBIN%\initdb.exe" goto :step1_ok
set "PGZIP="
for %%z in ("%RT%\downloads\pgsql-*.zip") do set "PGZIP=%%~fz"
if defined PGZIP goto :step1_extract
mkdir "%RT%\downloads" 2>nul
set "PGZIP=%RT%\downloads\pgsql.zip"
if exist "%PGZIP%" goto :step1_extract
set "PGPART=%PGZIP%.part"
if exist "%PGPART%" del "%PGPART%" >nul 2>&1
echo         正在下载自定义 PostgreSQL（约 369 MB）...
where curl.exe >nul 2>&1
if errorlevel 1 goto :download_pg_powershell
curl.exe -fL --retry 3 --connect-timeout 30 --progress-bar -o "%PGPART%" "https://github.com/7huukdlnkjkjba/ARTEX/releases/download/v17.11/pgsql.zip"
if errorlevel 1 goto :err_pgdownload
goto :download_pg_done

:download_pg_powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='Continue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $wc = New-Object System.Net.WebClient; $wc.Headers['User-Agent'] = 'ARTEX-Installer'; $wc.DownloadProgressChanged += { param($sender, $e) Write-Progress -Activity '下载 PostgreSQL' -Status ('已下载 ' + [math]::Round($e.BytesReceived/1MB,1) + ' MB / ' + [math]::Round($e.TotalBytesToReceive/1MB,1) + ' MB') -PercentComplete ([Math]::Min(100, [int]($e.ProgressPercentage))) }; $wc.DownloadFile('https://github.com/7huukdlnkjkjba/ARTEX/releases/download/v17.11/pgsql.zip', $env:PGPART)"
if errorlevel 1 goto :err_pgdownload

:download_pg_done
move /y "%PGPART%" "%PGZIP%" >nul
if errorlevel 1 goto :err_pgdownload
:step1_extract
echo         正在解压 PostgreSQL（需要几分钟）...
echo         来源: %PGZIP%
powershell -NoProfile -ExecutionPolicy Bypass -Command "$zip=$env:PGZIP; $dst=$env:RT; Write-Progress -Activity '解压 PostgreSQL' -Status '正在展开压缩包' -PercentComplete 0; Expand-Archive -LiteralPath $zip -DestinationPath $dst -Force; Write-Progress -Activity '解压 PostgreSQL' -Status '解压完成' -PercentComplete 100"
if errorlevel 1 goto :err_pgextract
if not exist "%PGBIN%\pg_ctl.exe" goto :err_pgextract
if not exist "%PGBIN%\initdb.exe" goto :err_pgextract
:step1_ok
for /f "delims=" %%v in ('"%PGBIN%\pg_ctl.exe" --version 2^>nul') do echo          %%v

echo [2/8] 检查 artex.exe ...
if exist "%ARTEXEXE%" goto :step2_ok
if not exist "%ROOT%\artex.exe" goto :err_noartex
copy /y "%ROOT%\artex.exe" "%ARTEXEXE%" >nul
if errorlevel 1 goto :err_noartex_copy
:step2_ok
for %%f in ("%ARTEXEXE%") do echo          %%~nxf  %%~zf 字节

echo [3/8] 准备口令文件 ...
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

if exist "%PGDATA%\PG_VERSION" goto :step4_conf
echo [4/8] 初始化数据库集群（首次运行）...
echo         正在初始化 PostgreSQL 数据目录 ...
if not exist "%PGDATA%" goto :initdb_data_ready
echo         数据目录不完整（无 PG_VERSION），先清空 %PGDATA%
rmdir /s /q "%PGDATA%" 2>nul
:initdb_data_ready
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

echo [5/8] 启动 PostgreSQL ...
echo         正在启动 PostgreSQL 服务 ...
taskkill /f /im postgres.exe >nul 2>&1
if exist "%PGDATA%\postmaster.pid" del /f /q "%PGDATA%\postmaster.pid" >nul 2>&1

if exist "%LOGS%\pg.log" del /f /q "%LOGS%\pg.log" >nul 2>&1
type nul > "%LOGS%\pg.log" 2>nul

"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" status >nul 2>&1
if not errorlevel 1 goto :step5_ok

set "PGPORT_RETRIES=0"
call :find_pgport
if not defined FREEPORT set "TAILFILE=%TMPDIR%\pgport.err"
if not defined FREEPORT goto :err_pgport
if "%FREEPORT%"=="%PGPORT%" goto :step5_start
echo         端口 %PGPORT% 已被占用，自动切换到 %FREEPORT% ...
set "PGPORT=%FREEPORT%"
set "AUTO_PGPORT_CHANGED=1"
>>"%PGDATA%\postgresql.conf" echo port = %PGPORT%
if errorlevel 1 goto :err_pgconf
:step5_start
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -w -t 60 -o "-p %PGPORT%" start >> "%LOGS%\pg.log" 2>&1
if not errorlevel 1 goto :step5_started
call :find_pgport
if not defined FREEPORT goto :err_pgstart
if "%FREEPORT%"=="%PGPORT%" goto :err_pgstart
set /a PGPORT_RETRIES+=1
if %PGPORT_RETRIES% gtr 5 goto :err_pgstart
echo         端口启动时发生冲突，改用 %FREEPORT% 重试 ...
set "PGPORT=%FREEPORT%"
set "AUTO_PGPORT_CHANGED=1"
>>"%PGDATA%\postgresql.conf" echo port = %PGPORT%
if errorlevel 1 goto :err_pgconf
goto :step5_start
:step5_started
if not defined AUTO_PGPORT_CHANGED goto :step5_ok
>"%PGPORT_STATE%" echo %PGPORT%
if errorlevel 1 goto :err_pgportstate
:step5_ok
echo         已在运行: %PGHOST%:%PGPORT%

set "PGPASSWORD=%PGPW%"
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d postgres -w -tAc "select 1 from pg_roles where rolname='%PGAPP%'" >"%TMPDIR%\role.txt" 2>"%TMPDIR%\role.err"
if errorlevel 1 set "TAILFILE=%TMPDIR%\role.err"
if errorlevel 1 set "TAILN=10"
if errorlevel 1 goto :err_pgauth
findstr /c:"1" "%TMPDIR%\role.txt" >nul
if not errorlevel 1 goto :step6_db
echo [6/8] 创建角色 %PGAPP% ...
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d postgres -w -c "create role %PGAPP% login password '%APPPW%'" >"%LOGS%\pg-init.log" 2>&1
if errorlevel 1 set "TAILFILE=%LOGS%\pg-init.log"
if errorlevel 1 set "TAILN=10"
if errorlevel 1 goto :err_pgrole
:step6_db
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d postgres -w -tAc "select 1 from pg_database where datname='%PGDB%'" >"%TMPDIR%\db.txt" 2>nul
findstr /c:"1" "%TMPDIR%\db.txt" >nul
if not errorlevel 1 goto :step6_verify
echo [6/8] 创建数据库 %PGDB% ...
"%PGBIN%\createdb.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -w -O %PGAPP% %PGDB% >>"%LOGS%\pg-init.log" 2>&1
if errorlevel 1 set "TAILFILE=%LOGS%\pg-init.log"
if errorlevel 1 set "TAILN=10"
if errorlevel 1 goto :err_pgdb
:step6_verify
set "PGPASSWORD=%APPPW%"
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGAPP% -d %PGDB% -w -tAc "select 1" >"%TMPDIR%\app.txt" 2>"%TMPDIR%\app.err"
set "PGPASSWORD="
if errorlevel 1 goto :warn_appauth
findstr /c:"1" "%TMPDIR%\app.txt" >nul
if errorlevel 1 goto :warn_appauth
echo [6/8] 角色与数据库就绪，连接自检通过
goto :step7

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
rem config.json 里的数据库端口必须和本次实际启动的端口一致：安装脚本用
rem -o "-p %PGPORT%" 覆盖了 postgresql.conf 启动，只改 conf 不同步 config.json
rem 时 backend 仍会去连旧端口（历史上出现过 config=5433、集群=5544 的分叉）。
set "CONFIG_FIX=%CONFIG%"
set "SKILL_DIR_NEW=%SKILLS:\=/%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=$env:CONFIG_FIX; try{$j=Get-Content -Raw -LiteralPath $p | ConvertFrom-Json}catch{Write-Output ('CONFIG_PARSE_FAIL ' + $_.Exception.Message); exit 2}; if($null -eq $j.database){Write-Output 'CONFIG_PARSE_FAIL missing database'; exit 3}; $changes=@(); if(([string]$j.skill_dir) -ne $env:SKILL_DIR_NEW){$j.skill_dir=$env:SKILL_DIR_NEW; $changes+='skill_dir'}; $oldPort=[int]$j.database.port; if($oldPort -ne [int]$env:PGPORT){$j.database.port=[int]$env:PGPORT; $changes+=('database.port ' + $oldPort + ' to ' + $env:PGPORT)}; if($changes.Count -eq 0){Write-Output 'CONFIG_OK'; exit 0}; $t=($j | ConvertTo-Json -Depth 8); [System.IO.File]::WriteAllText($p,$t,(New-Object System.Text.UTF8Encoding($false))); Write-Output ('CONFIG_UPDATED ' + ($changes -join '; '))" >"%TMPDIR%\configfix.txt" 2>&1
set "CONFIGFIX_RC=%ERRORLEVEL%"
set "CONFIG_MSG="
if exist "%TMPDIR%\configfix.txt" set /p CONFIG_MSG=<"%TMPDIR%\configfix.txt"
if not "%CONFIGFIX_RC%"=="0" (
  set "TAILFILE=%TMPDIR%\configfix.txt"
  set "TAILN=10"
  goto :err_config_port
)
if "%CONFIG_MSG%"=="CONFIG_OK" goto :step7_ok
rem 用 type 打印，别用 echo %CONFIG_MSG%：消息里带 ">" 会让 cmd 当成重定向。
echo         config.json 已更新：
type "%TMPDIR%\configfix.txt"
goto :step8
:step7_ok
echo         已存在且端口/skill_dir 一致: %SKILLS:\=/%"
goto :step8

:warn_config
echo [警告] config.json 自动修正失败（可能不是合法 JSON）。请手工把其中的
echo        "skill_dir" 改成: %SKILLS:\=/%"
set "TAILFILE=%TMPDIR%\configfix.txt"
if exist "%TMPDIR%\configfix.txt" call :tail
goto :step8

:step8
echo [8/8] 启动 ARTEX ...
echo         正在启动 ARTEX 后端服务 ...
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
if %TRY% leq 40 goto :artex_wait_continue
set "TAILFILE=%LOGS%\artex.err.log"
goto :err_artex
:artex_wait_continue
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
if errorlevel 1 set "TAILFILE=%TMPDIR%\authinit.txt"
if errorlevel 1 set "TAILN=5"
if errorlevel 1 goto :err_authinit
>"%SECRETS%\admin_password.txt" echo %ADMINPW%
set "NEWPW=%ADMINPW%"
echo         管理员已创建（用户名固定 ARTEX）
goto :summary
:auth_done
set "ADMINPW="
if exist "%SECRETS%\admin_password.txt" set /p ADMINPW=<"%SECRETS%\admin_password.txt"
if not defined ADMINPW goto :auth_recover
powershell -NoProfile -Command "$b=@{username='ARTEX';password=$env:ADMINPW} | ConvertTo-Json -Compress; try{$r=Invoke-RestMethod -Uri ($env:BASEURL + '/api/auth/login') -Method Post -Body $b -ContentType 'application/json' -TimeoutSec 10; if($r.token){'LOGIN_OK'}else{'LOGIN_ERROR 登录接口未返回 token'; exit 1}} catch {$response=$_.Exception.Response; if($response -and [int]$response.StatusCode -eq 401){'LOGIN_BAD'}else{'LOGIN_ERROR ' + $_.Exception.Message; exit 1}}" >"%TMPDIR%\authverify.txt" 2>&1
findstr /c:"LOGIN_OK" "%TMPDIR%\authverify.txt" >nul
if not errorlevel 1 goto :auth_saved_ok
findstr /c:"LOGIN_BAD" "%TMPDIR%\authverify.txt" >nul
if not errorlevel 1 goto :auth_recover
set "TAILFILE=%TMPDIR%\authverify.txt"
goto :err_authverify

:auth_recover
echo         管理员密码文件缺失或不匹配，正在重置本机管理员密码 ...
call :genpass
set "ADMINPW=%GENPASS%"
set "PGPASSWORD=%PGPW%"
>"%TMPDIR%\reset-admin.sql" echo \set ON_ERROR_STOP on
>>"%TMPDIR%\reset-admin.sql" echo \getenv newpw ADMINPW
>>"%TMPDIR%\reset-admin.sql" echo CREATE EXTENSION IF NOT EXISTS pgcrypto;
>>"%TMPDIR%\reset-admin.sql" echo INSERT INTO settings(key, value)
>>"%TMPDIR%\reset-admin.sql" echo VALUES ('auth.password_hash', crypt(:'newpw', gen_salt('bf', 10)))
>>"%TMPDIR%\reset-admin.sql" echo ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();
"%PGBIN%\psql.exe" -h %PGHOST% -p %PGPORT% -U %PGSUPER% -d %PGDB% -w -v ON_ERROR_STOP=1 -f "%TMPDIR%\reset-admin.sql" >"%LOGS%\admin-password-reset.log" 2>&1
set "AUTHRESET_RC=%ERRORLEVEL%"
set "PGPASSWORD="
if not "%AUTHRESET_RC%"=="0" set "TAILFILE=%LOGS%\admin-password-reset.log"
if not "%AUTHRESET_RC%"=="0" goto :err_authreset
powershell -NoProfile -Command "$b=@{username='ARTEX';password=$env:ADMINPW} | ConvertTo-Json -Compress; try{$r=Invoke-RestMethod -Uri ($env:BASEURL + '/api/auth/login') -Method Post -Body $b -ContentType 'application/json' -TimeoutSec 10; if($r.token){'LOGIN_OK'}else{'LOGIN_ERROR 登录接口未返回 token'; exit 1}} catch {'LOGIN_ERROR ' + $_.Exception.Message; exit 1}" >"%TMPDIR%\authverify.txt" 2>&1
findstr /c:"LOGIN_OK" "%TMPDIR%\authverify.txt" >nul
if not errorlevel 1 goto :auth_reset_verified
set "TAILFILE=%TMPDIR%\authverify.txt"
goto :err_authresetverify
:auth_reset_verified
>"%SECRETS%\admin_password.txt" echo %ADMINPW%
if errorlevel 1 goto :err_authreset_save
set "NEWPW=%ADMINPW%"
echo         管理员密码已重置并保存到 secrets\admin_password.txt
goto :summary

:auth_saved_ok
echo         管理员密码文件验证通过
goto :summary

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

:genpass
set "GENPASS="
for /f "delims=" %%g in ('powershell -NoProfile -Command "([guid]::NewGuid().ToString()+[guid]::NewGuid().ToString()).Substring(0,28)"') do set "GENPASS=%%g"
if not defined GENPASS set "GENPASS=artex%RANDOM%%RANDOM%%RANDOM%%RANDOM%"
goto :eof

:find_pgport
set "FREEPORT="
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ip=$null; try{$ip=[Net.IPAddress]::Parse($env:PGHOST)}catch{$addresses=[Net.Dns]::GetHostAddresses($env:PGHOST); $ip=$addresses | Where-Object {$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork} | Select-Object -First 1; if(-not $ip){$ip=$addresses | Select-Object -First 1}}; if(-not $ip){exit 2}; $first=[int]$env:PGPORT; $last=[Math]::Min(65535,$first+100); for($port=$first; $port -le $last; $port++){ $listener=$null; try{$listener=[Net.Sockets.TcpListener]::new($ip,$port); $listener.Start(); $listener.Stop(); Write-Output $port; exit 0}catch{if($listener){try{$listener.Stop()}catch{}}}}; exit 1" >"%TMPDIR%\pgport.txt" 2>"%TMPDIR%\pgport.err"
for /f "usebackq delims=" %%p in ("%TMPDIR%\pgport.txt") do set "FREEPORT=%%p"
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

:err_nopa
echo [错误] 找不到 %PA%
echo        请把 install.bat 放在 ARTEX 仓库根目录（与 pentest-ai\ 同级）后重试。
goto :fail

:err_pgdownload
if exist "%PGPART%" del "%PGPART%" >nul 2>&1
echo [错误] PostgreSQL 下载失败。请检查网络后重试。
goto :fail

:err_pgextract
echo [错误] PostgreSQL 压缩包无效或解压失败: %PGZIP%
goto :fail

:err_noartex
echo [错误] 找不到 %ARTEXEXE%
echo        当前仓库根目录也没有预编译的 artex.exe。
echo        请获取 ARTEX Windows Release 程序文件；无需在本机编译。
goto :fail

:err_noartex_copy
echo [错误] 无法将仓库根目录的 artex.exe 复制到 %ARTEXEXE%
goto :fail

:err_initdb
echo [错误] 初始化数据库集群失败。日志末尾：
call :tail
goto :fail

:err_pgstart
echo [错误] PostgreSQL 启动失败。日志末尾：
call :tail
goto :fail

:err_pgport
set "TAILN=5"
echo [错误] PostgreSQL 端口 %PGPORT% 附近没有可用端口，或无法检查监听地址。
echo        请检查 %PGHOST% 和以下错误信息，或手动设置 PGPORT 后重试。
call :tail
goto :fail

:err_pgportstate
echo [错误] PostgreSQL 已启动，但无法保存自动选择的端口到 %PGPORT_STATE%。
goto :fail

:err_pgconf
echo [错误] 无法将自动选择的 PostgreSQL 端口写入 postgresql.conf。
goto :fail

:err_config_port
echo [错误] PostgreSQL 已切换到端口 %PGPORT%，但无法同步 config.json。
echo        请检查该文件格式及数据库配置后重试。
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
echo [错误] ARTEX 在约 80 秒内没有就绪，已中止等待。日志末尾：
call :tail
goto :fail

:err_authinit
echo [错误] 管理员初始化失败（接口返回错误）：
call :tail
echo        可以打开 %BASEURL%/setup 在浏览器里设置管理员密码。
goto :fail

:err_authverify
set "TAILN=5"
echo [错误] 无法确认管理员密码是否有效；未修改现有密码。
call :tail
goto :fail

:err_authreset
echo [错误] 无法重置本机管理员密码；现有密码文件未覆盖。
echo        请检查 %LOGS%\admin-password-reset.log 和 PostgreSQL 超级用户口令。
call :tail
goto :fail

:err_authresetverify
set "TAILN=5"
echo [错误] 数据库已更新密码，但 ARTEX 登录接口未接受新密码。
echo        请检查 config.json 中的数据库连接是否与本机 PostgreSQL 一致。
echo        本次写入本机数据库的新密码: %ADMINPW%
call :tail
goto :fail

:err_authreset_save
echo [错误] 管理员密码已重置，但无法写入密码文件。
echo        本次新密码为: %ADMINPW%
goto :fail

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
