@echo off
setlocal EnableExtensions
chcp 936 >nul
title 删除 APTEX 渗透记录（直接执行，不可恢复）
color 0C

rem ================================================================
rem  删除 APTEX / ARTEX 记录（默认 clear 模式，无备份）
rem  模式：clear / all / verify
rem
rem  用法:
rem    1. 双击运行                      -> 执行 clear（清理渗透记录）
rem    2. 删除APTEX渗透记录.bat all     -> 清空全部（含资产/公司/凭据）
rem    3. 删除APTEX渗透记录.bat verify  -> 只删除「漏洞验证」记录
rem ================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "MODE=%~1"
if not defined MODE set "MODE=clear"

if /I "%MODE%"=="help" goto usage
if /I "%MODE%"=="-h"   goto usage
if /I "%MODE%"=="/?"   goto usage

set "MODE_OK="
if /I "%MODE%"=="clear"  set "MODE_OK=1"
if /I "%MODE%"=="all"    set "MODE_OK=1"
if /I "%MODE%"=="verify" set "MODE_OK=1"
if not defined MODE_OK goto bad_mode

rem --- 自动探测工作目录 (兼容带或不带 pentest-ai 文件夹) ---
set "PA=%ROOT%\pentest-ai"
if not exist "%PA%\runtime\pgsql\bin\psql.exe" set "PA=%ROOT%"

set "PSQL=%PA%\runtime\pgsql\bin\psql.exe"
set "DATA=%PA%\state\data"
set "CFG=%PA%\config\config.json"
set "SECRET=%PA%\runtime\secrets\artex_pg.txt"

if not exist "%PSQL%" goto bad_location
if not exist "%CFG%" goto bad_location
if not exist "%DATA%" goto bad_location

call :stop_artex
call :load_db
if errorlevel 1 goto fail
call :check_pg
if errorlevel 1 goto fail
call :counts
if errorlevel 1 goto fail
if /I "%MODE%"=="verify" call :verify_counts
if errorlevel 1 goto fail

echo.
echo ================================================================
echo   START DELETING RECORDS (%MODE%) - NO BACKUP
echo ================================================================
echo   Target DB: %DBHOST%:%DBPORT%/%DBNAME%
echo ----------------------------------------------------------------
if /I "%MODE%"=="verify" (
  echo   Found verifier conversations: %N_VERIFY_CONVS% ^| finding_checks: %N_CHECKS%
) else (
  echo   tasks: %N_TASKS% ^| findings: %N_FINDINGS% ^| explorations: %N_EXPL%
  echo   llm_usage: %N_LLMUSAGE% ^| tool_usage: %N_TOOLUSAGE%
  if /I "%MODE%"=="all" (
    echo   [ALL MODE] assets: %N_ASSETS% ^| companies: %N_COMPANIES%
    echo              credentials: %N_CREDS% ^| conversations: %N_CONVS%
  )
)
echo ----------------------------------------------------------------
echo.

if /I "%MODE%"=="verify" goto do_verify

rem ---- clear / all 模式：删除渗透记录 ----
call :clear_db
if errorlevel 1 (
  echo.
  echo [ERROR] Database clear failed.
  goto fail
)
call :delete_data
goto done

rem ---- verify 模式：只删除漏洞验证记录 ----
:do_verify
call :clear_verify
if errorlevel 1 (
  echo.
  echo [ERROR] Verification clear failed.
  goto fail
)
call :delete_verify_data

:done
echo.
echo ================================================================
echo   DONE. Records deleted.
echo ================================================================
timeout /t 3 >nul
exit /b 0

rem ================================================================
rem  Subroutines
rem ================================================================

:stop_artex
tasklist /FI "IMAGENAME eq artex.exe" 2>nul | find /I "artex.exe" >nul
if not errorlevel 1 (
  echo [INFO] Stopping running ARTEX process ...
  taskkill /F /IM artex.exe >nul 2>&1
  timeout /t 2 /nobreak >nul
)
exit /b 0

:load_db
set "PGPASSWORD="
if exist "%SECRET%" (
  for /f "usebackq delims=" %%p in ("%SECRET%") do (
    if not defined PGPASSWORD set "PGPASSWORD=%%p"
  )
)
if not defined PGPASSWORD exit /b 1

set "DBINFO="
set "PSFILE=%TEMP%\artex_dbinfo_%RANDOM%.txt"
set "ARTEX_CFG=%CFG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c=ConvertFrom-Json (Get-Content -Raw -Encoding UTF8 $env:ARTEX_CFG); '{0},{1},{2},{3}' -f $c.database.host,$c.database.port,$c.database.user,$c.database.dbname" > "%PSFILE%" 2>nul
if exist "%PSFILE%" (
  for /f "usebackq delims=" %%i in ("%PSFILE%") do set "DBINFO=%%i"
)
del "%PSFILE%" >nul 2>&1
if not defined DBINFO exit /b 1

for /f "tokens=1-4 delims=," %%a in ("%DBINFO%") do (
  set "DBHOST=%%a"
  set "DBPORT=%%b"
  set "DBUSER=%%c"
  set "DBNAME=%%d"
)
if not defined DBHOST exit /b 1
if not defined DBPORT exit /b 1
if not defined DBUSER exit /b 1
if not defined DBNAME exit /b 1

set "PGCONNECT_TIMEOUT=5"
set "PGCLIENTENCODING=UTF8"
exit /b 0

:check_pg
"%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -t -A -c "select 1" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Cannot connect to DB.
  exit /b 1
)
exit /b 0

:counts
set "COUNT_FILE=%TEMP%\artex_counts_%RANDOM%.txt"
"%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -t -A -F "," -c "select (select count(*) from tasks),(select count(*) from findings),(select count(*) from explorations),(select count(*) from llm_usage),(select count(*) from tool_usage),(select count(*) from assets),(select count(*) from companies),(select count(*) from credentials),(select count(*) from conversations)" > "%COUNT_FILE%" 2>nul
if errorlevel 1 (
  del "%COUNT_FILE%" >nul 2>&1
  exit /b 1
)
for /f "usebackq tokens=1-9 delims=," %%a in ("%COUNT_FILE%") do (
  set "N_TASKS=%%a" & set "N_FINDINGS=%%b" & set "N_EXPL=%%c" & set "N_LLMUSAGE=%%d" & set "N_TOOLUSAGE=%%e"
  set "N_ASSETS=%%f" & set "N_COMPANIES=%%g" & set "N_CREDS=%%h" & set "N_CONVS=%%i"
)
del "%COUNT_FILE%" >nul 2>&1
exit /b 0

:verify_counts
set "COUNT_FILE=%TEMP%\artex_vcounts_%RANDOM%.txt"
rem 扩大匹配范围：兼容 agent_key 为 verifier/verify，或标题带“验证”
"%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -t -A -F "," -c "select (select count(*) from conversations where agent_key in ('verifier','verify','vuln_verifier') or title like '%%验证%%'),(select count(*) from finding_checks)" > "%COUNT_FILE%" 2>nul
if errorlevel 1 (
  del "%COUNT_FILE%" >nul 2>&1
  exit /b 1
)
for /f "usebackq tokens=1-2 delims=," %%a in ("%COUNT_FILE%") do (
  set "N_VERIFY_CONVS=%%a" & set "N_CHECKS=%%b"
)
del "%COUNT_FILE%" >nul 2>&1
exit /b 0

:clear_db
set "SQLFILE=%TEMP%\artex_clear_%RANDOM%.sql"
> "%SQLFILE%" echo \set ON_ERROR_STOP on
>>"%SQLFILE%" echo BEGIN;
>>"%SQLFILE%" echo DELETE FROM findings;
>>"%SQLFILE%" echo DELETE FROM tasks;
>>"%SQLFILE%" echo DELETE FROM explorations;
>>"%SQLFILE%" echo DELETE FROM intercept_pending;
>>"%SQLFILE%" echo DELETE FROM pending_scope;
>>"%SQLFILE%" echo DELETE FROM llm_usage;
>>"%SQLFILE%" echo DELETE FROM llm_records;
>>"%SQLFILE%" echo DELETE FROM tool_usage;
>>"%SQLFILE%" echo DELETE FROM skill_usage;
>>"%SQLFILE%" echo DELETE FROM exploits;
>>"%SQLFILE%" echo DELETE FROM vulnhunt_runs;
>>"%SQLFILE%" echo DELETE FROM evolve_costs;
>>"%SQLFILE%" echo DELETE FROM evolve_runs;
>>"%SQLFILE%" echo DELETE FROM genome_phenotypes;
>>"%SQLFILE%" echo DELETE FROM traffic_evidence_snapshots;
>>"%SQLFILE%" echo DELETE FROM tunnels;
if /I "%MODE%"=="all" (
  >>"%SQLFILE%" echo DELETE FROM credentials;
  >>"%SQLFILE%" echo DELETE FROM assets;
  >>"%SQLFILE%" echo DELETE FROM companies;
  >>"%SQLFILE%" echo DELETE FROM conversations;
)
>>"%SQLFILE%" echo COMMIT;

echo [1/2] Deleting DB records ...
"%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -v ON_ERROR_STOP=1 -f "%SQLFILE%"
set "RC=%errorlevel%"
del "%SQLFILE%" >nul 2>&1
if not "%RC%"=="0" exit /b 1

for %%t in (tasks findings explorations exploration_nodes exploration_edges activity llm_usage tool_usage) do (
  "%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -c "VACUUM (ANALYZE) %%t" >nul 2>&1
)
exit /b 0

:clear_verify
set "SQLFILE=%TEMP%\artex_clear_verify_%RANDOM%.sql"
set "IDFILE=%TEMP%\artex_verify_convids_%RANDOM%.txt"

rem 1. 抓取需要删除的会话 ID
"%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -t -A -c "select id from conversations where agent_key in ('verifier','verify','vuln_verifier') or title like '%%验证%%' order by id" > "%IDFILE%" 2>nul

rem 2. 执行 SQL：用 DO 块检查可选表是否存在，避免事务因表不存在而整体回滚
> "%SQLFILE%" echo \set ON_ERROR_STOP on
>>"%SQLFILE%" echo BEGIN;
>>"%SQLFILE%" echo DO $$
>>"%SQLFILE%" echo BEGIN
>>"%SQLFILE%" echo   IF to_regclass('public.finding_checks') IS NOT NULL THEN
>>"%SQLFILE%" echo     DELETE FROM finding_checks;
>>"%SQLFILE%" echo   END IF;
>>"%SQLFILE%" echo   IF to_regclass('public.conversation_activities') IS NOT NULL THEN
>>"%SQLFILE%" echo     DELETE FROM conversation_activities WHERE conversation_id IN (SELECT id FROM conversations WHERE agent_key in ('verifier','verify','vuln_verifier') or title like '%%验证%%');
>>"%SQLFILE%" echo   END IF;
>>"%SQLFILE%" echo   DELETE FROM conversations WHERE agent_key in ('verifier','verify','vuln_verifier') or title like '%%验证%%';
>>"%SQLFILE%" echo END $$;
>>"%SQLFILE%" echo COMMIT;

echo [1/2] Deleting verification records ...
"%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -v ON_ERROR_STOP=1 -f "%SQLFILE%"
set "RC=%errorlevel%"
del "%SQLFILE%" >nul 2>&1
if not "%RC%"=="0" exit /b 1

for %%t in (finding_checks conversations conversation_activities) do (
  "%PSQL%" -w -h "%DBHOST%" -p "%DBPORT%" -U "%DBUSER%" -d "%DBNAME%" -c "VACUUM (ANALYZE) %%t" >nul 2>&1
)
exit /b 0

:delete_data
echo [2/2] Deleting local data ...
for %%d in (tasks traffic traffic-tasks archives evidence stage tunnels) do (
  if exist "%DATA%\%%d" (
    rmdir /S /Q "%DATA%\%%d" >nul 2>&1
  )
)
if exist "%DATA%\transcripts" (
  for %%f in ("%DATA%\transcripts\exp*") do (
    del /F /Q "%%~ff" >nul 2>&1
  )
)
if /I "%MODE%"=="all" (
  if exist "%DATA%\sessions" (
    rmdir /S /Q "%DATA%\sessions" >nul 2>&1
  )
  if exist "%DATA%\transcripts" (
    for %%f in ("%DATA%\transcripts\conv*") do (
      del /F /Q "%%~ff" >nul 2>&1
    )
  )
)
exit /b 0

:delete_verify_data
echo [2/2] Deleting verification local data ...
if not exist "%IDFILE%" exit /b 0
for /f "usebackq delims=" %%i in ("%IDFILE%") do (
  rem 兼容有前缀和无前缀的文件/目录名
  if exist "%DATA%\sessions\conv-%%i" rmdir /S /Q "%DATA%\sessions\conv-%%i" >nul 2>&1
  if exist "%DATA%\sessions\%%i" rmdir /S /Q "%DATA%\sessions\%%i" >nul 2>&1
  
  if exist "%DATA%\transcripts\conv-%%i" rmdir /S /Q "%DATA%\transcripts\conv-%%i" >nul 2>&1
  if exist "%DATA%\transcripts\conv-%%i.jsonl" del /F /Q "%DATA%\transcripts\conv-%%i.jsonl" >nul 2>&1
  
  if exist "%DATA%\transcripts\%%i" rmdir /S /Q "%DATA%\transcripts\%%i" >nul 2>&1
  if exist "%DATA%\transcripts\%%i.jsonl" del /F /Q "%DATA%\transcripts\%%i.jsonl" >nul 2>&1
)
del "%IDFILE%" >nul 2>&1
exit /b 0

:bad_mode
echo.
echo [ERROR] 未知模式: %MODE%
echo 支持的模式: clear ^| all ^| verify
echo 运行 "删除APTEX渗透记录.bat help" 查看用法。
pause
exit /b 1

:usage
echo.
echo 用法: 删除APTEX渗透记录.bat [模式]
echo.
echo   clear   默认。删除渗透记录(任务/漏洞/探索/用量/证据等)，保留资产、公司、凭据、会话
echo   all     在 clear 基础上再删除资产、公司、凭据、会话(全部记录)
echo   verify  只删除「漏洞验证」记录
echo.
echo 警告: 删除不可恢复，脚本不会备份。
pause
exit /b 0

:bad_location
echo [ERROR] Cannot find the correct directories!
echo Searched in: %ROOT%\ and %ROOT%\pentest-ai\
echo Missing: runtime\pgsql\bin\psql.exe or config\config.json
pause
exit /b 1

:fail
echo.
echo Operation failed. See errors above.
pause
exit /b 1