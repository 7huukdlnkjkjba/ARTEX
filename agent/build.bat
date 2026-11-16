@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion

set "GOFLAGS=-buildvcs=false"

if exist "%~dp0go.mod" (
  pushd "%~dp0" >nul 2>nul
) else (
  pushd "%~dp0.." >nul 2>nul
)
if errorlevel 1 (
  echo [ERROR] cannot enter repository root from %~dp0
  pause
  exit /b 1
)
set "REPO=%CD%"

if not exist "%REPO%\go.mod" (
  echo [ERROR] go.mod not found under %REPO%
  popd
  pause
  exit /b 1
)

set "COMMIT_MSG="
set "DO_TEST=0"
set "DO_COMMIT=1"
set "DO_PUSH=1"
set "DO_PAUSE=1"
set "PUSH_FAILED="
set "AHEAD=0"
set "BEHIND=0"
set "BRANCH="

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--help" goto usage
if /I "%~1"=="--test"            (set "DO_TEST=1"          & shift & goto parse_args)
if /I "%~1"=="--no-commit"       (set "DO_COMMIT=0"        & shift & goto parse_args)
if /I "%~1"=="--no-push"         (set "DO_PUSH=0"          & shift & goto parse_args)
if /I "%~1"=="--no-pause"        (set "DO_PAUSE=0"         & shift & goto parse_args)
if defined COMMIT_MSG (
  set "COMMIT_MSG=%COMMIT_MSG% %~1"
) else (
  set "COMMIT_MSG=%~1"
)
shift
goto parse_args

:args_done
if not defined COMMIT_MSG set "COMMIT_MSG=chore: build %DATE% %TIME%"

where go >nul 2>nul
if errorlevel 1 (
  echo [ERROR] go not found in PATH
  goto fail
)
where git >nul 2>nul
if errorlevel 1 (
  echo [ERROR] git not found in PATH
  goto fail
)

if not defined GOCACHE set "GOCACHE=%REPO%\.gocache"
if not exist "%GOCACHE%" mkdir "%GOCACHE%" >nul 2>nul
if not defined GOTMPDIR set "GOTMPDIR=%REPO%\.gotmp"
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%" >nul 2>nul

echo.
echo ============================================================
echo  ARTEX build / GitHub update
echo  Repo    : %REPO%
echo  Commit  : %COMMIT_MSG%
echo  GOFLAGS : %GOFLAGS%
echo ============================================================
echo.

echo [1/4] go build ./...
go build ./... || goto build_fail

echo.
echo [2/4] go build -o artex.exe ./cmd/artex
go build -o "%REPO%\artex.exe" ./cmd/artex || goto build_fail

if "%DO_TEST%"=="1" (
  echo.
  echo [test] go test ./agent
  go test ./agent || goto test_fail
)

if "%DO_COMMIT%"=="0" (
  echo.
  echo [done] build only; no commit/push requested.
  goto cleanup
)

echo.
echo [3/4] staging changes (强制全局添加)
git add -A

git status --short
git diff --cached --quiet
if not errorlevel 1 (
  echo [info] no staged changes; nothing to commit.
  if "%DO_PUSH%"=="1" (
    call :push_if_ahead
    if defined PUSH_FAILED goto push_fail
  )
  goto cleanup
)

echo [4/4] git commit
git commit -m "%COMMIT_MSG%" || goto commit_fail
echo [OK] 提交成功

if "%DO_PUSH%"=="0" (
  echo [done] committed locally; push skipped by --no-push.
  goto cleanup
)

call :fetch_and_check
if errorlevel 1 goto push_fail

for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
if "%BRANCH%"=="HEAD" (
  echo [ERROR] detached HEAD; cannot push automatically.
  goto fail
)
echo [push] git push -u origin %BRANCH%
git push -u origin "%BRANCH%" || goto push_fail
echo [OK] 已推送到 origin/%BRANCH%

echo.
echo [done] build, commit and push completed.
goto cleanup

rem ================================================================
rem  Subroutines
rem ================================================================

:fetch_and_check
set "AHEAD=0"
set "BEHIND=0"
git fetch origin >nul 2>&1
if errorlevel 1 (
  echo [WARN] git fetch failed; continuing without sync check.
  exit /b 0
)
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
if "%BRANCH%"=="HEAD" (
  echo [ERROR] detached HEAD; cannot sync.
  exit /b 1
)
git rev-parse --verify "origin/%BRANCH%" >nul 2>nul
if errorlevel 1 (
  echo [sync] origin/%BRANCH% does not exist yet ^(new branch^)
  exit /b 0
)
for /f "delims=" %%a in ('git rev-list --count "origin/%BRANCH%..%BRANCH%" 2^>nul') do set "AHEAD=%%a"
for /f "delims=" %%a in ('git rev-list --count "%BRANCH%..origin/%BRANCH%" 2^>nul') do set "BEHIND=%%a"
echo [sync] local ahead %AHEAD%, behind %BEHIND% vs origin/%BRANCH%
if not "%BEHIND%"=="0" (
  echo [pull] remote is ahead by %BEHIND% commit^(s^); rebasing local onto origin/%BRANCH% ...
  set "GIT_EDITOR=true"
  git pull --rebase origin "%BRANCH%"
  if errorlevel 1 (
    echo.
    echo [ERROR] git pull --rebase failed. Resolve conflicts manually:
    echo   git status
    echo   git add ^<resolved-files^>
    echo   git rebase --continue
    exit /b 1
  )
  set "AHEAD=0"
  for /f "delims=" %%a in ('git rev-list --count "origin/%BRANCH%..%BRANCH%" 2^>nul') do set "AHEAD=%%a"
  echo [pull] rebase completed; local now ahead %AHEAD%.
)
exit /b 0

:push_if_ahead
call :fetch_and_check
if errorlevel 1 (
  set "PUSH_FAILED=1"
  goto :eof
)
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
if "%BRANCH%"=="HEAD" (
  set "PUSH_FAILED=1"
  goto :eof
)
git rev-parse --verify "origin/%BRANCH%" >nul 2>nul
if errorlevel 1 (
  git push -u origin "%BRANCH%"
  if errorlevel 1 (
    set "PUSH_FAILED=1"
  )
  goto :eof
)
if "%AHEAD%"=="0" (
  goto :eof
)
git push -u origin "%BRANCH%"
if errorlevel 1 (
  set "PUSH_FAILED=1"
  goto :eof
)
goto :eof

:usage
echo ARTEX build script
echo.
popd
if "%DO_PAUSE%"=="1" pause
endlocal
exit /b 0

:build_fail
echo.
echo [ERROR] build failed.
goto fail

:test_fail
echo.
echo [ERROR] go test failed.
goto fail

:commit_fail
echo.
echo [ERROR] git commit failed.
goto fail

:push_fail
echo.
echo [ERROR] git push/sync failed.
if "%DO_PAUSE%"=="1" pause
popd
endlocal
exit /b 2

:fail
if "%DO_PAUSE%"=="1" pause
popd
endlocal
exit /b 1

:cleanup
if "%DO_PAUSE%"=="1" pause
popd
endlocal
exit /b 0