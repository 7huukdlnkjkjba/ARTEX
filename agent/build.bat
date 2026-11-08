@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion

rem ============================================================
rem  ARTEX reusable build + GitHub update script
rem  Location: agent\build.bat
rem  Run from anywhere; it switches to the repository root.
rem
rem  Usage:
rem    build.bat [commit message] [options]
rem
rem  Options:
rem    --test          run `go test ./agent` after building
rem    --no-commit     build only; do not stage/commit/push
rem    --no-push       commit locally, do not push
rem    --all           stage every change (including untracked files;
rem                    may include artex.exe / caches, use with care)
rem    --yes           do not ask for confirmation before commit/push
rem    --edit-readme   open README.md in Notepad before staging
rem    --pause         pause at the end (useful for double-click)
rem    --help          show this help
rem
rem  Notes:
rem    - Typed changes are staged: tracked modifications, README.md,
rem      CHANGELOG.md, plus new *.go / *.bat files.
rem    - Untracked binaries, .gocache, .gotmp are NOT staged unless --all.
rem    - A failed push keeps the local commit; re-run `git push -u origin <branch>`.
rem ============================================================

pushd "%~dp0.." >nul 2>nul
if errorlevel 1 (
  echo [ERROR] cannot enter repository root: %~dp0..
  exit /b 1
)
set "REPO=%CD%"

if not exist "%REPO%\go.mod" (
  echo [ERROR] go.mod not found under %REPO%
  popd
  exit /b 1
)

set "COMMIT_MSG="
set "DO_TEST=0"
set "DO_COMMIT=1"
set "DO_PUSH=1"
set "STAGE_ALL=0"
set "ASSUME_YES=0"
set "EDIT_README=0"
set "DO_PAUSE=0"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--help" goto usage
if /I "%~1"=="-h" goto usage
if /I "%~1"=="--test" (
  set "DO_TEST=1"
  shift
  goto parse_args
)
if /I "%~1"=="--no-commit" (
  set "DO_COMMIT=0"
  shift
  goto parse_args
)
if /I "%~1"=="--no-push" (
  set "DO_PUSH=0"
  shift
  goto parse_args
)
if /I "%~1"=="--all" (
  set "STAGE_ALL=1"
  shift
  goto parse_args
)
if /I "%~1"=="--yes" (
  set "ASSUME_YES=1"
  shift
  goto parse_args
)
if /I "%~1"=="--edit-readme" (
  set "EDIT_README=1"
  shift
  goto parse_args
)
if /I "%~1"=="--pause" (
  set "DO_PAUSE=1"
  shift
  goto parse_args
)
if defined COMMIT_MSG (
  set "COMMIT_MSG=%COMMIT_MSG% %~1"
) else (
  set "COMMIT_MSG=%~1"
)
shift
goto parse_args

:args_done
if not defined COMMIT_MSG set "COMMIT_MSG=chore: build %DATE% %TIME%"

rem ---------- preflight ----------
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
git rev-parse --is-inside-work-tree >nul 2>nul
if errorlevel 1 (
  echo [ERROR] %REPO% is not a git work tree
  goto fail
)
git remote get-url origin >nul 2>nul
if errorlevel 1 (
  echo [ERROR] git remote "origin" is not configured
  goto fail
)

rem Keep the Go cache inside the repo when no explicit cache is configured.
rem This avoids permission failures in sandboxed terminals; these dirs are
rem untracked and are never staged by the default path list.
if not defined GOCACHE set "GOCACHE=%REPO%\.gocache"
if not exist "%GOCACHE%" mkdir "%GOCACHE%" >nul 2>nul
if not defined GOTMPDIR set "GOTMPDIR=%REPO%\.gotmp"
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%" >nul 2>nul

echo.
echo ============================================================
echo  ARTEX build / GitHub update
echo  Repo   : %REPO%
echo  Commit : %COMMIT_MSG%
echo ============================================================
echo.

rem ---------- build ----------
echo [1/4] go build ./...
go build ./... || goto build_fail

echo [2/4] go build -o artex.exe ./cmd/artex
go build -o "%REPO%\artex.exe" ./cmd/artex || goto build_fail

if "%DO_TEST%"=="1" (
  echo [test] go test ./agent
  go test ./agent || goto test_fail
)

if "%DO_COMMIT%"=="0" (
  echo.
  echo [done] build only; no commit/push requested.
  goto cleanup
)

rem ---------- optional README edit ----------
if "%EDIT_README%"=="1" (
  if exist "%REPO%\README.md" (
    echo [readme] opening Notepad; save and close it to continue...
    start "" /wait notepad "%REPO%\README.md"
  ) else (
    echo [warn] README.md not found; skipping edit
  )
)

rem ---------- stage ----------
echo [3/4] staging changes
git add -u
if exist "%REPO%\README.md" git add -- "%REPO%\README.md"
if exist "%REPO%\CHANGELOG.md" git add -- "%REPO%\CHANGELOG.md"
git add -- "*.go" "*.bat" 2>nul
if "%STAGE_ALL%"=="1" (
  echo [warn] --all: staging every untracked file, including binaries/caches
  git add -A
)

git status --short
git diff --cached --quiet
if not errorlevel 1 (
  echo [info] no staged changes; nothing to commit.
  goto cleanup
)

if "%ASSUME_YES%"=="1" goto do_commit
choice /C YN /M "Commit and push these changes"
if errorlevel 2 goto abort
if errorlevel 255 goto abort

:do_commit
echo [4/4] git commit
git commit -m "%COMMIT_MSG%" || goto commit_fail

if "%DO_PUSH%"=="0" (
  echo [done] committed locally; push skipped by --no-push.
  goto cleanup
)

for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
if "%BRANCH%"=="HEAD" (
  echo [ERROR] detached HEAD; cannot push automatically.
  goto fail
)
echo [push] git push -u origin %BRANCH%
git push -u origin "%BRANCH%" || goto push_fail

echo.
echo [done] build, commit and push completed.
goto cleanup

:usage
echo ARTEX reusable build + GitHub update script
echo.
echo Usage: build.bat [commit message] [options]
echo.
echo Options:
echo   --test          run go test ./agent after building
echo   --no-commit     build only; do not stage/commit/push
echo   --no-push       commit locally, do not push
echo   --all           stage every change (including untracked files)
echo   --yes           do not ask for confirmation before commit/push
echo   --edit-readme   open README.md in Notepad before staging
echo   --pause         pause at the end
echo   --help          show this help
echo.
echo Default commit message: chore: build %%DATE%% %%TIME%%
echo Default staged set: tracked modifications + README.md + CHANGELOG.md
echo                     + new *.go / *.bat files.
popd
endlocal
exit /b 0

:abort
echo [info] aborted by user.
goto cleanup

:build_fail
echo.
echo [ERROR] build failed.
goto fail

:test_fail
echo.
echo [ERROR] go test ./agent failed.
goto fail

:commit_fail
echo.
echo [ERROR] git commit failed.
goto fail

:push_fail
echo.
echo [ERROR] git push failed. The local commit is kept.
echo         Check network/credentials, then run:
echo           git push -u origin %BRANCH%
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
