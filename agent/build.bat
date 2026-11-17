@echo off
chcp 65001 >nul
setlocal EnableExtensions EnableDelayedExpansion

pushd "%~dp0" >nul 2>nul
if errorlevel 1 (
    echo [Error] Could not enter the script directory.
    exit /b 1
)

set "COMMIT_MSG=%~1"
if not defined COMMIT_MSG set "COMMIT_MSG=chore: update data %DATE% %TIME%"

echo ============================================================
echo  Auto sync local data to GitHub repo
echo ============================================================

echo [1/3] Checking changes...
git add -A
if errorlevel 1 goto failure

echo [2/3] Commit changes...
git diff --cached --quiet
if errorlevel 2 goto failure
if errorlevel 1 (
    git commit -m "!COMMIT_MSG!"
    if errorlevel 1 goto failure
) else (
    echo [Info] No changes to commit, skipping commit.
)

echo [3/3] Sync and push to remote...
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
if /i "!BRANCH!"=="HEAD" (
    echo [Error] Cannot push while in detached HEAD state.
    goto failure
)

git fetch origin
if errorlevel 1 goto failure

echo [Warning] Remote-only commits on "!BRANCH!" will be replaced by the local branch.
git push --force-with-lease -u origin "HEAD:refs/heads/!BRANCH!"
if errorlevel 1 goto failure

:success
echo.
echo [OK] Local branch committed and synced to GitHub.
popd
pause
exit /b 0

:failure
echo.
echo [Error] Sync failed. Check the Git error above, then retry.
popd
pause
exit /b 1