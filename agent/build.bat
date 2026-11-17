@echo off
chcp 65001 >nul
setlocal EnableExtensions EnableDelayedExpansion

pushd "%~dp0" >nul 2>nul

set "COMMIT_MSG=%~1"
if not defined COMMIT_MSG set "COMMIT_MSG=chore: update data %DATE% %TIME%"

echo ============================================================
echo  Auto sync local data to GitHub repo
echo ============================================================

echo [1/3] Checking changes...
git add -A

echo [2/3] Commit changes...
git commit -m "!COMMIT_MSG!"
if errorlevel 1 (
    echo [Info] No changes to commit, skipping commit.
)

echo [3/3] Push to remote...
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"

git push -u origin "!BRANCH!"
if not errorlevel 1 goto success

echo.
echo [Network error] Port 443 timed out, trying proxies...
git config http.proxy http://127.0.0.1:7890
git config https.proxy http://127.0.0.1:7890
git push -u origin "!BRANCH!"
if not errorlevel 1 goto success

git config http.proxy http://127.0.0.1:10809
git config https.proxy http://127.0.0.1:10809
git push -u origin "!BRANCH!"
if not errorlevel 1 goto success

git config http.proxy http://127.0.0.1:1080
git config https.proxy http://127.0.0.1:1080
git push -u origin "!BRANCH!"
if not errorlevel 1 goto success

echo.
echo [Connection failed] This is not the GitHub server? Check whether your GitHub proxy is enabled or if you are using tools such as Clash/V2Ray.
pause
exit /b 1

:success
echo.
echo [OK] Commit and push succeeded.
pause
exit /b 0