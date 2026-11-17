@echo off
chcp 936 >nul
setlocal EnableExtensions EnableDelayedExpansion

pushd "%~dp0" >nul 2>nul

set "COMMIT_MSG=%~1"
if not defined COMMIT_MSG set "COMMIT_MSG=chore: update data %DATE% %TIME%"

echo ============================================================
echo  自动同步本地数据到 GitHub 云端
echo ============================================================

echo [1/3] 暂存更改...
git add -A

echo [2/3] 提交更改...
git commit -m "!COMMIT_MSG!"
if errorlevel 1 (
    echo [提示] 没有新变动，跳过提交。
)

echo [3/3] 推送至云端...
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"

:: 第一次尝试直连推送
git push -u origin "!BRANCH!"
if not errorlevel 1 goto success

echo.
echo [网络异常] 443端口超时，尝试自动寻找本地代理端口...
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
echo [彻底失败] 连不上 GitHub 服务器。
echo 请检查你的代理软件（Clash/V2ray等）是否已开启，或使用 Watt Toolkit 加速。
pause
exit /b 1

:success
echo.
echo [OK] 已成功提交并推送到云端仓库！
pause
exit /b 0