@echo off
chcp 936 >nul
setlocal EnableExtensions EnableDelayedExpansion

pushd "%~dp0" >nul 2>nul

set "COMMIT_MSG=%~1"
if not defined COMMIT_MSG set "COMMIT_MSG=chore: update data %DATE% %TIME%"

echo ============================================================
echo  鑷姩鍚屾鏈湴鏁版嵁鍒?GitHub 浜戠
echo ============================================================

echo [1/3] 鏆傚瓨鏇存敼...
git add -A

echo [2/3] 鎻愪氦鏇存敼...
git commit -m "!COMMIT_MSG!"
if errorlevel 1 (
    echo [鎻愮ず] 娌℃湁鏂板彉鍔紝璺宠繃鎻愪氦銆?
)

echo [3/3] 鎺ㄩ€佽嚦浜戠...
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"

:: 绗竴娆″皾璇曠洿杩炴帹閫?
git push -u origin "!BRANCH!"
if not errorlevel 1 goto success

echo.
echo [缃戠粶寮傚父] 443绔彛瓒呮椂锛屽皾璇曡嚜鍔ㄥ鎵炬湰鍦颁唬鐞嗙鍙?..
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
echo [褰诲簳澶辫触] 杩炰笉涓?GitHub 鏈嶅姟鍣ㄣ€?
echo 璇锋鏌ヤ綘鐨勪唬鐞嗚蒋浠讹紙Clash/V2ray绛夛級鏄惁宸插紑鍚紝鎴栦娇鐢?Watt Toolkit 鍔犻€熴€?
pause
exit /b 1

:success
echo.
echo [OK] 宸叉垚鍔熸彁浜ゅ苟鎺ㄩ€佸埌浜戠浠撳簱锛?
pause
exit /b 0