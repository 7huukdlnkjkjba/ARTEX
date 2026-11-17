@echo off
chcp 936 >nul
setlocal EnableExtensions EnableDelayedExpansion

if exist "%~dp0.git" (
  pushd "%~dp0" >nul 2>nul
) else (
  pushd "%~dp0.." >nul 2>nul
)

set "COMMIT_MSG="
if not "%~1"=="" set "COMMIT_MSG=%~1"
if not defined COMMIT_MSG set "COMMIT_MSG=chore: update %DATE% %TIME%"

echo ============================================================
echo  自动提交并推送本地数据到 GitHub
echo  目录: %CD%
echo  提交信息: !COMMIT_MSG!
echo ============================================================

echo [1/3] 添加所有更改...
git add -A

echo [2/3] 提交更改...
git commit -m "!COMMIT_MSG!"
if errorlevel 1 (
  echo [提示] 没有需要提交的新更改，或者提交失败。
)

echo [3/3] 推送到云端...
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "BRANCH=%%b"
git push -u origin "!BRANCH!"

if errorlevel 1 (
  echo.
  echo [错误] 推送失败，请检查网络或远程仓库权限。
) else (
  echo.
  echo [成功] 本地数据已成功提交并推送到云端仓库。
)

echo.
pause
endlocal
exit /b 0