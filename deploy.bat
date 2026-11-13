@echo off
setlocal
cd /d "%~dp0cmd\deploy" || exit /b 1
go run . %*
set "DEPLOY_EXIT=%ERRORLEVEL%"
exit /b %DEPLOY_EXIT%
