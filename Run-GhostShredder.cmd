@echo off
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if "%~1"=="" (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0GhostShredder.ps1"
) else (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0GhostShredder.ps1" -TargetPath "%~1"
)
endlocal
