@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "VENV311_PY=%SCRIPT_DIR%.venv311\Scripts\python.exe"
set "VENV_PY=%SCRIPT_DIR%.venv\Scripts\python.exe"

if exist "%VENV311_PY%" (
  "%VENV311_PY%" "%SCRIPT_DIR%run.py"
  exit /b %ERRORLEVEL%
)

if exist "%VENV_PY%" (
  "%VENV_PY%" "%SCRIPT_DIR%run.py"
  exit /b %ERRORLEVEL%
)

python "%SCRIPT_DIR%run.py"
