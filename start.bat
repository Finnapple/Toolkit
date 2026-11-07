@echo off
setlocal
cd /d "%~dp0"
title CTF Crypto Toolkit

rem ---- find Python 3 ----
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY goto :nopython

rem ---- one-time setup: create venv ----
if exist "venv\Scripts\python.exe" goto :run
echo [*] First run: creating virtual environment...
%PY% -m venv venv
if errorlevel 1 goto :venvfail
"venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
if exist requirements.txt "venv\Scripts\python.exe" -m pip install -r requirements.txt --quiet
echo [+] Setup complete.

:run
"venv\Scripts\python.exe" ctf_toolkit.py %*
echo.
pause
exit /b 0

:nopython
echo [x] Python 3 was not found.
echo     Install it from https://www.python.org/downloads/
echo     and tick "Add python.exe to PATH" during install.
pause
exit /b 1

:venvfail
echo [x] Could not create the virtual environment.
echo     Delete the "venv" folder if it exists and try again.
pause
exit /b 1
