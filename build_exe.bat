@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PY=
where py >nul 2>nul && set PY=py
if "%PY%"=="" where python >nul 2>nul && set PY=python
if "%PY%"=="" (
  echo [ERROR] Python not found. Install Python 3.8+ from https://www.python.org/downloads/ ^(check "Add Python to PATH"^)
  pause & exit /b 1
)
%PY% -m pip install -U pyinstaller -i https://pypi.tuna.tsinghua.edu.cn/simple
%PY% -m PyInstaller -F -w --clean --uac-admin --name ChromeTranslateFix gtfix.py
if exist dist\ChromeTranslateFix.exe (
  copy /y dist\ChromeTranslateFix.exe . >nul
  echo.
  echo SUCCESS: ChromeTranslateFix.exe is in this folder.
) else (
  echo.
  echo BUILD FAILED, see messages above.
)
pause
