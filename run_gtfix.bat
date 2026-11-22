@echo off
cd /d "%~dp0"
where pythonw >nul 2>nul && (start "" pythonw gtfix.py) || (where py >nul 2>nul && (py gtfix.py) || (python gtfix.py))
