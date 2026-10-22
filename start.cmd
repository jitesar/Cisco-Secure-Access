@echo off
cd /d "%~dp0"
python app.py --open-browser %*
if errorlevel 1 pause
