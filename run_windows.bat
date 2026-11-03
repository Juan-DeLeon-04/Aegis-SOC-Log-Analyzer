@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo Virtual environment not found. Run setup_windows.bat first.
    pause
    exit /b 1
)
"%CD%\.venv\Scripts\python.exe" -m streamlit run app.py
if errorlevel 1 (
    echo.
    echo Aegis stopped with an error. Take a screenshot of this window.
    pause
    exit /b 1
)
