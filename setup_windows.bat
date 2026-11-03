@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================
echo  Aegis SIEM - Windows setup (Python 3.10)
echo ============================================
echo.

REM Select Python 3.10 explicitly. Do not let the launcher choose the newest
REM installed version (this computer may also have Python 3.13 or 3.15).
py -3.10 --version
if errorlevel 1 goto missing_python

echo.
echo Checking selected Python version and architecture...
py -3.10 -c "import sys, struct; print('Executable:', sys.executable); print('Version:', sys.version.split()[0]); print('Architecture:', struct.calcsize('P') * 8, 'bit'); sys.exit(0 if sys.version_info[:2] == (3,10) and struct.calcsize('P') == 8 else 1)"
if errorlevel 1 goto unsupported_python

echo.
echo Removing any previous Aegis virtual environment...
if exist .venv rmdir /s /q .venv
if exist .venv goto error

echo.
echo Creating a clean Python 3.10 virtual environment...
py -3.10 -m venv .venv
if errorlevel 1 goto error

set "AEGIS_PY=%CD%\.venv\Scripts\python.exe"
if not exist "%AEGIS_PY%" goto error

echo.
echo Upgrading pip and packaging tools...
"%AEGIS_PY%" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 goto error

echo.
echo Installing Aegis dependencies using prebuilt packages only...
echo This prevents pip from trying to compile Pandas on your computer.
"%AEGIS_PY%" -m pip install --only-binary=:all: -r requirements.txt
if errorlevel 1 goto install_error

echo.
echo Verifying installed packages...
"%AEGIS_PY%" -c "import pandas, streamlit, plotly, reportlab, openpyxl; print('Pandas:', pandas.__version__); print('Streamlit:', streamlit.__version__); print('All key packages imported successfully.')"
if errorlevel 1 goto error

echo.
echo ============================================
echo Setup complete. Run run_windows.bat to start Aegis SIEM.
echo ============================================
pause
exit /b 0

:missing_python
echo.
echo Python 3.10 was not found by the Python Launcher.
echo In Command Prompt, run: py -0p
 echo Confirm that a 64-bit Python 3.10 installation is listed.
echo Then rerun this file.
pause
exit /b 1

:unsupported_python
echo.
echo The Python 3.10 selected above is not 64-bit CPython 3.10.
echo Aegis needs 64-bit Python 3.10 for the available prebuilt Windows packages.
echo Install Python 3.10.x Windows installer (64-bit) from python.org.
pause
exit /b 1

:install_error
echo.
echo Dependency installation failed. Because binary-only installation is enabled,
echo pip will not try to compile Pandas. Please send a screenshot of the error above.
pause
exit /b 1

:error
echo.
echo Setup failed. Please send a screenshot of the complete error above.
pause
exit /b 1
