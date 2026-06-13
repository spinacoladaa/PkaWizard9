@echo off
REM PT9 Answer-Recovery - all-in-one launcher.
REM   No argument: menu.   With arguments: passed straight to the tool, e.g.:
REM   run.bat --file "C:\path\your.pka"     run.bat --folder "C:\folder\with\pka"
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo ERROR: 'python' not found. Install Python 3.10+ ^(64-bit^) from python.org
  echo and tick "Add python.exe to PATH".
  pause & exit /b 1
)

if not "%~1"=="" ( python -m pka_answers %* & echo. & pause & exit /b )

:menu
echo.
echo ===========================================================
echo   PT9 Answer-Recovery
echo ===========================================================
echo   [1] Setup            (one-time: install pymem offline)
echo   [2] Process a .pka or folder
echo   [3] Quit
echo.
set /p c=Choice:
if "%c%"=="1" ( python -m pip install --no-index --find-links vendor pymem & pause & goto menu )
if "%c%"=="2" goto own
if "%c%"=="3" exit /b 0
goto menu

:own
echo.
echo First CLOSE all open Packet Tracer windows (otherwise the launch may "forward").
set /p f=Path to a .pka file or a folder:
if /i "%f:~-4%"==".pka" ( python -m pka_answers --file "%f%" ) else ( python -m pka_answers --folder "%f%" )
pause & goto menu
