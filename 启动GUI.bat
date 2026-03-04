@echo off
echo ==========================================
echo   Network Traffic Analyzer - C Version GUI
echo ==========================================
echo.

python c_analyzer_gui.py

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start GUI!
    echo Please make sure Python and tkinter are installed.
    echo.
    pause
)
