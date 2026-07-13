@echo off
cd /d "%~dp0"
echo Starting Threat Intelligence Analyst...
echo Press Ctrl+C to stop the server.
echo.
"%~dp0python\python.exe" -m streamlit run "%~dp0src\app.py"
pause
