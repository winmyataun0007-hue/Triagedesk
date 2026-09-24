@echo off
REM ===== TriageDesk launcher (Python 3.12, quoted paths) =====
cd /d "%~dp0"

set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PYEXE%" (
  echo [!] Could not find Python 3.12 at "%PYEXE%"
  echo     If you moved it, tell Claude. Otherwise reinstall Python 3.12 from python.org.
  pause
  exit /b 1
)

echo Setting up... (logged to run_log.txt, first run downloads packages ~1-2 min)
> run_log.txt 2>&1 (
  echo === PYTHON VERSION ===
  "%PYEXE%" --version
  echo === PIP INSTALL ===
  "%PYEXE%" -m pip install -r requirements.txt
  echo === IMPORT CHECK ===
  "%PYEXE%" -c "import fastapi, uvicorn, yaml, starlette; print('IMPORTS OK')"
)
type run_log.txt
echo.
echo ============================================================
echo  When you see  "Uvicorn running on http://127.0.0.1:8000"
echo  open Brave and go to:   http://127.0.0.1:8000
echo  (Keep this window open. Ctrl+C to stop.)
echo ============================================================
echo.
"%PYEXE%" -m uvicorn web.app:app --host 127.0.0.1 --port 8000
echo.
echo [server stopped]
pause
