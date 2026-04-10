@echo off
REM pkgfence scheduled scan — runs daily via Windows Task Scheduler
REM Scans all registered targets, then fires notification if new findings appear.
REM
REM Usage: scheduled-scan.bat [webhook-url]
REM   webhook-url: optional n8n webhook URL for notifications
REM
REM Exit codes match pkgfence: 0=clean, 1=findings, 2=scanner error, 3=config error

setlocal enabledelayedexpansion

set "PKGFENCE_DIR=D:\projects\pkgfence"
set "PYTHON=%PKGFENCE_DIR%\.venv\Scripts\python.exe"
set "WEBHOOK_URL=%~1"
set "LOG_DIR=%PKGFENCE_DIR%\state\logs"

REM Ensure log directory exists
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Timestamp for log file
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do set "DATESTAMP=%%c%%a%%b"
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set "TIMESTAMP=%%a%%b"
set "LOGFILE=%LOG_DIR%\scan-%DATESTAMP%-%TIMESTAMP%.log"

echo [%date% %time%] pkgfence scheduled scan starting >> "%LOGFILE%" 2>&1

REM Run scan
"%PYTHON%" -m scripts.scan_command --registry "%PKGFENCE_DIR%\state\registry.yaml" --state "%PKGFENCE_DIR%\state" >> "%LOGFILE%" 2>&1
set "SCAN_EXIT=%ERRORLEVEL%"
echo [%date% %time%] scan exit code: %SCAN_EXIT% >> "%LOGFILE%" 2>&1

REM Run notify (always — even if scan found nothing, notify reports the delta)
if defined WEBHOOK_URL (
    "%PYTHON%" -m scripts.notify --state "%PKGFENCE_DIR%\state" --webhook "%WEBHOOK_URL%" >> "%LOGFILE%" 2>&1
) else (
    "%PYTHON%" -m scripts.notify --state "%PKGFENCE_DIR%\state" >> "%LOGFILE%" 2>&1
)
set "NOTIFY_EXIT=%ERRORLEVEL%"
echo [%date% %time%] notify exit code: %NOTIFY_EXIT% >> "%LOGFILE%" 2>&1

echo [%date% %time%] scheduled scan complete >> "%LOGFILE%" 2>&1
exit /b %SCAN_EXIT%
