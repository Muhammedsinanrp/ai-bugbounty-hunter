@echo off
:: AI-BugBounty-Hunter — Windows System Install
:: Creates 'bugbounty' and 'bugbot' commands available anywhere
:: Run as Administrator for system-wide install

chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set TOOL_DIR=%~dp0
set TOOL_DIR=%TOOL_DIR:~0,-1%

echo.
echo  ================================================
echo  ^|  AI-BugBounty-Hunter -- Windows Installer    ^|
echo  ================================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Download from https://python.org
    pause & exit /b 1
)
echo [+] Python found

:: Create virtual environment
if not exist "%TOOL_DIR%\.venv" (
    echo [*] Creating virtual environment...
    python -m venv "%TOOL_DIR%\.venv"
)
echo [+] Virtual environment ready

:: Install dependencies
echo [*] Installing dependencies...
"%TOOL_DIR%\.venv\Scripts\python.exe" -m pip install -q --upgrade pip
"%TOOL_DIR%\.venv\Scripts\python.exe" -m pip install -q -r "%TOOL_DIR%\requirements.txt"
echo [+] Dependencies installed

:: Create Scripts directory for wrappers
set SCRIPTS_DIR=%TOOL_DIR%\bin
if not exist "%SCRIPTS_DIR%" mkdir "%SCRIPTS_DIR%"

:: ── Create bugbounty.bat ──────────────────────────────────────────
echo @echo off > "%SCRIPTS_DIR%\bugbounty.bat"
echo chcp 65001 ^>nul >> "%SCRIPTS_DIR%\bugbounty.bat"
echo set PYTHONUTF8=1 >> "%SCRIPTS_DIR%\bugbounty.bat"
echo set PYTHONIOENCODING=utf-8 >> "%SCRIPTS_DIR%\bugbounty.bat"
echo "%TOOL_DIR%\.venv\Scripts\python.exe" "%TOOL_DIR%\cli.py" %%* >> "%SCRIPTS_DIR%\bugbounty.bat"
echo [+] Created: bugbounty command

:: ── Create bugbot.bat ─────────────────────────────────────────────
echo @echo off > "%SCRIPTS_DIR%\bugbot.bat"
echo chcp 65001 ^>nul >> "%SCRIPTS_DIR%\bugbot.bat"
echo set PYTHONUTF8=1 >> "%SCRIPTS_DIR%\bugbot.bat"
echo set PYTHONIOENCODING=utf-8 >> "%SCRIPTS_DIR%\bugbot.bat"
echo "%TOOL_DIR%\.venv\Scripts\python.exe" "%TOOL_DIR%\telegram_bot.py" %%* >> "%SCRIPTS_DIR%\bugbot.bat"
echo [+] Created: bugbot command

:: ── Add bin dir to PATH (current user) ───────────────────────────
for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set CURRENT_PATH=%%b
echo %CURRENT_PATH% | find /i "%SCRIPTS_DIR%" >nul
if %errorlevel% neq 0 (
    setx PATH "%SCRIPTS_DIR%;%CURRENT_PATH%" >nul
    echo [+] Added to PATH: %SCRIPTS_DIR%
    echo [!] RESTART your terminal for PATH to take effect
) else (
    echo [+] Already in PATH
)

:: ── Create .env template ──────────────────────────────────────────
if not exist "%TOOL_DIR%\.env" (
    echo TELEGRAM_BOT_TOKEN= > "%TOOL_DIR%\.env"
    echo AI_API_KEY= >> "%TOOL_DIR%\.env"
    echo PYTHONUTF8=1 >> "%TOOL_DIR%\.env"
    echo [+] Created .env template
)

echo.
echo  ================================================
echo  ^|  Installation Complete!                      ^|
echo  ================================================
echo.
echo  COMMANDS (restart terminal first^):
echo.
echo    bugbounty example.com          Full AI scan
echo    bugbounty example.com --quick  Passive recon
echo    bugbounty example.com --help   All options
echo.
echo    bugbot                         Start Telegram bot
echo.
echo  SET API KEY:
echo    set AI_API_KEY=sk-your-key
echo    set TELEGRAM_BOT_TOKEN=your-bot-token
echo.
echo  Or edit: %TOOL_DIR%\bot_config.json
echo.
pause
