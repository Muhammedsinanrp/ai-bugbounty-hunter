@echo off
:: AI-BugBounty-Hunter — Setup Script (Windows)
:: Usage: setup.bat

echo.
echo   ===============================================
echo   ^|   AI-BugBounty-Hunter -- Setup v1.0        ^|
echo   ^|   AI-Powered Bug Bounty Automation          ^|
echo   ===============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Install from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [*] Python version: %PY_VER%

:: Create virtual environment
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    echo [+] Virtual environment created
)

:: Activate venv
call .venv\Scripts\activate.bat

:: Install dependencies
echo [*] Installing Python dependencies...
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt -q
echo [+] Dependencies installed

:: Create directories
echo [*] Creating directories...
if not exist "reports\output" mkdir reports\output
if not exist "reports\templates" mkdir reports\templates
if not exist "logs" mkdir logs
if not exist "findings_db" mkdir findings_db
if not exist "wordlists" mkdir wordlists
echo [+] Directories created

:: Check config
if exist "config.json" (
    echo [+] config.json found
) else (
    echo [!] config.json not found - will use defaults
)

echo.
echo   ===============================================
echo   ^|   Setup Complete!                          ^|
echo   ===============================================
echo.
echo Quick Start:
echo   python cli.py example.com                   ^(Full pipeline^)
echo   python cli.py example.com --quick           ^(Passive recon only^)
echo   python cli.py example.com --recon-only      ^(Recon only^)
echo   python cli.py example.com --ai-provider openai
echo.
echo Set AI API key:
echo   set AI_API_KEY=your-key-here
echo.
echo For free local AI with Ollama:
echo   Download Ollama from https://ollama.com
echo   ollama pull llama3
echo.
pause
