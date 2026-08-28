@echo off
:: AI-BugBounty-Hunter — Telegram Bot Launcher (Windows)
echo.
echo  ===============================================
echo  ^|   AI-BugBounty-Hunter Telegram Bot          ^|
echo  ===============================================
echo.

:: Check for token
if "%TELEGRAM_BOT_TOKEN%"=="" (
    if not exist "bot_config.json" (
        echo [!] No bot token found!
        echo.
        echo  Option 1: Set environment variable
        echo    set TELEGRAM_BOT_TOKEN=1234567890:ABCdef...
        echo.
        echo  Option 2: Edit bot_config.json
        echo    "telegram_token": "1234567890:ABCdef..."
        echo.
        pause
        exit /b 1
    )
)

python telegram_bot.py
pause
