@echo off
title WEPO Desktop Wallet
cls

echo.
echo  ██╗    ██╗███████╗██████╗  ██████╗ 
echo  ██║    ██║██╔════╝██╔══██╗██╔═══██╗
echo  ██║ █╗ ██║█████╗  ██████╔╝██║   ██║
echo  ██║███╗██║██╔══╝  ██╔═══╝ ██║   ██║
echo  ╚███╔███╔╝███████╗██║     ╚██████╔╝
echo   ╚══╝╚══╝ ╚══════╝╚═╝      ╚═════╝ 
echo.
echo        Desktop Wallet v1.0.0
echo      Christmas Day 2025 Launch Ready
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed!
    echo Please install Node.js from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

REM Install dependencies if needed
if not exist node_modules (
    echo 📦 Installing dependencies...
    call npm install
    if %errorlevel% neq 0 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Install frontend dependencies if needed
if not exist src\frontend\node_modules (
    echo 📦 Installing frontend dependencies...
    cd src\frontend
    call npm install
    cd ..\..
    if %errorlevel% neq 0 (
        echo ❌ Failed to install frontend dependencies
        pause
        exit /b 1
    )
)

echo.
echo 🚀 Launching WEPO Desktop Wallet...
echo.

REM Start the wallet
call npm start

if %errorlevel% neq 0 (
    echo.
    echo ❌ Failed to start WEPO Desktop Wallet
    echo Please check the error messages above.
    echo.
    pause
)

exit /b %errorlevel%