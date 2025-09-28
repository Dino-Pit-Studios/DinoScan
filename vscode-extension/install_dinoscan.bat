@echo off
REM DinoScan VSIX Quick Install Script for Windows
REM Usage: install_dinoscan.bat [optional-path-to-vsix]

setlocal enabledelayedexpansion

REM Default VSIX file
set "VSIX_FILE=dinoscan-vscode-2.1.0.vsix"

REM Use provided path or default
if not "%~1"=="" set "VSIX_FILE=%~1"

echo 🦕 DinoScan VSIX Installer
echo ================================================

REM Check if VSIX file exists
if not exist "%VSIX_FILE%" (
    echo ❌ Error: VSIX file '%VSIX_FILE%' not found
    echo Please ensure the file exists or provide the correct path:
    echo   install_dinoscan.bat "C:\path\to\dinoscan-vscode-2.1.0.vsix"
    exit /b 1
)

echo 📦 Installing DinoScan extension from: %VSIX_FILE%

REM Check if VS Code CLI is available
where code >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo ✅ VS Code CLI found

    REM Install the extension
    echo Installing extension...
    code --install-extension "%VSIX_FILE%"
    if %ERRORLEVEL% EQU 0 (
        echo ✅ DinoScan v2.1.0 successfully installed!
        echo.
        echo 🚀 Next steps:
        echo 1. Restart VS Code if it's currently running
        echo 2. Open a Python project
        echo 3. DinoScan will automatically activate and analyze your code
        echo 4. Create a .dinoscan.json file for custom configuration
        echo.
        echo Happy analyzing! 🦕
    ) else (
        echo ❌ Failed to install extension
        exit /b 1
    )
) else (
    echo ❌ VS Code CLI not found
    echo Please install the extension manually:
    echo 1. Open VS Code
    echo 2. Press Ctrl+Shift+P
    echo 3. Type "Extensions: Install from VSIX..."
    echo 4. Select: %VSIX_FILE%
    exit /b 1
)

endlocal