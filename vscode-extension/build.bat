@echo off
REM DinoScan VS Code Extension Build Script for Windows
REM This script builds and packages the extension for distribution

echo 🦕 Building DinoScan VS Code Extension...

REM Check if we're in the right directory
if not exist "package.json" (
    echo ❌ Error: package.json not found. Please run from the vscode-extension directory.
    exit /b 1
)

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    npm install
    if errorlevel 1 (
        echo ❌ Error: npm install failed.
        exit /b 1
    )
)

REM Clean previous builds
echo 🧹 Cleaning previous builds...
if exist "out" rmdir /s /q out
del /q *.vsix 2>nul

REM Lint the code
echo 🔍 Linting code...
npm run lint
if errorlevel 1 (
    echo ⚠️ Warning: Linting found issues, but continuing...
)

REM Compile TypeScript
echo 🔨 Compiling TypeScript...
npm run compile
if errorlevel 1 (
    echo ❌ Error: TypeScript compilation failed.
    exit /b 1
)

REM Check if compilation was successful
if not exist "out" (
    echo ❌ Error: TypeScript compilation failed - no output directory.
    exit /b 1
)

REM Package the extension
echo 📦 Packaging extension...
npm run package
if errorlevel 1 (
    echo ❌ Error: Extension packaging failed.
    exit /b 1
)

REM Find the generated VSIX file
for %%f in (*.vsix) do set VSIX_FILE=%%f

if defined VSIX_FILE (
    echo ✅ Extension packaged successfully: %VSIX_FILE%
    echo.
    echo 📋 Next steps:
    echo   1. Test locally: code --install-extension %VSIX_FILE%
    echo   2. Publish: npm run publish
    echo   3. Or upload to VS Code Marketplace manually
    echo.
    echo 📊 Package info:
    dir "%VSIX_FILE%" | findstr /C:"%VSIX_FILE%"
) else (
    echo ❌ Error: No VSIX file was generated.
    exit /b 1
)

echo 🎉 Build completed successfully!
pause