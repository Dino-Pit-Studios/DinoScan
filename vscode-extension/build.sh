#!/bin/bash

# DinoScan VS Code Extension Build Script
# This script builds and packages the extension for distribution

set -e

echo "🦕 Building DinoScan VS Code Extension..."

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found. Please run from the vscode-extension directory."
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf out/
rm -f *.vsix

# Lint the code
echo "🔍 Linting code..."
npm run lint

# Compile TypeScript
echo "🔨 Compiling TypeScript..."
npm run compile

# Check if compilation was successful
if [ ! -d "out" ]; then
    echo "❌ Error: TypeScript compilation failed."
    exit 1
fi

# Package the extension
echo "📦 Packaging extension..."
npm run package

# Find the generated VSIX file
VSIX_FILE=$(find . -name "*.vsix" -type f | head -n 1)

if [ -n "$VSIX_FILE" ]; then
    echo "✅ Extension packaged successfully: $VSIX_FILE"
    echo ""
    echo "📋 Next steps:"
    echo "  1. Test locally: code --install-extension $VSIX_FILE"
    echo "  2. Publish: npm run publish"
    echo "  3. Or upload to VS Code Marketplace manually"
    echo ""
    echo "📊 Package info:"
    ls -lh "$VSIX_FILE"
else
    echo "❌ Error: No VSIX file was generated."
    exit 1
fi

echo "🎉 Build completed successfully!"