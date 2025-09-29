#!/bin/bash
# DinoScan VSIX Quick Install Script
# Usage: ./install_dinoscan.sh [optional-path-to-vsix]

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default VSIX file
VSIX_FILE="dinoscan-vscode-2.1.0.vsix"

# Use provided path or default
if [ $# -eq 1 ]; then
    VSIX_FILE="$1"
fi

echo -e "${BLUE}🦕 DinoScan VSIX Installer${NC}"
echo "================================================"

# Check if VSIX file exists
if [ ! -f "$VSIX_FILE" ]; then
    echo -e "${RED}❌ Error: VSIX file '$VSIX_FILE' not found${NC}"
    echo "Please ensure the file exists or provide the correct path:"
    echo "  ./install_dinoscan.sh /path/to/dinoscan-vscode-2.1.0.vsix"
    exit 1
fi

echo -e "${BLUE}📦 Installing DinoScan extension from: $VSIX_FILE${NC}"

# Check if VS Code CLI is available
if command -v code &> /dev/null; then
    echo -e "${GREEN}✅ VS Code CLI found${NC}"

    # Install the extension
    echo "Installing extension..."
    if code --install-extension "$VSIX_FILE"; then
        echo -e "${GREEN}✅ DinoScan v2.1.0 successfully installed!${NC}"
        echo ""
        echo -e "${BLUE}🚀 Next steps:${NC}"
        echo "1. Restart VS Code if it's currently running"
        echo "2. Open a Python project"
        echo "3. DinoScan will automatically activate and analyze your code"
        echo "4. Create a .dinoscan.json file for custom configuration"
        echo ""
        echo -e "${GREEN}Happy analyzing! 🦕${NC}"
    else
        echo -e "${RED}❌ Failed to install extension${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ VS Code CLI not found${NC}"
    echo "Please install the extension manually:"
    echo "1. Open VS Code"
    echo "2. Press Ctrl+Shift+P (Windows) or Cmd+Shift+P (Mac)"
    echo "3. Type 'Extensions: Install from VSIX...'"
    echo "4. Select: $VSIX_FILE"
    exit 1
fi