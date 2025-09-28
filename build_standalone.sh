#!/bin/bash
# Build script for creating DinoScan standalone executables

echo "Building DinoScan standalone executables..."

# Install PyInstaller if not present
pip install pyinstaller

# Build Windows executable
echo "Building Windows executable..."
pyinstaller dinoscan.spec --clean --onefile

# Build for different platforms (if cross-compilation is set up)
# pyinstaller dinoscan.spec --clean --onefile --target-arch x86_64

echo "Executable built: dist/dinoscan.exe"
echo "Size: $(du -h dist/dinoscan.exe | cut -f1)"

# Create portable package
echo "Creating portable package..."
mkdir -p dist/dinoscan-portable
cp dist/dinoscan.exe dist/dinoscan-portable/
cp config.json dist/dinoscan-portable/
cp README.md dist/dinoscan-portable/
echo "Portable package created in: dist/dinoscan-portable/"

echo "Build complete!"
echo ""
echo "Usage:"
echo "  ./dist/dinoscan.exe security myproject/"
echo "  ./dist/dinoscan.exe all --format json myproject/"