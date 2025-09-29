# DinoScan VSIX Installation Guide

## 🚀 Installing DinoScan v2.1.0 in Your Local Repositories

### Quick Installation

1. **Locate the VSIX file**: `dinoscan-vscode-2.1.0.vsix` in this directory
2. **Install in VS Code**:
   - Open VS Code
   - Press `Ctrl+Shift+P` (Windows) or `Cmd+Shift+P` (Mac)
   - Type "Extensions: Install from VSIX..."
   - Browse and select `dinoscan-vscode-2.1.0.vsix`
   - Click "Install"

### Alternative Installation Methods

#### Method 1: Command Line

```bash
# Navigate to the directory containing the VSIX file
cd /path/to/DinoScan/vscode-extension

# Install using VS Code CLI
code --install-extension dinoscan-vscode-2.1.0.vsix
```

#### Method 2: Drag & Drop

1. Open VS Code
2. Open the Extensions panel (`Ctrl+Shift+X`)
3. Drag and drop the `dinoscan-vscode-2.1.0.vsix` file into the Extensions panel

### ✨ What's New in v2.1.0

This version includes all the enhanced features we just implemented:

- **Enhanced File Type Support**: 15+ programming languages
- **Centralized Error Handling**: Cleaner, more reliable error management
- **Improved Settings Integration**: VS Code workspace settings properly respected
- **Better Exclusion Patterns**: Ignore lists now work correctly
- **Multi-language Analysis**: Python, JavaScript, TypeScript, and more

### 📁 Copying to Other Repositories

To use the VSIX in other local repositories:

1. **Copy the VSIX file**:

   ```bash
   cp dinoscan-vscode-2.1.0.vsix /path/to/your/other/project/
   ```

2. **Or create a shared location**:

   ```bash
   # Create a shared extensions folder
   mkdir ~/vscode-extensions
   cp dinoscan-vscode-2.1.0.vsix ~/vscode-extensions/

   # Install from shared location in any project
   code --install-extension ~/vscode-extensions/dinoscan-vscode-2.1.0.vsix
   ```

### 🔧 Configuration

After installation, DinoScan will automatically:

1. **Detect Python files** in your workspace
2. **Load settings** from `.dinoscan.json` if present
3. **Respect VS Code workspace settings** under `dinoscan.*`
4. **Apply exclusion patterns** from your configuration

### 📝 Creating Configuration Files

For optimal results, create a `.dinoscan.json` in your project root:

```json
{
  "exclude_patterns": [
    "**/__pycache__/**",
    "**/node_modules/**",
    "**/.git/**",
    "**/venv/**",
    "**/env/**",
    "**/.pytest_cache/**",
    "**/test_*.py",
    "**/*_test.py"
  ],
  "analyzers": {
    "security": { "enabled": true },
    "documentation": { "enabled": true },
    "dead_code": { "enabled": true },
    "circular_import": { "enabled": true },
    "duplicate": { "enabled": true }
  },
  "output": {
    "format": "console",
    "show_context": true,
    "max_findings_per_file": 50
  },
  "performance": {
    "max_file_size_mb": 5,
    "parallel_analysis": true,
    "cache_results": false
  }
}
```

### 🛠️ Troubleshooting

- **Extension not appearing**: Check Extensions panel, may need VS Code restart
- **Analysis not running**: Ensure Python files are detected and configuration is valid
- **Settings not working**: Verify `.dinoscan.json` syntax and file permissions

### 📬 Support

If you encounter issues:

1. Check the VS Code Output panel (DinoScan channel)
2. Verify your configuration files
3. Ensure Python files are in your workspace
4. Restart VS Code if needed

---

**Happy Analyzing! 🦕**
