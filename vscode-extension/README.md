# DinoScan VS Code Extension

This is the VS Code extension for DinoScan - providing comprehensive AST-based Python code analysis directly in your editor.

## Features

### 🔍 **Real-time Analysis**
- Automatic analysis on file save
- Live diagnostics integrated with VS Code Problems panel
- Support for all DinoScan analyzers (security, circular imports, dead code, documentation, duplicates)

### 🎯 **Smart Integration**
- Context menu integration for Python files
- Status bar showing analysis progress and findings count
- Command palette integration for all DinoScan commands

### 📊 **Rich Reporting**
- Interactive HTML reports with detailed findings
- Export to JSON, SARIF formats
- Integrated output channel for detailed logs

### ⚙️ **Configurable Analysis**
- Three analysis profiles: strict, standard, relaxed
- Enable/disable specific analyzers
- Exclude patterns for files and directories
- Performance settings for large codebases

## Commands

| Command | Description |
|---------|-------------|
| `DinoScan: Analyze Current File` | Analyze the currently open Python file |
| `DinoScan: Analyze Workspace` | Analyze all Python files in workspace |
| `DinoScan: Show Analysis Report` | Display detailed HTML report |
| `DinoScan: Clear All Diagnostics` | Clear all DinoScan findings |
| `DinoScan: Toggle Auto Analysis` | Enable/disable automatic analysis on save |

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `dinoscan.analysisProfile` | Analysis strictness (strict/standard/relaxed) | `standard` |
| `dinoscan.enabledAnalyzers` | Which analyzers to run | All enabled |
| `dinoscan.excludePatterns` | File patterns to exclude | `tests/`, `venv/`, `__pycache__/` |
| `dinoscan.autoAnalysis` | Auto-analyze on save | `true` |
| `dinoscan.showStatusBar` | Show status in status bar | `true` |
| `dinoscan.maxFileSize` | Maximum file size to analyze (bytes) | `1048576` (1MB) |
| `dinoscan.outputFormat` | Default output format | `console` |

## Installation Requirements

This extension requires DinoScan to be installed:

```bash
pip install dinoscan
```

Or use the standalone executable version.

## Usage

1. **Install DinoScan**: `pip install dinoscan`
2. **Open a Python file**: The extension activates automatically
3. **Right-click in editor**: Select "DinoScan: Analyze Current File"
4. **View results**: Check the Problems panel for findings
5. **Generate report**: Use "DinoScan: Show Analysis Report" for detailed view

## Building from Source

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Package extension
npm run package

# Install locally
code --install-extension dinoscan-vscode-2.0.0.vsix
```

## Development

```bash
# Watch mode for development
npm run watch

# Run tests
npm test

# Lint code
npm run lint
```

## Support

- **Documentation**: [DinoScan GitHub](https://github.com/DinoAir/DinoScan)
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Join the community discussions

## License

MIT License - see LICENSE file for details.