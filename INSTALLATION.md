# DinoScan Installation & Usage Guide

## 📦 Installation Options

### Option 1: PyPI Package (Recommended)
```bash
# Install from PyPI
pip install dinoscan

# Verify installation
dinoscan --help

# Quick usage
dinoscan security myproject/
dinoscan all --format json --output report.json myproject/
```

### Option 2: Standalone Executable
```bash
# Download from releases page
wget https://github.com/DinoAir/DinoScan/releases/latest/download/dinoscan.exe

# Make executable (Linux/macOS)
chmod +x dinoscan

# Run directly
./dinoscan security myproject/
```

### Option 3: Docker Container
```bash
# Pull the image
docker pull dinoair/dinoscan:latest

# Run analysis on current directory
docker run --rm -v $(pwd):/workspace dinoair/dinoscan:latest security /workspace

# Generate JSON report
docker run --rm -v $(pwd):/workspace dinoair/dinoscan:latest \
  all --format json --output /workspace/report.json /workspace
```

### Option 4: Development Installation
```bash
# Clone repository
git clone https://github.com/DinoAir/DinoScan.git
cd DinoScan

# Install with Poetry
poetry install

# Run directly
poetry run python dinoscan_cli.py security myproject/
```

## 🚀 Quick Start Examples

### Basic Analysis
```bash
# Security analysis only
dinoscan security myproject/

# All analyzers
dinoscan all myproject/

# Specific analyzer with JSON output
dinoscan dead-code --format json --output dead_code_report.json myproject/
```

### Advanced Usage
```bash
# Strict analysis profile
dinoscan all --profile strict myproject/

# Exclude test directories  
dinoscan security --exclude "tests/" --exclude "venv/" myproject/

# Custom configuration file
dinoscan all --config custom_config.json myproject/

# Verbose output for debugging
dinoscan security --verbose myproject/
```

## 🔧 CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/dinoscan.yml
name: Code Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dinoair/dinoscan-action@v2
        with:
          path: '.'
          analyzers: 'all'
          format: 'sarif'
          fail-on: 'high'
```

### Pre-commit Integration
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/DinoAir/DinoScan
    rev: v2.0.0
    hooks:
      - id: dinoscan-security
      - id: dinoscan-all
```

## 🎯 Analyzer Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `strict` | Maximum scrutiny, all rules enabled | Production/critical code |
| `standard` | Balanced analysis (default) | General development |  
| `relaxed` | Fewer false positives | Legacy/experimental code |

## 📊 Output Formats

| Format | Description | Best For |
|--------|-------------|----------|
| `console` | Human-readable terminal output | Development |
| `json` | Structured JSON data | Automation/scripting |
| `xml` | XML format | Legacy tooling |
| `sarif` | SARIF 2.1 standard | CI/CD/IDEs |

## 🔍 Available Analyzers

- **security**: Vulnerability detection, secret scanning, injection analysis
- **circular**: Circular import detection using advanced graph algorithms  
- **dead-code**: Unused code identification with framework awareness
- **docs**: Documentation quality analysis (multiple formats)
- **duplicates**: Code duplication detection using winnowing algorithm
- **all**: Runs all analyzers

## ⚡ Performance Tips

- Use `--exclude` patterns for large codebases
- Enable specific analyzers instead of `all` for faster runs
- Use `--profile relaxed` for initial analysis of large legacy projects
- Consider Docker for consistent environments across teams

## 🛠️ Troubleshooting

### Import Errors
```bash
# Ensure proper installation
pip install --upgrade dinoscan

# For development
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Memory Issues (Large Codebases)
```bash
# Analyze in smaller chunks
dinoscan security src/module1/
dinoscan security src/module2/

# Use Docker with memory limits
docker run --memory=2g dinoair/dinoscan:latest security /workspace
```