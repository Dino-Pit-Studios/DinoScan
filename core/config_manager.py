"""
Configuration management for DinoScan analyzers.

This module handles loading, merging, and validating configuration
from multiple sources including files, environment variables, and defaults.
"""

import json
import os
from pathlib import Path
from typing import Any


class ConfigManager:
    """Manages configuration for DinoScan analyzers."""

    def __init__(self, config_path: str | None = None):
        """Initialize configuration manager."""
        self.config_path = config_path
        self._config: dict[str, Any] = {}
        self._load_default_config()
        if config_path:
            self._load_config_file(config_path)
        self._load_environment_overrides()

    def _load_default_config(self) -> None:
        """Load default configuration."""
        self._config = {
            "analyzers": {
                "security": {
                    "enabled": True,
                    "severity_filter": ["Critical", "High", "Medium", "Low"],
                    "rules": {
                        "python-security-eval": {"enabled": True, "severity": "High"},
                        "python-security-os-system": {
                            "enabled": True,
                            "severity": "High",
                        },
                        "python-security-pickle-import": {
                            "enabled": True,
                            "severity": "Medium",
                        },
                        "js-security-eval": {"enabled": True, "severity": "High"},
                    },
                },
                "style": {
                    "enabled": True,
                    "severity_filter": ["High", "Medium"],
                    "rules": {
                        "python-style-function-naming": {
                            "enabled": True,
                            "severity": "Medium",
                        },
                        "python-style-class-naming": {
                            "enabled": True,
                            "severity": "Medium",
                        },
                        "python-style-variable-naming": {
                            "enabled": True,
                            "severity": "Low",
                        },
                        "python-style-constant-naming": {
                            "enabled": True,
                            "severity": "Low",
                        },
                        "js-style-console-log": {"enabled": True, "severity": "Low"},
                        "js-style-var-usage": {"enabled": True, "severity": "Medium"},
                    },
                },
                "complexity": {
                    "enabled": True,
                    "severity_filter": ["High", "Medium"],
                    "max_complexity": 10,
                    "max_nested_depth": 4,
                    "rules": {
                        "python-complexity-cyclomatic": {
                            "enabled": True,
                            "severity": "Medium",
                        },
                        "python-complexity-nesting": {
                            "enabled": True,
                            "severity": "Medium",
                        },
                    },
                },
                "documentation": {
                    "enabled": True,
                    "severity_filter": ["Medium", "Low"],
                    "require_docstrings": False,
                    "max_todo_age_days": 90,
                    "rules": {
                        "python-docstring-missing": {
                            "enabled": True,
                            "severity": "Low",
                        },
                        "python-docstring-format": {"enabled": True, "severity": "Low"},
                    },
                },
                "imports": {
                    "enabled": True,
                    "severity_filter": ["Medium", "Low"],
                    "rules": {
                        "python-imports-unused": {"enabled": True, "severity": "Low"},
                        "python-imports-order": {"enabled": True, "severity": "Low"},
                        "python-imports-star": {"enabled": True, "severity": "Medium"},
                    },
                },
                "duplicates": {
                    "enabled": True,
                    "severity_filter": ["High", "Medium"],
                    "min_similarity": 0.7,
                    "min_cluster_size": 3,
                    "min_block_lines": 5,
                    "rules": {
                        "code-duplicate-exact": {"enabled": True, "severity": "High"},
                        "code-duplicate-similar": {
                            "enabled": True,
                            "severity": "Medium",
                        },
                    },
                },
                "dead_code": {
                    "enabled": True,
                    "severity_filter": ["Medium", "Low"],
                    "include_tests": False,
                    "aggressive_mode": False,
                    "rules": {
                        "dead-code-function": {"enabled": True, "severity": "Medium"},
                        "dead-code-variable": {"enabled": True, "severity": "Low"},
                        "dead-code-import": {"enabled": True, "severity": "Low"},
                    },
                },
            },
            "exclusions": {
                "directories": [
                    "__pycache__",
                    ".git",
                    ".pytest_cache",
                    ".mypy_cache",
                    "venv",
                    "env",
                    ".env",
                    "node_modules",
                    "build",
                    "dist",
                    ".vscode",
                    ".idea",
                    "htmlcov",
                    "coverage",
                    ".tox",
                    ".nox",
                ],
                "files": [
                    "*.pyc",
                    "*.pyo",
                    "*.pyd",
                    "*.so",
                    "*.dll",
                    "*.exe",
                    "*.log",
                    "*.tmp",
                    "*.cache",
                    "*.lock",
                    "*.pid",
                    "*.min.js",
                    "*.min.css",
                    "*.bundle.js",
                    "*.bundle.css",
                ],
                "extensions": [".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"],
            },
            "output": {
                "format": "console",  # console, json, xml, sarif
                "file": None,
                "max_issues_per_file": 50,
                "include_context": True,
                "include_suggestions": True,
            },
            "performance": {
                "max_file_size_mb": 10,
                "enable_caching": True,
                "parallel_analysis": True,
                "max_workers": None,  # None = auto-detect
            },
        }

    def _load_config_file(self, config_path: str) -> None:
        """Load configuration from file."""
        path = Path(config_path)

        if not path.exists():
            print(f"Warning: Config file {config_path} not found, using defaults")
            return

        try:
            if path.suffix.lower() == ".json":
                with path.open(encoding="utf-8") as f:
                    file_config = json.load(f)
            elif path.suffix.lower() in (".yml", ".yaml"):
                try:
                    import yaml

                    with path.open(encoding="utf-8") as f:
                        file_config = yaml.safe_load(f)
                except ImportError:
                    print("Warning: PyYAML not installed, cannot load YAML config")
                    return
            else:
                print(f"Warning: Unsupported config file format: {path.suffix}")
                return

            self._merge_config(file_config)

        except (json.JSONDecodeError, yaml.YAMLError) as e:
            print(f"Warning: Failed to parse config file {config_path}: {e}")
        except Exception as e:
            print(f"Warning: Error loading config file {config_path}: {e}")

    def _load_environment_overrides(self) -> None:
        """Load configuration overrides from environment variables."""
        # Support common environment variable patterns
        env_mappings = {
            "DINOSCAN_MAX_COMPLEXITY": ("analyzers.complexity.max_complexity", int),
            "DINOSCAN_MAX_NESTED_DEPTH": ("analyzers.complexity.max_nested_depth", int),
            "DINOSCAN_MIN_SIMILARITY": ("analyzers.duplicates.min_similarity", float),
            "DINOSCAN_OUTPUT_FORMAT": ("output.format", str),
            "DINOSCAN_MAX_FILE_SIZE": ("performance.max_file_size_mb", int),
            "DINOSCAN_PARALLEL": ("performance.parallel_analysis", bool),
        }

        for env_var, (config_path, converter) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    if converter == bool:
                        converted_value = value.lower() in ("true", "1", "yes", "on")
                    else:
                        converted_value = converter(value)

                    self._set_nested_config(config_path, converted_value)

                except (ValueError, TypeError) as e:
                    print(f"Warning: Invalid value for {env_var}: {value} ({e})")

    def _merge_config(self, new_config: dict[str, Any]) -> None:
        """Merge new configuration with existing configuration."""
        self._config = self._deep_merge(self._config, new_config)

    def _deep_merge(
        self, base: dict[str, Any], update: dict[str, Any]
    ) -> dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()

        for key, value in update.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _set_nested_config(self, path: str, value: Any) -> None:
        """Set a nested configuration value using dot notation."""
        keys = path.split(".")
        current = self._config

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def get(self, path: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        keys = path.split(".")
        current = self._config

        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default

    def get_analyzer_config(self, analyzer_name: str) -> dict[str, Any]:
        """Get configuration for a specific analyzer."""
        return self.get(f"analyzers.{analyzer_name}", {})

    def is_analyzer_enabled(self, analyzer_name: str) -> bool:
        """Check if an analyzer is enabled."""
        return self.get(f"analyzers.{analyzer_name}.enabled", False)

    def get_rule_config(self, analyzer_name: str, rule_id: str) -> dict[str, Any]:
        """Get configuration for a specific rule."""
        return self.get(f"analyzers.{analyzer_name}.rules.{rule_id}", {})

    def is_rule_enabled(self, analyzer_name: str, rule_id: str) -> bool:
        """Check if a specific rule is enabled."""
        return self.get(f"analyzers.{analyzer_name}.rules.{rule_id}.enabled", True)

    def get_exclusions(self) -> dict[str, Any]:
        """Get file and directory exclusions."""
        return self.get("exclusions", {})

    def get_output_config(self) -> dict[str, Any]:
        """Get output configuration."""
        return self.get("output", {})

    def get_performance_config(self) -> dict[str, Any]:
        """Get performance configuration."""
        return self.get("performance", {})

    def validate_config(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []

        # Validate analyzers
        analyzers = self.get("analyzers", {})
        for analyzer_name, analyzer_config in analyzers.items():
            if not isinstance(analyzer_config, dict):
                issues.append(f"Analyzer '{analyzer_name}' config must be a dictionary")
                continue

            # Check severity filters
            severity_filter = analyzer_config.get("severity_filter", [])
            valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
            for severity in severity_filter:
                if severity not in valid_severities:
                    issues.append(f"Invalid severity '{severity}' in {analyzer_name}")

        # Validate output format
        output_format = self.get("output.format", "console")
        valid_formats = {"console", "json", "xml", "sarif"}
        if output_format not in valid_formats:
            issues.append(
                f"Invalid output format '{output_format}'. Must be one of: {valid_formats}"
            )

        # Validate numeric values
        numeric_configs = [
            ("analyzers.complexity.max_complexity", 1, 50),
            ("analyzers.complexity.max_nested_depth", 1, 20),
            ("analyzers.duplicates.min_similarity", 0.0, 1.0),
            ("performance.max_file_size_mb", 1, 1000),
        ]

        for config_path, min_val, max_val in numeric_configs:
            value = self.get(config_path)
            if value is not None and not (min_val <= value <= max_val):
                issues.append(
                    f"Config '{config_path}' must be between {min_val} and {max_val}"
                )

        return issues

    def save_config(self, output_path: str) -> None:
        """Save current configuration to file."""
        path = Path(output_path)

        try:
            if path.suffix.lower() == ".json":
                with path.open("w", encoding="utf-8") as f:
                    json.dump(self._config, f, indent=2, sort_keys=True)
            elif path.suffix.lower() in (".yml", ".yaml"):
                try:
                    import yaml

                    with path.open("w", encoding="utf-8") as f:
                        yaml.dump(
                            self._config, f, default_flow_style=False, sort_keys=True
                        )
                except ImportError:
                    raise ValueError("PyYAML not installed, cannot save YAML config")
            else:
                raise ValueError(f"Unsupported config file format: {path.suffix}")

        except Exception as e:
            print(f"Error saving config to {output_path}: {e}")
            raise

    def to_dict(self) -> dict[str, Any]:
        """Return configuration as dictionary."""
        return self._config.copy()

    def __repr__(self) -> str:
        """Return string representation of configuration."""
        return f"ConfigManager(config_path={self.config_path})"
