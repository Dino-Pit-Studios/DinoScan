#!/usr/bin/env python3
"""
Enhanced settings management with proper integration.
"""

from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import os
import fnmatch


class SettingsManager:
    """Manages DinoScan settings with proper integration."""

    def __init__(self, workspace_path: Optional[str] = None):
        """Initialize settings manager with workspace path."""
        self.workspace_path = workspace_path
        self.settings = self._load_settings()

    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from multiple sources in priority order."""
        settings = self._get_default_settings()

        # 1. Load from workspace .dinoscan.json
        if self.workspace_path:
            workspace_config = Path(self.workspace_path) / ".dinoscan.json"
            if workspace_config.exists():
                workspace_settings = self._load_json_config(str(workspace_config))
                settings.update(workspace_settings)

        # 2. Load from VS Code settings (if available)
        vscode_settings = self._load_vscode_settings()
        if vscode_settings:
            settings.update(vscode_settings)

        # 3. Load from environment variables
        env_settings = self._load_env_settings()
        settings.update(env_settings)

        return settings

    def _get_default_settings(self) -> Dict[str, Any]:
        """Get default settings."""
        return {
            "excludePatterns": [
                "__pycache__/**",
                ".git/**",
                "node_modules/**",
                "venv/**",
                "env/**",
                ".env/**",
                "build/**",
                "dist/**",
                ".pytest_cache/**",
                ".mypy_cache/**",
                "**/*.pyc",
                "**/*.pyo",
                "**/*.pyd",
                "**/*.log",
                "**/*.tmp",
                "**/*.backup",
                ".tox/**",
                ".coverage",
                "htmlcov/**",
            ],
            "maxFileSize": 1048576,  # 1MB
            "enabledAnalyzers": {
                "security": True,
                "deadCode": True,
                "documentation": True,
                "duplicateCode": True,
                "circularImports": True,
            },
            "analysisProfile": "standard",
            "outputFormat": "json",
            "showStatusBar": True,
            "autoAnalysis": True,
            "recursiveAnalysis": True,
            "followSymlinks": False,
            "ignoreHiddenFiles": True,
        }

    def _load_vscode_settings(self) -> Dict[str, Any]:
        """Load VS Code specific settings."""
        if self.workspace_path:
            vscode_settings_file = (
                Path(self.workspace_path) / ".vscode" / "settings.json"
            )
            if vscode_settings_file.exists():
                try:
                    with open(vscode_settings_file, "r", encoding="utf-8") as f:
                        vscode_data = json.load(f)
                        # Extract dinoscan settings
                        dinoscan_settings = {}
                        for key, value in vscode_data.items():
                            if key.startswith("dinoscan."):
                                setting_key = key.replace("dinoscan.", "")
                                # Convert camelCase to snake_case for internal consistency
                                setting_key = self._camel_to_snake(setting_key)
                                dinoscan_settings[setting_key] = value
                        return dinoscan_settings
                except (json.JSONDecodeError, OSError):
                    pass
        return {}

    def _camel_to_snake(self, name: str) -> str:
        """Convert camelCase to snake_case."""
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append("_")
            result.append(char.lower())
        return "".join(result)

    def _load_env_settings(self) -> Dict[str, Any]:
        """Load settings from environment variables."""
        env_settings = {}

        # Map environment variables to settings
        env_mapping = {
            "DINOSCAN_MAX_FILE_SIZE": ("maxFileSize", int),
            "DINOSCAN_AUTO_ANALYSIS": ("autoAnalysis", lambda x: x.lower() == "true"),
            "DINOSCAN_PROFILE": ("analysisProfile", str),
            "DINOSCAN_OUTPUT_FORMAT": ("outputFormat", str),
            "DINOSCAN_RECURSIVE": ("recursiveAnalysis", lambda x: x.lower() == "true"),
            "DINOSCAN_FOLLOW_SYMLINKS": (
                "followSymlinks",
                lambda x: x.lower() == "true",
            ),
            "DINOSCAN_IGNORE_HIDDEN": (
                "ignoreHiddenFiles",
                lambda x: x.lower() == "true",
            ),
        }

        for env_var, (setting_key, converter) in env_mapping.items():
            if env_var in os.environ:
                try:
                    env_settings[setting_key] = converter(os.environ[env_var])
                except (ValueError, TypeError):
                    pass  # Ignore invalid environment values

        # Handle exclude patterns from environment
        if "DINOSCAN_EXCLUDE_PATTERNS" in os.environ:
            patterns = os.environ["DINOSCAN_EXCLUDE_PATTERNS"].split(",")
            env_settings["excludePatterns"] = [p.strip() for p in patterns if p.strip()]

        return env_settings

    def _load_json_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def should_exclude_file(self, file_path: str) -> bool:
        """Check if file should be excluded based on patterns."""
        path = Path(file_path)

        # Check if file is hidden and should be ignored
        if self.settings.get("ignoreHiddenFiles", True) and path.name.startswith("."):
            return True

        # Check file size
        try:
            if path.stat().st_size > self.settings["maxFileSize"]:
                return True
        except OSError:
            return True

        # Check exclude patterns
        for pattern in self.settings["excludePatterns"]:
            if self._matches_pattern(str(path), pattern):
                return True

        return False

    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches exclude pattern."""
        path = Path(file_path)

        # Direct pattern match
        if fnmatch.fnmatch(str(path), pattern):
            return True

        # Filename only match
        if fnmatch.fnmatch(path.name, pattern):
            return True

        # Check parent directories for directory patterns
        if pattern.endswith("/**"):
            dir_pattern = pattern[:-3]  # Remove /**
            for parent in path.parents:
                if fnmatch.fnmatch(parent.name, dir_pattern):
                    return True
                if fnmatch.fnmatch(str(parent), dir_pattern):
                    return True

        # Relative path matching
        try:
            if self.workspace_path:
                relative_path = path.relative_to(Path(self.workspace_path))
                if fnmatch.fnmatch(str(relative_path), pattern):
                    return True
        except ValueError:
            pass  # Path is not relative to workspace

        return False

    def is_analyzer_enabled(self, analyzer_name: str) -> bool:
        """Check if an analyzer is enabled."""
        enabled_analyzers = self.settings.get("enabledAnalyzers", {})

        # Try exact match first
        if analyzer_name in enabled_analyzers:
            return enabled_analyzers[analyzer_name]

        # Try common variations
        variations = [
            analyzer_name.lower(),
            analyzer_name.replace("_", ""),
            analyzer_name.replace("analyzer", "").replace("_", ""),
            analyzer_name.replace("Analyzer", ""),
        ]

        for variation in variations:
            if variation in enabled_analyzers:
                return enabled_analyzers[variation]

        # Default to True if not specified
        return True

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a specific setting value."""
        return self.settings.get(key, default)

    def update_setting(self, key: str, value: Any) -> None:
        """Update a setting value."""
        self.settings[key] = value

    def get_analysis_profile(self) -> str:
        """Get the current analysis profile."""
        return self.settings.get("analysisProfile", "standard")

    def is_recursive_analysis_enabled(self) -> bool:
        """Check if recursive directory analysis is enabled."""
        return self.settings.get("recursiveAnalysis", True)

    def should_follow_symlinks(self) -> bool:
        """Check if symbolic links should be followed."""
        return self.settings.get("followSymlinks", False)

    def get_max_file_size(self) -> int:
        """Get maximum file size for analysis."""
        return self.settings.get("maxFileSize", 1048576)

    def get_exclude_patterns(self) -> List[str]:
        """Get list of exclude patterns."""
        return self.settings.get("excludePatterns", [])

    def add_exclude_pattern(self, pattern: str) -> None:
        """Add a new exclude pattern."""
        patterns = self.get_exclude_patterns()
        if pattern not in patterns:
            patterns.append(pattern)
            self.settings["excludePatterns"] = patterns

    def remove_exclude_pattern(self, pattern: str) -> None:
        """Remove an exclude pattern."""
        patterns = self.get_exclude_patterns()
        if pattern in patterns:
            patterns.remove(pattern)
            self.settings["excludePatterns"] = patterns

    def save_workspace_config(self) -> bool:
        """Save current settings to workspace configuration."""
        if not self.workspace_path:
            return False

        config_path = Path(self.workspace_path) / ".dinoscan.json"
        try:
            # Only save non-default settings
            default_settings = self._get_default_settings()
            config_to_save = {}

            for key, value in self.settings.items():
                if key not in default_settings or default_settings[key] != value:
                    config_to_save[key] = value

            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config_to_save, f, indent=2, sort_keys=True)
            return True
        except OSError:
            return False

    def reset_to_defaults(self) -> None:
        """Reset all settings to default values."""
        self.settings = self._get_default_settings()

    def get_all_settings(self) -> Dict[str, Any]:
        """Get a copy of all current settings."""
        return self.settings.copy()
