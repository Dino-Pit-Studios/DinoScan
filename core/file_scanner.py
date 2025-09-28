"""
File scanner utility for discovering and filtering files for analysis.

This module provides efficient file discovery with support for patterns,
exclusions, and multi-language projects.
"""

import fnmatch
import os
from pathlib import Path
from typing import Any, Iterator


class FileScanner:
    """Scans directories for files matching analysis criteria."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize file scanner with configuration."""
        self.config = config or {}
        self._load_exclusions()

    def _load_exclusions(self) -> None:
        """Load exclusion patterns from configuration."""
        exclusions = self.config.get("exclusions", {})

        self.excluded_dirs = set(
            exclusions.get(
                "directories",
                [
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
            )
        )

        self.excluded_file_patterns = exclusions.get(
            "files",
            [
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
        )

        self.supported_extensions = set(
            exclusions.get(
                "extensions", [".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"]
            )
        )

        # Performance settings
        perf_config = self.config.get("performance", {})
        self.max_file_size_bytes = perf_config.get("max_file_size_mb", 10) * 1024 * 1024

    def should_exclude_directory(self, dir_path: str) -> bool:
        """Check if directory should be excluded from scanning."""
        dir_name = os.path.basename(dir_path)
        return dir_name in self.excluded_dirs

    def should_exclude_file(self, file_path: str) -> bool:
        """Check if file should be excluded from analysis."""
        path = Path(file_path)

        # Check file size
        try:
            if path.stat().st_size > self.max_file_size_bytes:
                return True
        except OSError:
            return True

        # Check extension
        if path.suffix not in self.supported_extensions:
            return True

        # Check excluded file patterns
        file_name = path.name
        for pattern in self.excluded_file_patterns:
            if fnmatch.fnmatch(file_name, pattern):
                return True

        # Check if in excluded directory
        for excluded_dir in self.excluded_dirs:
            if excluded_dir in path.parts:
                return True

        return False

    def scan_directory(self, directory: str) -> Iterator[str]:
        """
        Scan directory for files to analyze.

        Yields absolute file paths that should be analyzed.
        """
        directory_path = Path(directory)

        if not directory_path.exists():
            raise ValueError(f"Directory does not exist: {directory}")

        if not directory_path.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        for root, dirs, files in os.walk(directory):
            # Filter out excluded directories
            dirs[:] = [
                d
                for d in dirs
                if not self.should_exclude_directory(os.path.join(root, d))
            ]

            for file in files:
                file_path = os.path.join(root, file)

                if not self.should_exclude_file(file_path):
                    yield os.path.abspath(file_path)

    def scan_files(self, paths: list[str]) -> Iterator[str]:
        """
        Scan multiple files and directories.

        Args:
            paths: List of file or directory paths

        Yields:
            Absolute file paths that should be analyzed
        """
        for path in paths:
            path_obj = Path(path)

            if path_obj.is_file():
                if not self.should_exclude_file(str(path_obj)):
                    yield str(path_obj.absolute())
            elif path_obj.is_dir():
                yield from self.scan_directory(str(path_obj))
            else:
                print(f"Warning: Path does not exist or is not accessible: {path}")

    def get_file_language(self, file_path: str) -> str | None:
        """
        Determine the programming language of a file based on its extension.

        Returns:
            Language identifier or None if not supported
        """
        extension = Path(file_path).suffix.lower()

        language_map = {
            ".py": "python",
            ".pyi": "python",
            ".pyw": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".vue": "vue",
            ".svelte": "svelte",
        }

        return language_map.get(extension)

    def group_files_by_language(self, file_paths: list[str]) -> dict[str, list[str]]:
        """
        Group files by programming language.

        Returns:
            Dictionary mapping language names to lists of file paths
        """
        groups: dict[str, list[str]] = {}

        for file_path in file_paths:
            language = self.get_file_language(file_path)
            if language:
                if language not in groups:
                    groups[language] = []
                groups[language].append(file_path)

        return groups

    def get_project_info(self, directory: str) -> dict[str, Any]:
        """
        Gather information about a project directory.

        Returns:
            Dictionary containing project metadata
        """
        directory_path = Path(directory)

        if not directory_path.exists():
            raise ValueError(f"Directory does not exist: {directory}")

        # Count files by language
        file_counts = {}
        total_files = 0
        total_size = 0

        for file_path in self.scan_directory(directory):
            language = self.get_file_language(file_path)
            if language:
                file_counts[language] = file_counts.get(language, 0) + 1
                total_files += 1

                try:
                    total_size += Path(file_path).stat().st_size
                except OSError:
                    pass

        # Detect project type markers
        project_files = {
            "python": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
            "javascript": ["package.json", "yarn.lock", "package-lock.json"],
            "typescript": ["tsconfig.json", "typescript.json"],
        }

        detected_types = []
        for project_type, marker_files in project_files.items():
            for marker_file in marker_files:
                if (directory_path / marker_file).exists():
                    detected_types.append(project_type)
                    break

        return {
            "directory": str(directory_path.absolute()),
            "total_files": total_files,
            "total_size_bytes": total_size,
            "file_counts_by_language": file_counts,
            "detected_project_types": detected_types,
            "supported_languages": list(file_counts.keys()),
        }

    def get_statistics(self) -> dict[str, Any]:
        """Get scanner configuration and statistics."""
        return {
            "excluded_directories": list(self.excluded_dirs),
            "excluded_file_patterns": self.excluded_file_patterns,
            "supported_extensions": list(self.supported_extensions),
            "max_file_size_mb": self.max_file_size_bytes // (1024 * 1024),
        }
