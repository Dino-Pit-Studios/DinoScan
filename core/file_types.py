#!/usr/bin/env python3
"""
Enhanced file type detection and language mapping.
"""

from pathlib import Path
from typing import Dict, Set, Optional, List
import mimetypes


class FileTypeManager:
    """Manages file type detection and language mapping."""

    def __init__(self):
        """Initialize file type manager with language mappings."""
        self.language_extensions: Dict[str, Set[str]] = {
            "python": {".py", ".pyi", ".pyw"},
            "javascript": {".js", ".jsx", ".mjs", ".cjs"},
            "typescript": {".ts", ".tsx", ".d.ts"},
            "vue": {".vue"},
            "svelte": {".svelte"},
            "php": {".php", ".php3", ".php4", ".php5", ".phtml"},
            "java": {".java", ".jar"},
            "csharp": {".cs"},
            "cpp": {".cpp", ".cxx", ".cc", ".c++", ".hpp", ".hxx", ".h++"},
            "c": {".c", ".h"},
            "go": {".go"},
            "rust": {".rs"},
            "ruby": {".rb", ".rake", ".gemspec"},
            "shell": {".sh", ".bash", ".zsh", ".fish"},
            "powershell": {".ps1", ".psm1", ".psd1"},
            "yaml": {".yml", ".yaml"},
            "json": {".json", ".jsonc"},
            "xml": {".xml", ".xsd", ".xsl", ".xslt"},
            "html": {".html", ".htm", ".xhtml"},
            "css": {".css", ".scss", ".sass", ".less"},
            "sql": {".sql", ".mysql", ".pgsql"},
            "dockerfile": {"Dockerfile", ".dockerfile"},
            "markdown": {".md", ".markdown", ".mdown"},
            "config": {".ini", ".cfg", ".conf", ".toml", ".env"},
        }

        self.security_sensitive_extensions = {
            ".env",
            ".key",
            ".pem",
            ".p12",
            ".pfx",
            ".jks",
            ".keystore",
            ".config",
            ".ini",
            ".conf",
            ".properties",
            ".secrets",
        }

        self.binary_extensions = {
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".bin",
            ".class",
            ".jar",
            ".zip",
            ".tar",
            ".gz",
            ".rar",
            ".7z",
            ".iso",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".ico",
            ".svg",
            ".mp3",
            ".wav",
            ".mp4",
            ".avi",
            ".mov",
            ".mkv",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
        }

        # Initialize mime types
        mimetypes.init()

    def get_language(self, file_path: str) -> Optional[str]:
        """Get language for a file path."""
        path = Path(file_path)
        extension = path.suffix.lower()
        filename = path.name.lower()

        # Check exact filename matches first (for files like Dockerfile)
        for lang, exts in self.language_extensions.items():
            if filename in exts or extension in exts:
                return lang

        return None

    def is_text_file(self, file_path: str) -> bool:
        """Check if file is likely a text file."""
        path = Path(file_path)

        # Quick check for binary extensions
        if path.suffix.lower() in self.binary_extensions:
            return False

        # Check mime type
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            return mime_type.startswith("text/") or mime_type in [
                "application/json",
                "application/xml",
                "application/javascript",
                "application/x-yaml",
                "application/yaml",
            ]

        # Fallback to extension check
        return any(
            path.suffix.lower() in exts for exts in self.language_extensions.values()
        )

    def is_binary_file(self, file_path: str) -> bool:
        """Check if file is likely binary."""
        return not self.is_text_file(file_path)

    def is_security_sensitive(self, file_path: str) -> bool:
        """Check if file contains potentially sensitive data."""
        path = Path(file_path)
        return path.suffix.lower() in self.security_sensitive_extensions or any(
            keyword in path.name.lower()
            for keyword in ["secret", "password", "key", "token"]
        )

    def get_supported_extensions(self) -> Set[str]:
        """Get all supported file extensions."""
        extensions = set()
        for exts in self.language_extensions.values():
            extensions.update(exts)
        return extensions

    def get_extensions_for_language(self, language: str) -> Set[str]:
        """Get file extensions for a specific language."""
        return self.language_extensions.get(language, set())

    def get_supported_languages(self) -> List[str]:
        """Get list of all supported languages."""
        return list(self.language_extensions.keys())

    def is_source_code_file(self, file_path: str) -> bool:
        """Check if file is a source code file."""
        language = self.get_language(file_path)
        if not language:
            return False

        # Exclude configuration and documentation files
        excluded_languages = {"config", "markdown", "yaml", "json", "xml"}
        return language not in excluded_languages

    def is_configuration_file(self, file_path: str) -> bool:
        """Check if file is a configuration file."""
        language = self.get_language(file_path)
        config_languages = {"config", "yaml", "json", "xml"}
        return language in config_languages

    def get_file_category(self, file_path: str) -> str:
        """Get the category of a file (source, config, documentation, etc.)."""
        language = self.get_language(file_path)

        if not language:
            return "unknown"

        if language == "markdown":
            return "documentation"
        elif language in {"config", "yaml", "json", "xml"}:
            return "configuration"
        elif language in {"dockerfile"}:
            return "infrastructure"
        elif self.is_source_code_file(file_path):
            return "source"
        else:
            return "other"

    def should_analyze_for_security(self, file_path: str) -> bool:
        """Determine if file should be analyzed for security issues."""
        return self.is_text_file(file_path) and (
            self.is_source_code_file(file_path)
            or self.is_configuration_file(file_path)
            or self.is_security_sensitive(file_path)
        )

    def get_analyzable_files(self, directory: str, config: Dict) -> List[str]:
        """Get list of files that can be analyzed based on configuration."""
        try:
            from .file_scanner import FileScanner
        except ImportError:
            # Fallback implementation if FileScanner not available
            return self._simple_file_scan(directory)

        scanner = FileScanner(config)
        files = []

        try:
            for file_path in scanner.scan_directory(directory):
                if self.is_text_file(file_path):
                    files.append(file_path)
        except Exception:
            # Fallback to simple scan if FileScanner fails
            files = self._simple_file_scan(directory)

        return files

    def _simple_file_scan(self, directory: str) -> List[str]:
        """Simple fallback file scanning implementation."""
        files = []
        try:
            for path in Path(directory).rglob("*"):
                if path.is_file() and self.is_text_file(str(path)):
                    files.append(str(path))
        except Exception:
            pass  # Return empty list on any error
        return files
