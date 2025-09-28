#!/usr/bin/env python3
"""
Centralized error handling for DinoScan analyzers.
"""

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional


class DinoScanError(Exception):
    """Base exception for DinoScan errors."""

    pass


class FileReadError(DinoScanError):
    """Error reading file."""

    pass


class ParseError(DinoScanError):
    """Error parsing file content."""

    pass


class ErrorHandler:
    """Centralized error handling with consistent logging."""

    def __init__(self, logger_name: str = "dinoscan"):
        """Initialize error handler with logger."""
        self.logger = logging.getLogger(logger_name)
        if not self.logger.handlers:
            # Set up basic logging configuration if none exists
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.WARNING)

    @contextmanager
    def handle_file_operation(self, file_path: str, operation: str = "processing"):
        """Context manager for file operations with consistent error handling."""
        try:
            yield
        except OSError as e:
            self.logger.warning("Failed %s %s: %s", operation, file_path, e)
            raise FileReadError(f"Cannot read file {file_path}: {e}") from e
        except UnicodeDecodeError as e:
            self.logger.warning("Encoding error in %s: %s", file_path, e)
            raise FileReadError(f"Encoding error in {file_path}: {e}") from e
        except SyntaxError as e:
            self.logger.debug("Syntax error in %s: %s", file_path, e)
            raise ParseError(f"Syntax error in {file_path}: {e}") from e
        except Exception as e:
            self.logger.error("Unexpected error %s %s: %s", operation, file_path, e)
            raise DinoScanError(f"Unexpected error {operation} {file_path}: {e}") from e

    def safe_file_read(self, file_path: str, encoding: str = "utf-8") -> Optional[str]:
        """Safe file reading with error handling."""
        try:
            with self.handle_file_operation(file_path, "reading"):
                return Path(file_path).read_text(encoding=encoding, errors="ignore")
        except DinoScanError:
            return None

    def safe_ast_parse(self, content: str, filename: str) -> Optional[Any]:
        """Safe AST parsing with error handling."""
        try:
            import ast

            with self.handle_file_operation(filename, "parsing"):
                return ast.parse(content, filename=filename)
        except (DinoScanError, ValueError):
            return None

    def log_analysis_start(self, file_path: str, analyzer_name: str) -> None:
        """Log the start of analysis for a file."""
        self.logger.debug("Starting %s analysis of %s", analyzer_name, file_path)

    def log_analysis_complete(
        self, file_path: str, analyzer_name: str, finding_count: int
    ) -> None:
        """Log the completion of analysis for a file."""
        self.logger.debug(
            "Completed %s analysis of %s: %s findings",
            analyzer_name,
            file_path,
            finding_count
        )

    def log_file_skipped(self, file_path: str, reason: str) -> None:
        """Log when a file is skipped during analysis."""
        self.logger.debug("Skipping %s: %s", file_path, reason)
