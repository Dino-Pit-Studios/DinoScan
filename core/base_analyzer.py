"""
Base analyzer module providing foundational classes for code analysis.

This module defines the core interfaces and data structures used throughout
the DinoScan analysis framework.
"""

import ast
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .error_handler import ErrorHandler
from .file_types import FileTypeManager
from .settings_manager import SettingsManager


class Severity(Enum):
    """Analysis finding severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Category(Enum):
    """Analysis category types."""

    SECURITY = "security"
    STYLE = "style"
    COMPLEXITY = "complexity"
    DOCUMENTATION = "documentation"
    DUPLICATES = "duplicates"
    IMPORTS = "imports"
    DEAD_CODE = "dead-code"
    PERFORMANCE = "performance"


@dataclass
class Finding:
    """Represents a single analysis finding."""

    # Core identification
    rule_id: str
    category: Category
    severity: Severity
    message: str

    # Location information
    file_path: str
    line_number: int
    column_number: int = 0
    end_line: int = 0
    end_column: int = 0

    # Context and details
    context: str = ""
    code_snippet: str = ""
    suggestion: str = ""
    cwe: str | None = None
    confidence: float = 1.0

    # Additional metadata
    fixable: bool = False
    external_refs: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary format."""
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "context": self.context,
            "code_snippet": self.code_snippet,
            "suggestion": self.suggestion,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "fixable": self.fixable,
            "external_refs": self.external_refs,
            "tags": list(self.tags),
        }


@dataclass
class AnalysisResult:
    """Contains the complete results of an analysis run."""

    # Basic metadata
    analyzer_name: str
    version: str
    timestamp: str
    project_path: str

    # Results
    findings: list[Finding] = field(default_factory=list)
    files_analyzed: list[str] = field(default_factory=list)
    files_skipped: list[str] = field(default_factory=list)

    # Statistics
    analysis_duration: float = 0.0
    rules_executed: list[str] = field(default_factory=list)

    # Configuration used
    config: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: Category) -> list[Finding]:
        """Get all findings of a specific category."""
        return [f for f in self.findings if f.category == category]

    def get_findings_by_file(self, file_path: str) -> list[Finding]:
        """Get all findings for a specific file."""
        return [f for f in self.findings if f.file_path == file_path]

    def get_summary_stats(self) -> dict[str, Any]:
        """Get summary statistics."""
        severity_counts = {}
        category_counts = {}

        for finding in self.findings:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )
            category_counts[finding.category.value] = (
                category_counts.get(finding.category.value, 0) + 1
            )

        return {
            "total_findings": len(self.findings),
            "files_analyzed": len(self.files_analyzed),
            "files_skipped": len(self.files_skipped),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "fixable_issues": len([f for f in self.findings if f.fixable]),
            "analysis_duration": self.analysis_duration,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            "analyzer_name": self.analyzer_name,
            "version": self.version,
            "timestamp": self.timestamp,
            "project_path": self.project_path,
            "findings": [f.to_dict() for f in self.findings],
            "files_analyzed": self.files_analyzed,
            "files_skipped": self.files_skipped,
            "analysis_duration": self.analysis_duration,
            "rules_executed": self.rules_executed,
            "config": self.config,
            "summary": self.get_summary_stats(),
        }


class BaseAnalyzer(ABC):
    """Abstract base class for all DinoScan analyzers with enhanced capabilities."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize analyzer with optional configuration."""
        self.config = config or {}
        self.name = self.__class__.__name__
        self.version = "2.0.0"

        # Initialize managers
        self.error_handler = ErrorHandler(f"dinoscan.{self.name}")
        self.file_type_manager = FileTypeManager()
        self.settings_manager = SettingsManager(self.config.get("workspace_path"))

        # Legacy exclusions for backward compatibility
        self._excluded_dirs = set()
        self._excluded_files = set()
        self._included_extensions = set()
        self._load_exclusions()

    def _load_exclusions(self) -> None:
        """Load file and directory exclusions from config (legacy support)."""
        exclude_config = self.config.get("exclusions", {})

        self._excluded_dirs.update(
            exclude_config.get(
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
                ],
            )
        )

        self._excluded_files.update(
            exclude_config.get(
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
        )

        self._included_extensions.update(
            exclude_config.get(
                "extensions", [".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"]
            )
        )

    def should_analyze_file(self, file_path: str) -> bool:
        """Determine if a file should be analyzed using enhanced filtering."""
        # Use settings manager for primary exclusion logic
        if self.settings_manager.should_exclude_file(file_path):
            self.error_handler.log_file_skipped(file_path, "excluded by settings")
            return False

        # Check if file type is supported
        language = self.file_type_manager.get_language(file_path)
        if not language:
            self.error_handler.log_file_skipped(file_path, "unsupported file type")
            return False

        # Check if file extension is supported by this analyzer
        supported_extensions = self.get_supported_extensions()
        if Path(file_path).suffix not in supported_extensions:
            self.error_handler.log_file_skipped(
                file_path, "unsupported extension for this analyzer"
            )
            return False

        # Legacy exclusion check for backward compatibility
        path = Path(file_path)

        # Check excluded directories (legacy)
        for excluded_dir in self._excluded_dirs:
            if excluded_dir in path.parts:
                self.error_handler.log_file_skipped(
                    file_path, f"excluded directory: {excluded_dir}"
                )
                return False

        # Check excluded files (legacy pattern matching)
        file_name = path.name
        for pattern in self._excluded_files:
            if pattern.replace("*", "") in file_name:
                self.error_handler.log_file_skipped(
                    file_path, f"excluded file pattern: {pattern}"
                )
                return False

        return True

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze a single file and return findings with enhanced error handling."""
        if not self.should_analyze_file(file_path):
            return []

        self.error_handler.log_analysis_start(file_path, self.name)

        try:
            # For backward compatibility, existing analyzers override this method directly
            findings = self._do_analysis(file_path)
            self.error_handler.log_analysis_complete(
                file_path, self.name, len(findings)
            )
            return findings
        except Exception as e:
            self.error_handler.logger.error("Error analyzing %s: %s", file_path, e)
            return []

    @staticmethod
    def _do_analysis(file_path: str) -> list[Finding]:
        """Default analysis implementation - can be overridden by subclasses."""
        return []

    @abstractmethod
    def get_supported_extensions(self) -> set[str]:
        """Return set of file extensions this analyzer supports."""

        ...

    def safe_read_file(self, file_path: str) -> str | None:
        """Safely read file content."""
        return self.error_handler.safe_file_read(file_path)

    def safe_parse_ast(self, content: str, filename: str) -> ast.AST | None:
        """Safely parse AST from content."""
        return self.error_handler.safe_ast_parse(content, filename)

    def is_enabled(self) -> bool:
        """Check if this analyzer is enabled in settings."""
        analyzer_key = self.name.lower().replace("analyzer", "")
        return self.settings_manager.is_analyzer_enabled(analyzer_key)

    @staticmethod
    def get_analyzer_type() -> str:
        """Get the type/category of this analyzer."""
        return "general"

    def create_finding(
        self,
        file_path: str,
        line: int,
        column: int,
        message: str,
        severity: Severity = Severity.MEDIUM,
        category: Category = Category.STYLE,
        rule_id: str = "",
        suggestion: str = "",
        code_snippet: str = "",
        context: str = "",
        fixable: bool = False,
    ) -> Finding:
        """Create a finding with proper defaults."""
        if not rule_id:
            rule_id = f"{self.name.lower()}_rule"

        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            message=message,
            file_path=file_path,
            line_number=line,
            column_number=column,
            context=context,
            code_snippet=code_snippet,
            suggestion=suggestion,
            fixable=fixable,
        )

    def analyze_project(self, project_path: str) -> AnalysisResult:
        """Analyze an entire project directory with enhanced filtering."""
        import time
        from datetime import datetime

        if not self.is_enabled():
            # Return empty result if analyzer is disabled
            return AnalysisResult(
                analyzer_name=self.name,
                version=self.version,
                timestamp=datetime.now().isoformat(),
                project_path=project_path,
                config=self.config,
            )

        start_time = time.time()
        result = AnalysisResult(
            analyzer_name=self.name,
            version=self.version,
            timestamp=datetime.now().isoformat(),
            project_path=project_path,
            config=self.config,
        )
        # Use enhanced file scanning
        try:
            analyzable_files = self.file_type_manager.get_analyzable_files(
                project_path, self.config
            )
        except Exception:
            # Fallback to legacy scanning
            analyzable_files = self._legacy_file_scan(project_path)

        # Process files
        for file_path in analyzable_files:
            if not self.should_analyze_file(file_path):
                result.files_skipped.append(file_path)
                continue

            # Check if file extension is supported by this analyzer
            supported_extensions = self.get_supported_extensions()
            if Path(file_path).suffix not in supported_extensions:
                result.files_skipped.append(file_path)
                continue

            try:
                findings = self.analyze_file(file_path)
                result.findings.extend(findings)
                result.files_analyzed.append(file_path)
            except Exception as e:
                # Log error and continue
                self.error_handler.logger.error("Error analyzing %s: %s", file_path, e)
                result.files_skipped.append(file_path)

        result.analysis_duration = time.time() - start_time
        return result

    def _legacy_file_scan(self, project_path: str) -> list[str]:
        """Legacy file scanning for backward compatibility."""
        files = []
        supported_extensions = self.get_supported_extensions()

        for root, dirs, filenames in os.walk(project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self._excluded_dirs]

            for filename in filenames:
                file_path = os.path.join(root, filename)
                if Path(file_path).suffix in supported_extensions:
                    files.append(file_path)

        return files

    @staticmethod
    def get_rule_documentation() -> dict[str, str]:
        """Return documentation for all rules implemented by this analyzer."""
        return {}

    @staticmethod
    def normalize_path(file_path: str) -> str:
        """Normalize a file path for consistent comparison."""
        return os.path.normpath(os.path.abspath(file_path))

    @staticmethod
    def get_file_extension(file_path: str) -> str:
        """Get the file extension from a file path."""
        return Path(file_path).suffix.lower()

    @staticmethod
    def is_python_file(file_path: str) -> bool:
        """Check if a file is a Python file based on extension."""
        python_extensions = {".py", ".pyw", ".pyx", ".pyi"}
        return BaseAnalyzer.get_file_extension(file_path) in python_extensions


class ASTAnalyzer(BaseAnalyzer):
    """Base class for AST-based analyzers with enhanced parsing."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._ast_cache: dict[str, ast.AST] = {}

    def parse_file(self, file_path: str) -> ast.AST | None:
        """Parse a file and return its AST, with caching and enhanced error handling."""
        if file_path in self._ast_cache:
            return self._ast_cache[file_path]

        # Use safe file reading from error handler
        content = self.safe_read_file(file_path)
        if content is None:
            return None

        # Use safe AST parsing from error handler
        tree = self.safe_parse_ast(content, file_path)
        if tree is not None:
            self._ast_cache[file_path] = tree

        return tree

    def get_line_content(self, file_path: str, line_number: int) -> str:
        """Get the content of a specific line from a file."""
        content = self.safe_read_file(file_path)
        if content is None:
            return ""

        return self.get_line_content_from_string(content, line_number)

    @staticmethod
    def get_line_content_from_string(content: str, line_number: int) -> str:
        """Get the content of a specific line from string content."""
        try:
            lines = content.splitlines()
            if 1 <= line_number <= len(lines):
                return lines[line_number - 1].rstrip()
        except (IndexError, ValueError):
            return ""
        return ""

    def get_context_lines(
        self, file_path: str, line_number: int, context_size: int = 3
    ) -> str:
        """Get context lines around a specific line."""
        content = self.safe_read_file(file_path)
        if content is None:
            return ""

        return self.get_context_lines_from_string(content, line_number, context_size)

    @staticmethod
    def get_context_lines_from_string(
        content: str, line_number: int, context_size: int = 3
    ) -> str:
        """Get context lines around a specific line from string content."""
        try:
            lines = content.splitlines()
            start_line = max(0, line_number - context_size - 1)
            end_line = min(len(lines), line_number + context_size)
            context_lines = lines[start_line:end_line]
            return "\n".join(context_lines)
        except (IndexError, ValueError):
            return ""

    def clear_cache(self) -> None:
        """Clear the AST cache."""
        self._ast_cache.clear()

    @staticmethod
    def extract_string_literals(node: ast.AST) -> list[str]:
        """Extract all string literals from an AST node."""
        string_literals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                string_literals.append(child.value)
            elif isinstance(child, ast.Str):  # Python < 3.8 compatibility
                string_literals.append(child.s)
        return string_literals

    @staticmethod
    def get_function_complexity(node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function."""
        complexity = 1  # Base complexity
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.BoolOp) and isinstance(
                child.op, (ast.And, ast.Or)
            ):
                complexity += len(child.values) - 1
        return complexity

    @staticmethod
    def get_node_name(node: ast.AST) -> str:
        """Get the name of an AST node if it has one."""
        if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            return node.name
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.arg):
            return node.arg
        return ""
