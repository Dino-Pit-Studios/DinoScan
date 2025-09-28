"""
Base analyzer module providing foundational classes for code analysis.

This module defines the core interfaces and data structures used throughout
the DinoScan analysis framework.
"""

import ast
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Union


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
    """Abstract base class for all DinoScan analyzers."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize analyzer with optional configuration."""
        self.config = config or {}
        self.name = self.__class__.__name__
        self.version = "2.0.0"
        self._excluded_dirs = set()
        self._excluded_files = set()
        self._included_extensions = set()
        self._load_exclusions()

    def _load_exclusions(self) -> None:
        """Load file and directory exclusions from config."""
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
        """Determine if a file should be analyzed."""
        path = Path(file_path)

        # Check extension
        if path.suffix not in self._included_extensions:
            return False

        # Check excluded directories
        for excluded_dir in self._excluded_dirs:
            if excluded_dir in path.parts:
                return False

        # Check excluded files (basic pattern matching)
        file_name = path.name
        for pattern in self._excluded_files:
            if pattern.replace("*", "") in file_name:
                return False

        return True

    @abstractmethod
    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze a single file and return findings."""
        pass

    @abstractmethod
    def get_supported_extensions(self) -> set[str]:
        """Return set of file extensions this analyzer supports."""
        pass

    def analyze_project(self, project_path: str) -> AnalysisResult:
        """Analyze an entire project directory."""
        import time
        from datetime import datetime

        start_time = time.time()
        result = AnalysisResult(
            analyzer_name=self.name,
            version=self.version,
            timestamp=datetime.now().isoformat(),
            project_path=project_path,
            config=self.config,
        )

        # Scan for files
        supported_extensions = self.get_supported_extensions()
        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self._excluded_dirs]

            for file in files:
                file_path = os.path.join(root, file)

                if not self.should_analyze_file(file_path):
                    result.files_skipped.append(file_path)
                    continue

                # Check if file extension is supported by this analyzer
                if Path(file_path).suffix not in supported_extensions:
                    continue

                try:
                    findings = self.analyze_file(file_path)
                    result.findings.extend(findings)
                    result.files_analyzed.append(file_path)
                except Exception as e:
                    # Log error and continue
                    print(f"Error analyzing {file_path}: {e}")
                    result.files_skipped.append(file_path)

        result.analysis_duration = time.time() - start_time
        return result

    def get_rule_documentation(self) -> dict[str, str]:
        """Return documentation for all rules implemented by this analyzer."""
        return {}


class ASTAnalyzer(BaseAnalyzer):
    """Base class for AST-based analyzers."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._ast_cache: dict[str, ast.AST] = {}

    def parse_file(self, file_path: str) -> ast.AST | None:
        """Parse a file and return its AST, with caching."""
        if file_path in self._ast_cache:
            return self._ast_cache[file_path]

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content, filename=file_path)
            self._ast_cache[file_path] = tree
            return tree

        except (SyntaxError, UnicodeDecodeError) as e:
            print(f"Failed to parse {file_path}: {e}")
            return None

    def get_line_content(self, file_path: str, line_number: int) -> str:
        """Get the content of a specific line from a file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if 1 <= line_number <= len(lines):
                    return lines[line_number - 1].rstrip()
        except (IOError, UnicodeDecodeError):
            pass
        return ""

    def clear_cache(self) -> None:
        """Clear the AST cache."""
        self._ast_cache.clear()
