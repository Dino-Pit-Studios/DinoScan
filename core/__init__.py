"""
DinoScan Core - Comprehensive AST-based code analysis framework.

This module provides the foundational AST analysis capabilities for the DinoScan
toolkit, leveraging Python's built-in ast module and optional JavaScript/TypeScript
parsing through esprima, babel, or tree-sitter bindings.
"""

__version__ = "2.0.0"
__author__ = "DinoScan Development Team"

from .ast_analyzer import ASTAnalyzer, JavaScriptASTAnalyzer, PythonASTAnalyzer
from .base_analyzer import AnalysisResult, BaseAnalyzer, Finding
from .config_manager import ConfigManager
from .file_scanner import FileScanner
from .reporter import ConsoleReporter, JSONReporter, Reporter

__all__ = [
    "ASTAnalyzer",
    "PythonASTAnalyzer",
    "JavaScriptASTAnalyzer",
    "BaseAnalyzer",
    "AnalysisResult",
    "Finding",
    "ConfigManager",
    "FileScanner",
    "Reporter",
    "JSONReporter",
    "ConsoleReporter",
]
