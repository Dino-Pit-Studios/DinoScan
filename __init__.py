"""
DinoScan - Comprehensive AST-based Python code analysis toolkit.

DinoScan provides enterprise-grade static analysis capabilities with enhanced
accuracy through AST parsing and modern Python architecture.
"""

__version__ = "2.0.0"
__author__ = "DinoScan Development Team"
__email__ = "dev@dinoair.com"
__license__ = "MIT"

from .analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
from .analyzers.circular_import_analyzer import CircularImportAnalyzer  
from .analyzers.dead_code_analyzer import DeadCodeAnalyzer
from .analyzers.doc_quality_analyzer import DocumentationAnalyzer
from .analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
from .core.base_analyzer import AnalysisResult, Finding, Severity, Category
from .core.config_manager import ConfigManager
from .core.reporter import create_reporter

__all__ = [
    # Core classes
    "AnalysisResult",
    "Finding", 
    "Severity",
    "Category",
    "ConfigManager",
    "create_reporter",
    # Analyzers
    "AdvancedSecurityAnalyzer",
    "CircularImportAnalyzer",
    "DeadCodeAnalyzer", 
    "DocumentationAnalyzer",
    "DuplicateCodeAnalyzer",
    # Metadata
    "__version__",
    "__author__",
    "__email__",
    "__license__",
]