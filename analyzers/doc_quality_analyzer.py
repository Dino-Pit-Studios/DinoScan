#!/usr/bin/env python3
"""
DinoScan Documentation Quality Analyzer - Advanced AST-based documentation validation.

This analyzer validates documentation quality using comprehensive AST analysis:
- Docstring presence and format validation (Google, Sphinx, NumPy styles)
- Parameter documentation completeness with type consistency
- Return value documentation validation
- Code example testing and validation
- API completeness checking for public interfaces
- Multilingual documentation support

Enhanced features over PowerShell version:
- AST-based parsing for precise parameter and return value extraction
- Support for multiple docstring conventions with auto-detection
- Type annotation consistency checking
- Code example execution validation
- Public API coverage analysis with __all__ support
- Configurable severity levels and style preferences
"""

import argparse
import ast
import re
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.base_analyzer import AnalysisResult, ASTAnalyzer, Category, Finding, Severity
from core.config_manager import ConfigManager
from core.reporter import create_reporter

parser = argparse.ArgumentParser(
    description=(
        "DinoScan Documentation Quality Analyzer: Analyze and validate "
        "docstrings and documentation quality in Python code."
    ),
    epilog="""Examples:
  %(prog)s /path/to/file.py --style google
  %(prog)s /path/to/project --output-format json --output-file docs.json
""",
)


class DocstringInfo:
    """Information about a docstring."""

    content: str
    style: str = "unknown"  # 'google', 'sphinx', 'numpy', 'plain'
    sections: dict[str, str] = field(default_factory=dict)
    parameters: dict[str, str] = field(default_factory=dict)
    returns: str = ""
    examples: list[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class FunctionInfo:
    """Information about a function for documentation analysis."""

    name: str
    parameters: list[str]
    parameter_types: dict[str, str]
    return_type: str | None
    is_private: bool
    is_method: bool
    is_property: bool
    decorators: list[str]
    line_number: int
    docstring: DocstringInfo | None = None


class DocumentationAnalyzer(ASTAnalyzer):
    """Documentation quality analyzer with comprehensive AST-based validation."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.name = "DocumentationAnalyzer"
        self._setup_doc_config()

    @staticmethod
    def get_supported_extensions() -> set[str]:
        """Return supported Python file extensions."""
        return {".py", ".pyi", ".pyw"}

    def _setup_doc_config(self) -> None:
        """Set up documentation analysis configuration."""
        # Documentation style preferences
        self.preferred_style = self.config.get("preferred_style", "google")
        self.enforce_style = self.config.get("enforce_style", False)

        # Coverage requirements
        self.require_module_docstring = self.config.get(
            "require_module_docstring", True
        )
        self.require_class_docstring = self.config.get("require_class_docstring", True)
        self.require_function_docstring = self.config.get(
            "require_function_docstring", True
        )
        self.require_method_docstring = self.config.get(
            "require_method_docstring", True
        )

        # Parameter documentation
        self.require_parameter_docs = self.config.get("require_parameter_docs", True)
        self.require_return_docs = self.config.get("require_return_docs", True)
        self.check_type_consistency = self.config.get("check_type_consistency", True)

        # Private/special method handling
        self.check_private_methods = self.config.get("check_private_methods", False)
        self.check_special_methods = self.config.get("check_special_methods", False)

        # Example validation
        self.validate_examples = self.config.get("validate_examples", True)

        # Minimum docstring length
        self.min_docstring_length = self.config.get("min_docstring_length", 10)

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze documentation quality in a Python file."""
        tree = self.parse_file(file_path)
        if not tree:
            return []

        findings = []
        visitor = DocStringVisitor(file_path, self.config)
        visitor.visit(tree)

        # Check module docstring
        if self.require_module_docstring:
            module_docstring = (
                ast.get_docstring(tree) if isinstance(tree, ast.Module) else None
            )
            if not module_docstring:
                findings.append(
                    Finding(
                        rule_id="DOC001",
                        category=Category.DOCUMENTATION,
                        severity=Severity.WARNING,
                        line_number=1,
                        message="Module docstring is missing.",
                        file_path=file_path,
                    )
                )

    def _analyze_function_docs(
        self, func: FunctionInfo, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if self._should_skip_function(func):
            return findings

        missing = self._get_missing_docstring_findings(func, file_path)
        if missing:
            return missing

        findings.extend(self._get_docstring_length_findings(func, file_path))

        return findings

    def _should_skip_function(self, func: FunctionInfo) -> bool:
        if func.is_private and not self.check_private_methods:
            return True
        if func.name.startswith("__") and func.name.endswith("__") and not self.check_special_methods:
            return True
        return False

    def _get_missing_docstring_findings(
        self, func: FunctionInfo, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        requires = self.require_function_docstring or (
            func.is_method and self.require_method_docstring
        )
        if not func.docstring and requires:
            severity = Severity.MEDIUM if not func.is_private else Severity.LOW
            findings.append(
                Finding(
                    rule_id="missing-function-docstring",
                    category=Category.DOCUMENTATION,
                    severity=severity,
                    message=(
                        f"Missing docstring for {'method' if func.is_method else 'function'} "
                        f"'{func.name}'"
                    ),
                    file_path=file_path,
                    line_number=func.line_number,
                    column_number=0,
                    suggestion=(
                        "Add docstring describing the "
                        f"{'method' if func.is_method else 'function'}"
                        "'s purpose"
                    ),
                    tags={"docstring", "function" if not func.is_method else "method"},
                )
            )
        return findings

    def _get_docstring_length_findings(
        self, func: FunctionInfo, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        if func.docstring and len(func.docstring.content) < self.min_docstring_length:
            findings.append(
                Finding(
                    rule_id="short-function-docstring",
                    category=Category.DOCUMENTATION,
                    severity=Severity.LOW,
                    message=(
                        f"Function docstring too short ({len(func.docstring.content)} chars)"
                    ),
                    file_path=file_path,
                    line_number=func.line_number,
                    column_number=0,
                    suggestion=(
                        "Expand docstring to at least "
                        f"{self.min_docstring_length} characters"
                    ),
                    tags={"docstring", "function", "length"},
                )
            )
        return findings
                Finding(
                    rule_id="short-function-docstring",
                    category=Category.DOCUMENTATION,
                    severity=Severity.LOW,
                    message=(
                        f"Docstring too short for '{func.name}' "
                        f"({len(func.docstring.content)} chars)"
                    ),
                    file_path=file_path,
                    line_number=func.docstring.line_number,
                    column_number=0,
                    suggestion=(
                        "Expand docstring to at least "
                        f"{self.min_docstring_length} "
                        "characters"
                    ),
                    tags={"docstring", "function", "length"},
                )
            )

        # Check docstring style
        if self.enforce_style and func.docstring.style != self.preferred_style:
            findings.append(
                Finding(
                    rule_id="docstring-style-mismatch",
                    category=Category.DOCUMENTATION,
                    severity=Severity.LOW,
                    message=(
                        f"Docstring style '{func.docstring.style}' "
                        f"doesn't match preferred '{self.preferred_style}'"
                    ),
                    file_path=file_path,
                    line_number=func.docstring.line_number,
                    column_number=0,
                    suggestion=f"Convert docstring to {self.preferred_style} style",
                    tags={"docstring", "style"},
                )
            )

        # Check parameter documentation
        if self.require_parameter_docs:
            findings.extend(self._check_parameter_docs(func, file_path))

        # Check return documentation
        if self.require_return_docs and func.return_type != "None":
            findings.extend(self._check_return_docs(func, file_path))

        # Check type consistency
        if self.check_type_consistency:
            findings.extend(self._check_type_consistency(func, file_path))

        # Validate examples
        if self.validate_examples and func.docstring.examples:
            findings.extend(self._validate_examples(func, file_path))

        return findings

    def _analyze_class_docs(
        self, class_info: dict[str, Any], file_path: str
    ) -> list[Finding]:
        """Analyze documentation for a class."""
        findings = []

        if not class_info["docstring"] and self.require_class_docstring:
            severity = Severity.MEDIUM if not class_info["is_private"] else Severity.LOW
            findings.append(
                Finding(
                    rule_id="missing-class-docstring",
                    category=Category.DOCUMENTATION,
                    severity=severity,
                    message=(f"Missing docstring for class '{class_info['name']}'"),
                    file_path=file_path,
                    line_number=class_info["line_number"],
                    column_number=0,
                    suggestion=(
                        "Add class docstring describing the class purpose and usage"
                    ),
                    tags={"docstring", "class"},
                )
            )

        return findings

    @staticmethod
    def _check_parameter_docs(func: FunctionInfo, file_path: str) -> list[Finding]:
        """Check parameter documentation completeness."""
        findings: list[Finding] = []

        # Skip 'self' and 'cls' parameters
        params_to_check = [p for p in func.parameters if p not in ("self", "cls")]

        if not params_to_check or not func.docstring:
            return findings

        documented_params = set(func.docstring.parameters.keys())
        missing_params = set(params_to_check) - documented_params
        extra_params = documented_params - set(params_to_check)

        # Missing parameter documentation
        for param in missing_params:
            findings.append(
                Finding(
                    rule_id="missing-parameter-doc",
                    category=Category.DOCUMENTATION,
                    severity=Severity.MEDIUM,
                    message=(
                        f"Missing documentation for parameter '{param}' "
                        f"in '{func.name}'"
                    ),
                    file_path=file_path,
                    line_number=func.docstring.line_number,
                    column_number=0,
                    suggestion=f"Add documentation for parameter '{param}'",
                    tags={"docstring", "parameter", "missing"},
                )
            )

        # Extra parameter documentation
        for param in extra_params:
            findings.append(
                Finding(
                    rule_id="extra-parameter-doc",
                    category=Category.DOCUMENTATION,
                    severity=Severity.LOW,
                    message=(
                        f"Documentation for non-existent parameter '{param}' "
                        f"in '{func.name}'"
                    ),
                    file_path=file_path,
                    line_number=func.docstring.line_number,
                    column_number=0,
                    suggestion=(
                        f"Remove documentation for parameter '{param}' "
                        "or check parameter name"
                    ),
                    tags={"docstring", "parameter", "extra"},
                )
            )

        return findings

    @staticmethod
    def _check_return_docs(func: FunctionInfo, file_path: str) -> list[Finding]:
        """Check return value documentation."""
        findings: list[Finding] = []

        if (
            func.docstring
            and not func.docstring.returns
            and func.return_type
            and func.return_type != "None"
        ):
            findings.append(
                Finding(
                    rule_id="missing-return-doc",
                    category=Category.DOCUMENTATION,
                    severity=Severity.MEDIUM,
                    message=f"Missing return value documentation for '{func.name}'",
                    file_path=file_path,
                    line_number=func.docstring.line_number,
                    column_number=0,
                    suggestion="Add return value documentation",
                    tags={"docstring", "return", "missing"},
                )
            )

        return findings

    def _check_type_consistency(
        self, func: FunctionInfo, file_path: str
    ) -> list[Finding]:
        """Check consistency between type annotations and docstring."""
        findings: list[Finding] = []

        if not func.docstring:
            return findings

        # Check parameter type consistency
        for param, doc_type in func.docstring.parameters.items():
            if param in func.parameter_types:
                annotation_type = func.parameter_types[param]
                if not self._types_compatible(annotation_type, doc_type):
                    findings.append(
                        Finding(
                            rule_id="type-annotation-mismatch",
                            category=Category.DOCUMENTATION,
                            severity=Severity.LOW,
                            message=(
                                f"Type annotation '{annotation_type}' doesn't match "
                                f"documented type '{doc_type}' "
                                f"for parameter '{param}'"
                            ),
                            file_path=file_path,
                            line_number=func.docstring.line_number,
                            column_number=0,
                            suggestion=(
                                "Update type annotation or documentation to match"
                            ),
                            tags={"docstring", "type", "mismatch"},
                        )
                    )

        return findings

    @staticmethod
    def _validate_examples(
        func: FunctionInfo,
        file_path: str,
    ) -> list[Finding]:
        """Validate code examples in docstring."""
        findings: list[Finding] = []

        if not func.docstring:
            return findings

        for i, example in enumerate(func.docstring.examples):
            try:
                # Try to compile the example code
                compile(example, f"<docstring_example_{i}>", "exec")
            except SyntaxError as e:
                findings.append(
                    Finding(
                        rule_id="invalid-docstring-example",
                        category=Category.DOCUMENTATION,
                        severity=Severity.LOW,
                        message=(
                            "Syntax error in docstring example for '"
                            + func.name
                            + "': "
                            + e.msg
                        ),
                        file_path=file_path,
                        line_number=func.docstring.line_number,
                        column_number=0,
                        suggestion="Fix syntax error in example code",
                        tags={"docstring", "example", "syntax"},
                    )
                )

        return findings

    @staticmethod
    def _types_compatible(annotation: str, documented: str) -> bool:
        """Check if type annotation and documented type are compatible."""
        # Simple compatibility check - can be enhanced
        # Normalize types
        annotation = annotation.strip().lower()
        documented = documented.strip().lower()

        # Direct match
        if annotation == documented:
            return True

        # Common aliases
        aliases = {
            "str": ["string"],
            "int": ["integer"],
            "bool": ["boolean"],
            "list": ["array"],
            "dict": ["dictionary", "mapping"],
        }

        for base_type, alias_list in aliases.items():
            if annotation == base_type and documented in alias_list:
                return True
            if documented == base_type and annotation in alias_list:
                return True

        return False


class DocStringVisitor(ast.NodeVisitor):
    """AST visitor to extract docstring and function information."""

    def __init__(self, file_path: str, config: dict[str, Any]):
        self.file_path = file_path
        self.config = config
        self.functions: list[FunctionInfo] = []
        self.classes: list[dict[str, Any]] = []
        self.current_class: str | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        self._process_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        self._process_function(node)
        self.generic_visit(node)

    def _process_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Process function or method node."""
        # Extract parameters
        parameters = []
        parameter_types = {}

        for arg in node.args.args:
            parameters.append(arg.arg)
            if arg.annotation:
                parameter_types[arg.arg] = ast.unparse(arg.annotation)

        # Extract return type
        return_type = None
        if node.returns:
            return_type = ast.unparse(node.returns)

        # Extract decorators
        decorators = []
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                decorators.append(decorator.id)
            elif isinstance(decorator, ast.Attribute):
                decorators.append(decorator.attr)

        # Determine if this is a method or property
        is_method = self.current_class is not None
        is_property = "property" in decorators

        # Extract docstring
        docstring_info = None
        docstring_content = ast.get_docstring(node)
        if docstring_content:
            docstring_info = self._parse_docstring(docstring_content, node.lineno + 1)

        func_info = FunctionInfo(
            name=node.name,
            parameters=parameters,
            parameter_types=parameter_types,
            return_type=return_type,
            is_private=node.name.startswith("_"),
            is_method=is_method,
            is_property=is_property,
            decorators=decorators,
            line_number=node.lineno,
            docstring=docstring_info,
        )

    self.functions.append(func_info)

def visit_ClassDef(self, node: ast.ClassDef) -> None:
    """Visit class definition."""
    old_class = self.current_class
    self.current_class = node.name

    # Extract class docstring
    docstring_content = ast.get_docstring(node)

    class_info = {
        "name": node.name,
        "line_number": node.lineno,
        "is_private": node.name.startswith("_"),
        "docstring": docstring_content,
    }

    self.classes.append(class_info)

    self.generic_visit(node)
    self.current_class = old_class


@staticmethod
def _detect_docstring_style(content: str) -> str:
    """Detect the docstring style."""
    # Google style: Args:, Returns:
    if re.search(r"\b(Args|Arguments|Parameters):\s*\n", content):
        return "google"

    # Sphinx style: :param, :return
    if re.search(r":param\s+\w+:", content) or re.search(r":return:", content):
        return "sphinx"

    # NumPy style: Parameters, Returns with dashes
    if re.search(r"\n\s*Parameters\s*\n\s*-+", content):
        return "numpy"

    return "plain"

def _parse_google_docstring(self, content: str, docstring_info: DocstringInfo) -> None:
    """Parse Google-style docstring."""
    lines = content.split("\n")
    raw_sections = self._extract_google_sections(lines)

    # Assign joined section content to docstring_info.sections
    for name, content_lines in raw_sections.items():
        docstring_info.sections[name] = "\n".join(content_lines)

    # Helper functions for section parsing
    def _handle_returns():
        docstring_info.returns = docstring_info.sections["returns"].strip()

    def _handle_examples():
        example_text = docstring_info.sections["examples"]
        code_blocks = re.findall(r">>> (.+?)(?=>>>|\Z)", example_text, re.DOTALL)
        docstring_info.examples = [block.strip() for block in code_blocks]

    # Section handlers mapping
    handlers = {
        "parameters": lambda: self._parse_google_parameters(
            docstring_info.sections["parameters"], docstring_info
        ),
        "returns": _handle_returns,
        "examples": _handle_examples,
    }

    # Invoke handlers for present sections
    for section, handler in handlers.items():
        if section in raw_sections:
            handler()

    parser.add_argument("path", help="Path to analyze (file or directory)")

    parser.add_argument(
        "--output-format",
        choices=["console", "json", "xml", "sarif"],
        default="console",
        help="Output format (default: console)",
    )

    parser.add_argument(
        "--output-file", help="Output file path (default: print to stdout)"
    )

    parser.add_argument("--config", help="Configuration file path")

    parser.add_argument(
        "--style",
        choices=["google", "sphinx", "numpy", "any"],
        help="Preferred docstring style",
    )

    parser.add_argument(
        "--enforce-style",
        action="store_true",
        help="Enforce consistent docstring style",
    )

    parser.add_argument(
        "--no-private",
        action="store_true",
        help="Skip private methods and functions",
    )

    parser.add_argument(
        "--no-examples",
        action="store_true",
        help="Skip private methods and functions",
    )

# Public wrappers for protected methods
def detect_docstring_style(self, content: str) -> str:
    return self._detect_docstring_style(content)

def extract_google_sections(self, lines) -> dict:
    return self._extract_google_sections(lines)

def parse_google_docstring(self, content: str, docstring_info: DocstringInfo) -> None:
    return self._parse_google_docstring(content, docstring_info)

def parse_google_parameters(self, content: str, docstring_info: DocstringInfo) -> None:
    return self._parse_google_parameters(content, docstring_info)

def parse_numpy_docstring(self, content: str, docstring_info: DocstringInfo) -> None:
    return self._parse_numpy_docstring(content, docstring_info)

def parse_sphinx_docstring(self, content: str, docstring_info: DocstringInfo) -> None:
    return self._parse_sphinx_docstring(content, docstring_info)
        help="Skip example validation",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose output",
    )

    args = parser.parse_args()

    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.get_analyzer_config("documentation")

    # Override config with command-line arguments
    if args.style:
        config["preferred_style"] = args.style
    if args.enforce_style:
        config["enforce_style"] = True
    if args.no_private:
        config["check_private_methods"] = False
    if args.no_examples:
        config["validate_examples"] = False

    # Create analyzer
    analyzer = DocumentationAnalyzer(config)

    try:
        if args.verbose:
            sys.stderr.write(f"Starting documentation analysis of {args.path}...\n")

        # Analyze file or project
        if Path(args.path).is_file():
            findings = analyzer.analyze_file(args.path)
            result = AnalysisResult(
                analyzer_name=analyzer.name,
                version=analyzer.version,
                timestamp=datetime.now().isoformat(),
                project_path=str(Path(args.path).parent),
            )
            result.findings = findings
            result.files_analyzed = [args.path]
        else:
            result = analyzer.analyze_project(args.path)

        if args.verbose:
            stats = result.get_summary_stats()
            sys.stderr.write(
                f"Analysis complete: {stats['total_findings']} "
                "documentation issues found\n"
            )

        # Create reporter and output results
        reporter_config = {
            "use_colors": not args.output_file,
            "show_context": True,
            "max_findings_per_file": 20,
        }

        reporter = create_reporter(args.output_format, reporter_config)

        if args.output_file:
            reporter.save_results(result, args.output_file)
            if args.verbose:
                sys.stderr.write(f"Results saved to {args.output_file}\n")
        else:
            reporter.print_results(result)

        # Exit with appropriate code
        stats = result.get_summary_stats()
        if stats["high_severity"] > 0:
            sys.exit(2)
        elif stats["medium_severity"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        sys.stderr.write(f"Error during analysis: {e}\n")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
