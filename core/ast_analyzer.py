"""
AST analyzer implementations for Python and JavaScript/TypeScript.

This module provides concrete AST analyzer implementations that can parse
and analyze code using Abstract Syntax Trees for more accurate analysis.
"""

import ast
import json
import re
from typing import Any

from .base_analyzer import ASTAnalyzer, Category, Finding, Severity


class PythonASTAnalyzer(ASTAnalyzer):
    """Python-specific AST analyzer with comprehensive code analysis."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.visitors = []
        self._setup_visitors()

    def _setup_visitors(self) -> None:
        """Set up AST visitor classes for different analysis types."""
        # We'll add visitor classes as we implement specific analyzers
        pass

    def get_supported_extensions(self) -> set[str]:
        """Return supported Python file extensions."""
        return {".py", ".pyi", ".pyw"}

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze a Python file using AST."""
        findings = []
        tree = self.parse_file(file_path)

        if not tree:
            return findings

        # Run all registered visitors
        for visitor_class in self.visitors:
            visitor = visitor_class(file_path, self.config)
            visitor.visit(tree)
            findings.extend(visitor.findings)

        return findings


class PythonASTVisitor(ast.NodeVisitor):
    """Base visitor class for Python AST analysis."""

    def __init__(self, file_path: str, config: dict[str, Any]):
        self.file_path = file_path
        self.config = config
        self.findings: list[Finding] = []
        self._lines: list[str] = []
        self._load_file_lines()

    def _load_file_lines(self) -> None:
        """Load file lines for context extraction."""
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                self._lines = f.readlines()
        except (IOError, UnicodeDecodeError):
            self._lines = []

    def get_line_content(self, line_number: int) -> str:
        """Get content of a specific line."""
        if 1 <= line_number <= len(self._lines):
            return self._lines[line_number - 1].rstrip()
        return ""

    def add_finding(
        self,
        rule_id: str,
        category: Category,
        severity: Severity,
        message: str,
        node: ast.AST,
        suggestion: str = "",
        cwe: str | None = None,
        fixable: bool = False,
    ) -> None:
        """Add a finding from an AST node."""
        finding = Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            message=message,
            file_path=self.file_path,
            line_number=getattr(node, "lineno", 0),
            column_number=getattr(node, "col_offset", 0),
            end_line=getattr(node, "end_lineno", 0) or getattr(node, "lineno", 0),
            end_column=getattr(node, "end_col_offset", 0)
            or getattr(node, "col_offset", 0),
            context=self.get_line_content(getattr(node, "lineno", 0)),
            code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
            suggestion=suggestion,
            cwe=cwe,
            fixable=fixable,
        )
        self.findings.append(finding)


class SecurityVisitor(PythonASTVisitor):
    """AST visitor for security-related issues."""

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for security issues."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Check for dangerous eval/exec calls
            if func_name in ("eval", "exec"):
                self.add_finding(
                    rule_id="python-security-eval",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    message=f"Use of {func_name}() can lead to code injection",
                    node=node,
                    suggestion=f"Avoid using {func_name}(). Consider safer alternatives.",
                    cwe="CWE-94",
                )

        elif isinstance(node.func, ast.Attribute):
            # Check for os.system calls
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "system"
            ):
                self.add_finding(
                    rule_id="python-security-os-system",
                    category=Category.SECURITY,
                    severity=Severity.HIGH,
                    message="Use of os.system() can lead to command injection",
                    node=node,
                    suggestion="Use subprocess.run() with shell=False instead",
                    cwe="CWE-78",
                )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Check imports for security issues."""
        for alias in node.names:
            if alias.name == "pickle":
                self.add_finding(
                    rule_id="python-security-pickle-import",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    message="pickle module can be unsafe with untrusted data",
                    node=node,
                    suggestion="Consider using json or other safe serialization formats",
                    cwe="CWE-502",
                )

        self.generic_visit(node)


class ComplexityVisitor(PythonASTVisitor):
    """AST visitor for complexity analysis."""

    def __init__(self, file_path: str, config: dict[str, Any]):
        super().__init__(file_path, config)
        self.max_complexity = config.get("max_complexity", 10)
        self.max_nested_depth = config.get("max_nested_depth", 4)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function complexity."""
        complexity = self._calculate_complexity(node)

        if complexity > self.max_complexity:
            self.add_finding(
                rule_id="python-complexity-cyclomatic",
                category=Category.COMPLEXITY,
                severity=Severity.MEDIUM,
                message=f"Function '{node.name}' has cyclomatic complexity of {complexity} (max: {self.max_complexity})",
                node=node,
                suggestion="Consider breaking this function into smaller functions",
            )

        # Check nesting depth
        max_depth = self._calculate_max_depth(node)
        if max_depth > self.max_nested_depth:
            self.add_finding(
                rule_id="python-complexity-nesting",
                category=Category.COMPLEXITY,
                severity=Severity.MEDIUM,
                message=f"Function '{node.name}' has nesting depth of {max_depth} (max: {self.max_nested_depth})",
                node=node,
                suggestion="Consider extracting nested logic into separate functions",
            )

        self.generic_visit(node)

    @staticmethod
    def _calculate_complexity(node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function."""
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.BoolOp, ast.Compare)):
                # Add complexity for boolean operations
                if isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1

        return complexity

    @staticmethod
    def _calculate_max_depth(node: ast.FunctionDef) -> int:
        """Calculate maximum nesting depth in a function."""

        def get_depth(node: ast.AST, current_depth: int = 0) -> int:
            max_depth = current_depth

            for child in ast.iter_child_nodes(node):
                if isinstance(
                    child,
                    (
                        ast.If,
                        ast.While,
                        ast.For,
                        ast.AsyncFor,
                        ast.With,
                        ast.AsyncWith,
                        ast.Try,
                    ),
                ):
                    child_depth = get_depth(child, current_depth + 1)
                    max_depth = max(max_depth, child_depth)
                else:
                    child_depth = get_depth(child, current_depth)
                    max_depth = max(max_depth, child_depth)

            return max_depth

        return get_depth(node)


class StyleVisitor(PythonASTVisitor):
    """AST visitor for style and naming conventions."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function naming conventions."""
        if not self._is_snake_case(node.name) and not node.name.startswith("_"):
            self.add_finding(
                rule_id="python-style-function-naming",
                category=Category.STYLE,
                severity=Severity.MEDIUM,
                message=f"Function '{node.name}' should use snake_case naming",
                node=node,
                suggestion="Use lowercase with underscores (snake_case)",
                fixable=False,
            )

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Check class naming conventions."""
        if not self._is_pascal_case(node.name):
            self.add_finding(
                rule_id="python-style-class-naming",
                category=Category.STYLE,
                severity=Severity.MEDIUM,
                message=f"Class '{node.name}' should use PascalCase naming",
                node=node,
                suggestion="Use PascalCase (first letter of each word capitalized)",
                fixable=False,
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check variable naming conventions."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                # Check for constants (all uppercase)
                if self._is_constant_context(node) and not var_name.isupper():
                    self.add_finding(
                        rule_id="python-style-constant-naming",
                        category=Category.STYLE,
                        severity=Severity.LOW,
                        message=f"Constant '{var_name}' should use UPPER_CASE naming",
                        node=node,
                        suggestion="Use UPPER_CASE for module-level constants",
                        fixable=False,
                    )
                elif not self._is_constant_context(node) and not self._is_snake_case(
                    var_name
                ):
                    self.add_finding(
                        rule_id="python-style-variable-naming",
                        category=Category.STYLE,
                        severity=Severity.LOW,
                        message=f"Variable '{var_name}' should use snake_case naming",
                        node=node,
                        suggestion="Use lowercase with underscores (snake_case)",
                        fixable=False,
                    )

        self.generic_visit(node)

    @staticmethod
    def _is_snake_case(name: str) -> bool:
        """Check if name follows snake_case convention."""
        return re.match(r"^[a-z_][a-z0-9_]*$", name) is not None

    @staticmethod
    def _is_pascal_case(name: str) -> bool:
        """Check if name follows PascalCase convention."""
        return re.match(r"^[A-Z][a-zA-Z0-9]*$", name) is not None

    @staticmethod
    def _is_constant_context(node: ast.Assign) -> bool:
        """Check if assignment is in a context where it's likely a constant."""
        # Simplified check - if assigned a literal value at module level
        if isinstance(node.value, (ast.Constant, ast.Str, ast.Num)):
            return True
        return False


class ImportsVisitor(PythonASTVisitor):
    """AST visitor for import analysis."""

    def __init__(self, file_path: str, config: dict[str, Any]):
        super().__init__(file_path, config)
        self.imports: set[str] = set()
        self.used_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Record imports."""
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports.add(name)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record from imports."""
        for alias in node.names:
            if alias.name != "*":
                name = alias.asname or alias.name
                self.imports.add(name)

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        """Record name usage."""
        if isinstance(node.ctx, (ast.Load, ast.Del)):
            self.used_names.add(node.id)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Record attribute access (module.attribute)."""
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)

        self.generic_visit(node)

    def check_unused_imports(self) -> None:
        """Check for unused imports after visiting the entire tree."""
        unused = self.imports - self.used_names

        for unused_import in unused:
            # This is a simplified approach - we'd need to track the original import nodes
            # for proper line numbers and context
            finding = Finding(
                rule_id="python-imports-unused",
                category=Category.IMPORTS,
                severity=Severity.LOW,
                message=f"Unused import: {unused_import}",
                file_path=self.file_path,
                line_number=1,  # Would need proper tracking
                suggestion=f"Remove unused import '{unused_import}'",
                fixable=True,
            )
            self.findings.append(finding)


class JavaScriptASTAnalyzer(ASTAnalyzer):
    """JavaScript/TypeScript AST analyzer using external parsers."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._setup_js_parser()

    def _setup_js_parser(self) -> None:
        """Set up JavaScript parser (would use esprima, babel, or tree-sitter)."""
        # For now, we'll implement basic regex-based analysis
        # In a full implementation, this would integrate with:
        # - esprima for JavaScript
        # - @babel/parser for modern JS/TS
        # - tree-sitter for universal parsing
        self.parser_available = False

    @staticmethod
    def get_supported_extensions() -> set[str]:
        """Return supported JavaScript/TypeScript file extensions."""
        return {".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze a JavaScript/TypeScript file."""
        findings = []

        if not self.parser_available:
            # Fallback to regex-based analysis
            findings.extend(self._regex_based_analysis(file_path))

        return findings

    def _regex_based_analysis(self, file_path: str) -> list[Finding]:
        """Perform basic regex-based analysis as fallback."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                lines = content.splitlines()
        except (IOError, UnicodeDecodeError):
            return findings

        # Check for console.log statements
        for i, line in enumerate(lines, 1):
            if re.search(r"\bconsole\.log\b", line):
                findings.append(
                    Finding(
                        rule_id="js-style-console-log",
                        category=Category.STYLE,
                        severity=Severity.LOW,
                        message="console.log found - remove before production",
                        file_path=file_path,
                        line_number=i,
                        context=line.strip(),
                        suggestion="Remove console.log or use proper logging",
                        fixable=True,
                    )
                )

            # Check for var usage
            if re.search(r"\bvar\s+\w+", line):
                findings.append(
                    Finding(
                        rule_id="js-style-var-usage",
                        category=Category.STYLE,
                        severity=Severity.MEDIUM,
                        message="Use 'let' or 'const' instead of 'var'",
                        file_path=file_path,
                        line_number=i,
                        context=line.strip(),
                        suggestion="Replace 'var' with 'let' or 'const'",
                        fixable=True,
                    )
                )

        return findings
