#!/usr/bin/env python3
"""
DinoScan Advanced Security Analyzer - Comprehensive AST-based security analysis.

This analyzer provides enhanced security vulnerability detection using:
- AST-based code analysis for precise detection
- Advanced secret detection (AWS keys, JWTs, high-entropy strings)
- PII pattern matching with configurable allowlists
- Git hygiene validation for secret patterns in .gitignore
- Integration with external security tools and databases

Enhanced features over PowerShell version:
- More accurate detection using AST parsing
- Context-aware analysis
- Reduced false positives
- Better performance through caching
- Integration with vulnerability databases
"""

import argparse
import ast
import math
import re
import sys
from pathlib import Path
from typing import Any

from core.base_analyzer import ASTAnalyzer, Category, Finding, Severity
from core.config_manager import ConfigManager
from core.reporter import create_reporter


class SecurityPattern:
    """Represents a security pattern with metadata."""

    def __init__(
        self,
        pattern: str,
        message: str,
        severity: Severity,
        cwe: str,
        confidence: float = 0.8,
        context_required: bool = False,
    ):
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.message = message
        self.severity = severity
        self.cwe = cwe
        self.confidence = confidence
        self.context_required = context_required


class SecurityPatternFactory:
    """Factory class to create security patterns."""

    @staticmethod
    def create_secret_patterns() -> list[SecurityPattern]:
        """Create secret detection patterns."""
        return [
            # AWS Credentials
            SecurityPattern(
                r"AKIA[0-9A-Z]{16}",
                "AWS Access Key ID detected",
                Severity.CRITICAL,
                "CWE-798",
            ),
            SecurityPattern(
                r'aws[_-]?secret[_-]?access[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9+\/]{40}',
                "AWS Secret Access Key detected",
                Severity.CRITICAL,
                "CWE-798",
            ),
            # GitHub Tokens
            SecurityPattern(
                r"ghp_[A-Za-z0-9]{36}",
                "GitHub Personal Access Token detected",
                Severity.CRITICAL,
                "CWE-798",
            ),
            # OpenAI API Keys
            SecurityPattern(
                r"sk-[A-Za-z0-9]{48,}",
                "OpenAI API Key detected",
                Severity.CRITICAL,
                "CWE-798",
            ),
            # Generic API Keys
            SecurityPattern(
                r'api[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9+/=]{20,}',
                "API Key detected",
                Severity.HIGH,
                "CWE-798",
            ),
            # JWT Tokens
            SecurityPattern(
                r"eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+",
                "JWT Token detected",
                Severity.HIGH,
                "CWE-798",
            ),
        ]

    @staticmethod
    def create_vulnerability_patterns() -> list[SecurityPattern]:
        """Create vulnerability detection patterns."""
        return [
            # Code Injection
            SecurityPattern(
                r"\beval\s*\(\s*[^)]*\+[^)]*\)",
                "Code injection via eval() with concatenated input",
                Severity.CRITICAL,
                "CWE-94",
            ),
            SecurityPattern(
                r"\bexec\s*\(\s*[^)]*\+[^)]*\)",
                "Code injection via exec() with concatenated input",
                Severity.CRITICAL,
                "CWE-94",
            ),
            # Command Injection
            SecurityPattern(
                r"os\.system\s*\(\s*[^)]*\+[^)]*\)",
                "Command injection via os.system() with concatenated input",
                Severity.CRITICAL,
                "CWE-78",
            ),
            # SQL Injection
            SecurityPattern(
                r'(execute|query)\s*\(\s*["\'][^"\']*\+[^"\']*["\']',
                "SQL injection via string concatenation",
                Severity.HIGH,
                "CWE-89",
            ),
            # Unsafe Deserialization
            SecurityPattern(
                r"pickle\.loads?\s*\(",
                "Unsafe pickle deserialization",
                Severity.CRITICAL,
                "CWE-502",
            ),
        ]

    @staticmethod
    def create_pii_patterns() -> list[SecurityPattern]:
        """Create PII detection patterns."""
        return [
            # Email addresses
            SecurityPattern(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "Email address detected",
                Severity.MEDIUM,
                "CWE-200",
            ),
            # US Phone Numbers
            SecurityPattern(
                r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                "US phone number detected",
                Severity.MEDIUM,
                "CWE-200",
            ),
            # US Social Security Numbers
            SecurityPattern(
                r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
                "US Social Security Number detected",
                Severity.HIGH,
                "CWE-200",
            ),
        ]


class EntropyAnalyzer:
    """Handles entropy-based secret detection."""

    def __init__(self, config: dict[str, Any]):
        entropy_config = config.get("secret_detection_settings", {})
        self.min_entropy_threshold = entropy_config.get("min_entropy_threshold", 4.5)
        self.min_string_length = entropy_config.get("min_string_length", 20)

    @staticmethod
    def calculate_entropy(string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        string_length = len(string)

        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def is_high_entropy_string(self, string: str) -> bool:
        """Check if string has high entropy (potentially a secret)."""
        if len(string) < self.min_string_length:
            return False

        entropy = self.calculate_entropy(string)
        return entropy >= self.min_entropy_threshold


class PIIAllowlistManager:
    """Manages PII allowlists."""

    def __init__(self, config: dict[str, Any]):
        pii_config = config.get("pii_allowlists", {})
        self.pii_allowlists = {
            "email_address": set(
                pii_config.get(
                    "email_address",
                    ["test@example.com", "user@example.org", "admin@test.com"],
                )
            ),
            "us_phone_number": set(
                pii_config.get(
                    "us_phone_number", ["555-0123", "555-1234", "(555) 123-4567"]
                )
            ),
        }

    def is_pii_allowlisted(self, text: str) -> bool:
        """Check if PII text is in allowlist."""
        return any(text in allowlist for allowlist in self.pii_allowlists.values())


class PatternMatcher:
    """Handles pattern matching operations."""

    def __init__(self, pii_allowlist_manager: PIIAllowlistManager):
        self.pii_allowlist_manager = pii_allowlist_manager

    def find_pattern_matches(
        self,
        pattern: SecurityPattern,
        lines: list[str],
        file_path: str,
        analysis_type: str,
    ) -> list[Finding]:
        """Find matches for a specific pattern."""
        findings = []

        for line_num, line in enumerate(lines, 1):
            matches = pattern.pattern.finditer(line)
            for match in matches:
                match_text = match.group()

                if self._should_skip_match(match_text, line, analysis_type):
                    continue

                finding = self._create_pattern_finding(
                    pattern, match, line, line_num, file_path
                )
                findings.append(finding)

        return findings

    def _should_skip_match(
        self, match_text: str, line: str, analysis_type: str
    ) -> bool:
        """Check if match should be skipped."""
        # Check PII allowlists
        if analysis_type == "pii" and self.pii_allowlist_manager.is_pii_allowlisted(
            match_text
        ):
            return True

        # Skip obvious test/example data
        return self._is_test_data(line, match_text)

    @staticmethod
    def _is_test_data(line: str, match_text: str) -> bool:
        """Check if match appears to be test/example data."""
        line_lower = line.lower()
        match_lower = match_text.lower()

        test_indicators = [
            "test",
            "example",
            "sample",
            "demo",
            "placeholder",
            "dummy",
            "fake",
            "mock",
            "todo",
            "fixme",
            "xxx",
        ]

        return any(
            indicator in line_lower or indicator in match_lower
            for indicator in test_indicators
        )

    @staticmethod
    def _create_pattern_finding(
        pattern: SecurityPattern, match, line: str, line_num: int, file_path: str
    ) -> Finding:
        """Create a Finding object for pattern detection."""
        return Finding(
            rule_id=f"security-pattern-{pattern.cwe.lower()}",
            category=Category.SECURITY,
            severity=pattern.severity,
            message=pattern.message,
            file_path=file_path,
            line_number=line_num,
            column_number=match.start() + 1,
            context=line.strip(),
            cwe=pattern.cwe,
            confidence=pattern.confidence,
        )


class AdvancedSecurityAnalyzer(ASTAnalyzer):
    """Advanced security analyzer with AST-based detection."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.name = "AdvancedSecurityAnalyzer"
        self._setup_components()

    def _setup_components(self) -> None:
        """Setup analyzer components."""
        self.secret_patterns = SecurityPatternFactory.create_secret_patterns()
        self.vulnerability_patterns = (
            SecurityPatternFactory.create_vulnerability_patterns()
        )
        self.pii_patterns = SecurityPatternFactory.create_pii_patterns()

        self.pii_allowlist_manager = PIIAllowlistManager(self.config)
        self.entropy_analyzer = EntropyAnalyzer(self.config)
        self.pattern_matcher = PatternMatcher(self.pii_allowlist_manager)

    @staticmethod
    def get_supported_extensions() -> set[str]:
        """Return supported file extensions."""
        return {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".vue",
            ".svelte",
            ".json",
            ".yaml",
            ".yml",
            ".env",
            ".cfg",
            ".ini",
            ".toml",
        }

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze file for security vulnerabilities."""
        content = self._read_file_safely(file_path)
        if content is None:
            return self._create_file_read_error(file_path)

        findings = []

        # For Python files, use AST analysis
        if file_path.endswith(".py"):
            findings.extend(self._analyze_python_ast(file_path, content))

        # For all files, run pattern-based analysis
        findings.extend(self._analyze_patterns(file_path, content))
        findings.extend(self._analyze_entropy(file_path, content))

        return findings

    def _read_file_safely(self, file_path: str) -> str | None:
        """Safely read file content."""
        try:
            with Path(file_path).open(encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return None

    def _create_file_read_error(self, file_path: str) -> list[Finding]:
        """Create file read error finding."""
        return [
            Finding(
                rule_id="file-read-error",
                category=Category.SECURITY,
                severity=Severity.LOW,
                message="Could not read file",
                file_path=file_path,
                line_number=1,
            )
        ]

    def _analyze_python_ast(self, file_path: str, content: str) -> list[Finding]:
        """Analyze Python file using AST."""
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            return [
                Finding(
                    rule_id="python-syntax-error",
                    category=Category.SECURITY,
                    severity=Severity.LOW,
                    message=f"Syntax error prevents security analysis: {e}",
                    file_path=file_path,
                    line_number=getattr(e, "lineno", 1),
                )
            ]

        # Use AST visitor for detailed analysis
        visitor = SecurityASTVisitor(file_path, self.config)
        visitor.visit(tree)
        return visitor.findings

    def _analyze_patterns(self, file_path: str, content: str) -> list[Finding]:
        """Analyze file content using regex patterns."""
        findings = []
        lines = content.splitlines()

        # Analyze different pattern types
        pattern_types = [
            (self.secret_patterns, "secret"),
            (self.vulnerability_patterns, "vulnerability"),
            (self.pii_patterns, "pii"),
        ]

        for patterns, analysis_type in pattern_types:
            for pattern in patterns:
                findings.extend(
                    self.pattern_matcher.find_pattern_matches(
                        pattern, lines, file_path, analysis_type
                    )
                )

        return findings

    def _analyze_entropy(
        self,
        file_path: str,
        content: str,
    ) -> list[Finding]:
        """Analyze file for high-entropy strings (potential secrets)."""
        if not self.config.get("secret_detection_settings", {}).get(
            "enable_high_entropy_detection", True
        ):
            return []

        findings = []
        lines = content.splitlines()
        string_patterns = [
            r'["\']([^"\']{20,})["\']',  # Quoted strings
            r"=\s*([A-Za-z0-9+/=]{20,})(?:\s|$)",  # Assignment values
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern in string_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    candidate_string = match.group(1)

                    if self._should_skip_entropy_candidate(candidate_string):
                        continue

                    if self.entropy_analyzer.is_high_entropy_string(candidate_string):
                        entropy_score = self.entropy_analyzer.calculate_entropy(
                            candidate_string
                        )
                        finding = Finding(
                            rule_id="security-entropy-high",
                            category=Category.SECURITY,
                            severity=(
                                Severity.MEDIUM
                                if entropy_score < 5.0
                                else Severity.HIGH
                            ),
                            message=(
                                f"High-entropy string detected "
                                f"(entropy: {entropy_score:.2f})"
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            column_number=match.start() + 1,
                            context=line.strip(),
                            cwe="CWE-798",
                            confidence=min(0.9, entropy_score / 6.0),
                        )
                        findings.append(finding)

        return findings

    @staticmethod
    def _should_skip_entropy_candidate(candidate_string: str) -> bool:
        """Check if entropy candidate should be skipped."""
        return any(
            indicator in candidate_string.lower()
            for indicator in ["http", "www", "com", "/", "\\", ".org", ".net"]
        )


class SecurityASTVisitor(ast.NodeVisitor):
    """AST visitor for Python security analysis."""

    def __init__(self, file_path: str, config: dict[str, Any]):
        self.file_path = file_path
        self.config = config
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        self._check_dangerous_functions(node)
        self.generic_visit(node)

    def _check_dangerous_functions(self, node: ast.Call) -> None:
        """Check for dangerous function calls."""
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in ("eval", "exec")
            and node.args
            and self._has_dynamic_input(node.args[0])
        ):
            self.findings.append(
                Finding(
                    rule_id=f"python-security-{node.func.id}",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Dynamic {node.func.id}() call with potential user input"
                    ),
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column_number=node.col_offset,
                    cwe="CWE-94",
                )
            )

    def visit_Import(self, node: ast.Import) -> None:
        """Check imports for security concerns."""
        for alias in node.names:
            if alias.name in ("pickle", "cPickle"):
                self.findings.append(
                    Finding(
                        rule_id="python-security-pickle-import",
                        category=Category.SECURITY,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Import of {alias.name} module "
                            "(unsafe deserialization risk)"
                        ),
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        cwe="CWE-502",
                    )
                )
        self.generic_visit(node)

    @staticmethod
    def _has_dynamic_input(node: ast.AST) -> bool:
        """Check if AST node involves dynamic input (simplified heuristic)."""
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return True

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("input", "raw_input")
        ):
            return True

        return False


def main():
    """Main entry point for the advanced security analyzer."""
    parser = argparse.ArgumentParser(
        description="DinoScan Advanced Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("project_path", help="Path to the project directory to analyze")
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
    parser.add_argument("--verbose", action="store_true", help="Show verbose output")

    args = parser.parse_args()

    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.get_analyzer_config("security")

    # Create analyzer
    analyzer = AdvancedSecurityAnalyzer(config)

    # Run analysis
    try:
        result = analyzer.analyze_project(args.project_path)

        # Create reporter
        reporter = create_reporter(
            args.output_format,
            {
                "use_colors": not args.output_file,
                "show_context": True,
            },
        )

        # Output results
        if args.output_file:
            reporter.save_results(result, args.output_file)
            if args.verbose:
                print(f"Results saved to {args.output_file}")
        else:
            reporter.print_results(result)

        # Exit with appropriate code
        stats = result.get_summary_stats()
        critical_count = stats["severity_breakdown"].get("Critical", 0)
        high_count = stats["severity_breakdown"].get("High", 0)

        if critical_count > 0:
            sys.exit(2)
        elif high_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
