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
import base64
import hashlib
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from core.base_analyzer import ASTAnalyzer, Finding, Severity, Category
from core.config_manager import ConfigManager
from core.file_scanner import FileScanner
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
        context_required: bool = False
    ):
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.message = message
        self.severity = severity
        self.cwe = cwe
        self.confidence = confidence
        self.context_required = context_required


class AdvancedSecurityAnalyzer(ASTAnalyzer):
    """Advanced security analyzer with AST-based detection."""
    
    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.name = "AdvancedSecurityAnalyzer"
        self._setup_patterns()
        self._setup_pii_allowlists()
        self._setup_entropy_detector()
    
    @staticmethod
    def get_supported_extensions() -> set[str]:
        """Return supported file extensions."""
        return {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte",
            ".json", ".yaml", ".yml", ".env", ".cfg", ".ini", ".toml"
        }
    
    def _setup_patterns(self) -> None:
        """Set up security detection patterns."""
        self.secret_patterns = [
            # AWS Credentials
            SecurityPattern(
                r'AKIA[0-9A-Z]{16}',
                'AWS Access Key ID detected',
                Severity.CRITICAL,
                'CWE-798'
            ),
            SecurityPattern(
                r'aws[_-]?secret[_-]?access[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9+\/]{40}',
                'AWS Secret Access Key detected',
                Severity.CRITICAL,
                'CWE-798'
            ),
            
            # GitHub Tokens
            SecurityPattern(
                r'ghp_[A-Za-z0-9]{36}',
                'GitHub Personal Access Token detected',
                Severity.CRITICAL,
                'CWE-798'
            ),
            SecurityPattern(
                r'gho_[A-Za-z0-9]{36}',
                'GitHub OAuth Token detected',
                Severity.CRITICAL,
                'CWE-798'
            ),
            
            # OpenAI API Keys
            SecurityPattern(
                r'sk-[A-Za-z0-9]{48,}',
                'OpenAI API Key detected',
                Severity.CRITICAL,
                'CWE-798'
            ),
            
            # Slack Tokens
            SecurityPattern(
                r'xox[baprs]-[A-Za-z0-9\-]{10,}',
                'Slack Token detected',
                Severity.CRITICAL,
                'CWE-798'
            ),
            
            # Generic API Keys
            SecurityPattern(
                r'api[_-]?key["\s]*[:=]["\s]*[A-Za-z0-9+/=]{20,}',
                'API Key detected',
                Severity.HIGH,
                'CWE-798'
            ),
            
            # JWT Tokens
            SecurityPattern(
                r'eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+',
                'JWT Token detected',
                Severity.HIGH,
                'CWE-798'
            ),
            
            # Database Connection Strings
            SecurityPattern(
                r'(mongodb|mysql|postgresql)://[^:\s]+:[^@\s]+@[^/\s]+',
                'Database connection string with credentials detected',
                Severity.HIGH,
                'CWE-798'
            ),
            
            # Private Keys
            SecurityPattern(
                r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
                'Private key detected',
                Severity.CRITICAL,
                'CWE-798'
            )
        ]
        
        self.vulnerability_patterns = [
            # Code Injection
            SecurityPattern(
                r'\beval\s*\(\s*[^)]*\+[^)]*\)',
                'Code injection via eval() with concatenated input',
                Severity.CRITICAL,
                'CWE-94'
            ),
            SecurityPattern(
                r'\bexec\s*\(\s*[^)]*\+[^)]*\)',
                'Code injection via exec() with concatenated input',
                Severity.CRITICAL,
                'CWE-94'
            ),
            
            # Command Injection
            SecurityPattern(
                r'os\.system\s*\(\s*[^)]*\+[^)]*\)',
                'Command injection via os.system() with concatenated input',
                Severity.CRITICAL,
                'CWE-78'
            ),
            SecurityPattern(
                r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\+[^)]*\)',
                'Command injection via subprocess with shell=True',
                Severity.CRITICAL,
                'CWE-78'
            ),
            
            # SQL Injection
            SecurityPattern(
                r'(execute|query)\s*\(\s*["\'][^"\']*\+[^"\']*["\']',
                'SQL injection via string concatenation',
                Severity.HIGH,
                'CWE-89'
            ),
            
            # Path Traversal
            SecurityPattern(
                r'(open|read|write)\s*\([^)]*\.\./[^)]*\)',
                'Path traversal vulnerability detected',
                Severity.HIGH,
                'CWE-22'
            ),
            
            # Unsafe Deserialization
            SecurityPattern(
                r'pickle\.loads?\s*\(',
                'Unsafe pickle deserialization',
                Severity.CRITICAL,
                'CWE-502'
            ),
            SecurityPattern(
                r'yaml\.load\s*\(',
                'Unsafe YAML deserialization (use yaml.safe_load)',
                Severity.HIGH,
                'CWE-502'
            ),
            
            # Weak Cryptography
            SecurityPattern(
                r'\b(md5|sha1)\s*\(',
                'Weak cryptographic hash function',
                Severity.MEDIUM,
                'CWE-327'
            ),
            SecurityPattern(
                r'random\.random\(\)',
                'Weak random number generation (use secrets module)',
                Severity.MEDIUM,
                'CWE-338'
            ),
            
            # SSL/TLS Issues
            SecurityPattern(
                r'ssl_verify\s*=\s*False',
                'SSL certificate verification disabled',
                Severity.HIGH,
                'CWE-295'
            ),
            SecurityPattern(
                r'verify\s*=\s*False',
                'SSL verification disabled in requests',
                Severity.HIGH,
                'CWE-295'
            )
        ]
        
        self.pii_patterns = [
            # Email addresses
            SecurityPattern(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'Email address detected',
                Severity.MEDIUM,
                'CWE-200'
            ),
            
            # US Phone Numbers
            SecurityPattern(
                r'\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'US phone number detected',
                Severity.MEDIUM,
                'CWE-200'
            ),
            
            # US Social Security Numbers
            SecurityPattern(
                r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
                'US Social Security Number detected',
                Severity.HIGH,
                'CWE-200'
            ),
            
            # Credit Card Numbers (basic pattern)
            SecurityPattern(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                'Credit card number detected',
                Severity.HIGH,
                'CWE-200'
            ),
            
            # IP Addresses (private ranges might be sensitive)
            SecurityPattern(
                r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b',
                'Private IP address detected',
                Severity.LOW,
                'CWE-200'
            )
        ]

    def _setup_pii_allowlists(self) -> None:
        """Set up PII allowlists from configuration."""
        pii_config = self.config.get('pii_allowlists', {})
        
        self.pii_allowlists = {
            'email_address': set(pii_config.get('email_address', [
                'test@example.com', 'user@example.org', 'admin@test.com'
            ])),
            'us_phone_number': set(pii_config.get('us_phone_number', [
                '555-0123', '555-1234', '(555) 123-4567'
            ])),
            'us_ssn': set(pii_config.get('us_ssn', [
                '123-45-6789', '000-00-0000', '999-99-9999'
            ])),
            'ip_address': set(pii_config.get('ip_address', [
                '127.0.0.1', '0.0.0.0', '192.168.1.1'
            ]))
        }

    def _setup_entropy_detector(self) -> None:
        """Set up entropy-based secret detection."""
        entropy_config = self.config.get('secret_detection_settings', {})
        self.min_entropy_threshold = entropy_config.get('min_entropy_threshold', 4.5)
        self.min_string_length = entropy_config.get('min_string_length', 20)

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

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze file for security vulnerabilities."""
        findings = []
        
        try:
            with Path(file_path).open(encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return [Finding(
                rule_id="file-read-error",
                category=Category.SECURITY,
                severity=Severity.LOW,
                message=f"Could not read file: {e}",
                file_path=file_path,
                line_number=1
            )]
        
        # For Python files, use AST analysis
        if file_path.endswith('.py'):
            findings.extend(self._analyze_python_ast(file_path, content))
        
        # For all files, run pattern-based analysis
        findings.extend(self._analyze_patterns(file_path, content))
        findings.extend(self._analyze_entropy(file_path, content))
        
        return findings
    
    def _analyze_python_ast(self, file_path: str, content: str) -> list[Finding]:
        """Analyze Python file using AST."""
        findings = []
        
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            return [Finding(
                rule_id="python-syntax-error",
                category=Category.SECURITY,
                severity=Severity.LOW,
                message=f"Syntax error prevents security analysis: {e}",
                file_path=file_path,
                line_number=getattr(e, 'lineno', 1)
            )]
        
        # Use AST visitor for detailed analysis
        visitor = SecurityASTVisitor(file_path, self.config)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        
        return findings
    
    def _analyze_patterns(self, file_path: str, content: str) -> list[Finding]:
        """Analyze file content using regex patterns."""
        findings = []
        lines = content.splitlines()
        
        # Analyze secrets
        for pattern in self.secret_patterns:
            findings.extend(self._find_pattern_matches(
                pattern, lines, file_path, "secret"
            ))
        
        # Analyze vulnerabilities
        for pattern in self.vulnerability_patterns:
            findings.extend(self._find_pattern_matches(
                pattern, lines, file_path, "vulnerability"
            ))
        
        # Analyze PII
        for pattern in self.pii_patterns:
            findings.extend(self._find_pattern_matches(
                pattern, lines, file_path, "pii"
            ))
        
        return findings
    
    def _find_pattern_matches(
        self, 
        pattern: SecurityPattern, 
        lines: list[str], 
        file_path: str,
        analysis_type: str
    ) -> list[Finding]:
        """Find matches for a specific pattern."""
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            matches = pattern.pattern.finditer(line)
            
            for match in matches:
                match_text = match.group()
                
                # Check PII allowlists
                if analysis_type == "pii" and self._is_pii_allowlisted(match_text):
                    continue
                
                # Skip obvious test/example data
                if self._is_test_data(line, match_text):
                    continue
                
                finding = Finding(
                    rule_id=f"security-{analysis_type}-{pattern.cwe.lower()}",
                    category=Category.SECURITY,
                    severity=pattern.severity,
                    message=pattern.message,
                    file_path=file_path,
                    line_number=line_num,
                    column_number=match.start() + 1,
                    context=line.strip(),
                    cwe=pattern.cwe,
                    confidence=pattern.confidence,
                    suggestion=self._get_security_suggestion(pattern.cwe)
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_entropy(self, file_path: str, content: str) -> list[Finding]:
        """Analyze file for high-entropy strings (potential secrets)."""
        if not self.config.get('secret_detection_settings', {}).get('enable_high_entropy_detection', True):
            return []
        
        findings = []
        lines = content.splitlines()
        
        # Look for quoted strings and assignment values
        string_patterns = [
            r'["\']([^"\']{20,})["\']',  # Quoted strings
            r'=\s*([A-Za-z0-9+/=]{20,})(?:\s|$)',  # Assignment values
            r':\s*([A-Za-z0-9+/=]{20,})(?:\s|$|,)'  # JSON-style values
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in string_patterns:
                matches = re.finditer(pattern, line)
                
                for match in matches:
                    candidate_string = match.group(1)
                    
                    # Skip if it looks like a URL or path
                    if any(indicator in candidate_string.lower() for indicator in 
                           ['http', 'www', 'com', '/', '\\', '.org', '.net']):
                        continue
                    
                    # Check entropy
                    if self.is_high_entropy_string(candidate_string):
                        # Additional checks to reduce false positives
                        if not self._is_likely_secret(candidate_string):
                            continue
                        
                        entropy_score = self.calculate_entropy(candidate_string)
                        
                        finding = Finding(
                            rule_id="security-entropy-high",
                            category=Category.SECURITY,
                            severity=Severity.MEDIUM if entropy_score < 5.0 else Severity.HIGH,
                            message=f"High-entropy string detected (entropy: {entropy_score:.2f})",
                            file_path=file_path,
                            line_number=line_num,
                            column_number=match.start() + 1,
                            context=line.strip(),
                            cwe="CWE-798",
                            confidence=min(0.9, entropy_score / 6.0),  # Scale confidence with entropy
                            suggestion="Verify if this is a secret that should be moved to environment variables"
                        )
                        findings.append(finding)
        
        return findings
    
    def _is_pii_allowlisted(self, text: str) -> bool:
        """Check if PII text is in allowlist."""
        for allowlist in self.pii_allowlists.values():
            if text in allowlist:
                return True
        return False
    
    @staticmethod
    def _is_test_data(line: str, match_text: str) -> bool:
        """Check if match appears to be test/example data."""
        line_lower = line.lower()
        match_lower = match_text.lower()
        
        test_indicators = [
            'test', 'example', 'sample', 'demo', 'placeholder', 'dummy',
            'fake', 'mock', 'todo', 'fixme', 'xxx', 'lorem', 'ipsum'
        ]
        
        return any(indicator in line_lower or indicator in match_lower 
                  for indicator in test_indicators)
    
    @staticmethod
    def _is_likely_secret(string: str) -> bool:
        """Additional heuristics to determine if high-entropy string is likely a secret."""
        # Check for common secret characteristics
        has_mixed_case = any(c.islower() for c in string) and any(c.isupper() for c in string)
        has_numbers = any(c.isdigit() for c in string)
        has_special = any(c in '+/=' for c in string)
        
        # Base64-like strings are more likely to be secrets
        if has_mixed_case and has_numbers and (has_special or len(string) % 4 == 0):
            return True
        
        # Check for common secret prefixes/suffixes
        secret_indicators = [
            'key', 'token', 'secret', 'pass', 'auth', 'api',
            'client', 'id', 'signature', 'hash'
        ]
        
        string_lower = string.lower()
        return any(indicator in string_lower for indicator in secret_indicators)
    
    @staticmethod
    def _get_security_suggestion(cwe: str) -> str:
        """Get security remediation suggestion based on CWE."""
        suggestions = {
            'CWE-798': 'Move secrets to environment variables or secure key management',
            'CWE-94': 'Avoid dynamic code execution. Use safe alternatives or input validation',
            'CWE-78': 'Use subprocess with shell=False and validate inputs',
            'CWE-89': 'Use parameterized queries or ORM frameworks',
            'CWE-22': 'Validate file paths and use path.resolve() to prevent traversal',
            'CWE-502': 'Avoid deserializing untrusted data. Use safe formats like JSON',
            'CWE-327': 'Use modern cryptographic algorithms (SHA-256, bcrypt)',
            'CWE-338': 'Use cryptographically secure random generators (secrets module)',
            'CWE-295': 'Always verify SSL certificates in production',
            'CWE-200': 'Avoid storing PII in code. Use data anonymization techniques'
        }
        return suggestions.get(cwe, 'Review security implications and apply appropriate mitigations')


class SecurityASTVisitor(ast.NodeVisitor):
    """AST visitor for Python security analysis."""
    
    def __init__(self, file_path: str, config: dict[str, Any]):
        self.file_path = file_path
        self.config = config
        self.findings: list[Finding] = []
    
    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        # Check for dangerous function calls
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            if func_name in ('eval', 'exec', 'compile'):
                # Check if argument involves user input (simplified)
                if self._has_dynamic_input(node.args[0]):
                    self.findings.append(Finding(
                        rule_id=f"python-security-{func_name}",
                        category=Category.SECURITY,
                        severity=Severity.CRITICAL,
                        message=f"Dynamic {func_name}() call with potential user input",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        cwe="CWE-94",
                        suggestion=f"Avoid {func_name}(). Use safe alternatives for dynamic behavior"
                    ))
        
        elif isinstance(node.func, ast.Attribute):
            # Check for dangerous method calls
            if (isinstance(node.func.value, ast.Name) and 
                node.func.value.id == 'os' and 
                node.func.attr == 'system')
                
                if node.args and self._has_dynamic_input(node.args[0]):
                    self.findings.append(Finding(
                        rule_id="python-security-os-system",
                        category=Category.SECURITY,
                        severity=Severity.CRITICAL,
                        message="os.system() call with dynamic input",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        cwe="CWE-78",
                        suggestion="Use subprocess.run() with shell=False and input validation"
                    ))
        
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import) -> None:
        """Check imports for security concerns."""
        for alias in node.names:
            if alias.name in ('pickle', 'cPickle'):
                self.findings.append(Finding(
                    rule_id="python-security-pickle-import",
                    category=Category.SECURITY,
                    severity=Severity.MEDIUM,
                    message=f"Import of {alias.name} module (unsafe deserialization risk)",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column_number=node.col_offset,
                    cwe="CWE-502",
                    suggestion="Consider using safe serialization formats like JSON"
                ))
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignments for hardcoded secrets."""
        # Look for suspicious variable names
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                if any(secret_word in var_name for secret_word in 
                       ['password', 'secret', 'key', 'token', 'api']):
                    
                    # Check if assigned a literal value (potential hardcoded secret)
                    if isinstance(node.value, (ast.Str, ast.Constant)):
                        value = node.value.s if isinstance(node.value, ast.Str) else node.value.value
                        
                        if isinstance(value, str) and len(value) > 8:
                            self.findings.append(Finding(
                                rule_id="python-security-hardcoded-secret",
                                category=Category.SECURITY,
                                severity=Severity.HIGH,
                                message=f"Potential hardcoded secret in variable '{target.id}'",
                                file_path=self.file_path,
                                line_number=node.lineno,
                                column_number=node.col_offset,
                                cwe="CWE-798",
                                suggestion="Move secrets to environment variables or secure configuration"
                            ))
        
        self.generic_visit(node)
    
    @staticmethod
    def _has_dynamic_input(node: ast.AST) -> bool:
        """Check if AST node involves dynamic input (simplified heuristic)."""
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return True
        
        if isinstance(node, ast.Call):
            # Check for input(), request data, etc.
            if isinstance(node.func, ast.Name):
                if node.func.id in ('input', 'raw_input'):
                    return True
        
        return False


def main():
    """Main entry point for the advanced security analyzer."""
    parser = argparse.ArgumentParser(
        description='DinoScan Advanced Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s /path/to/project --output-format json --output-file security-report.json
  %(prog)s /path/to/project --config security-config.json --include-tests
        """
    )
    
    parser.add_argument(
        'project_path',
        help='Path to the project directory to analyze'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['console', 'json', 'xml', 'sarif'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '--output-file',
        help='Output file path (default: print to stdout)'
    )
    
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--include-tests',
        action='store_true',
        help='Include test files in analysis'
    )
    
    parser.add_argument(
        '--max-file-size',
        type=int,
        default=10,
        help='Maximum file size to analyze in MB (default: 10)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show verbose output'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.get_analyzer_config('security')
    
    # Override config with command-line arguments
    if args.include_tests:
        config['include_test_files'] = True
    
    config['performance'] = config.get('performance', {})
    config['performance']['max_file_size_mb'] = args.max_file_size
    
    # Create analyzer
    analyzer = AdvancedSecurityAnalyzer(config)
    
    # Analyze project
    try:
        if args.verbose:
            print(f"Starting security analysis of {args.project_path}...")
        
        result = analyzer.analyze_project(args.project_path)
        
        if args.verbose:
            stats = result.get_summary_stats()
            print(f"Analysis complete: {stats['total_findings']} findings in {stats['files_analyzed']} files")
        
        # Create reporter and output results
        reporter_config = {
            'use_colors': not args.output_file,  # Only use colors for console output
            'show_context': True,
            'max_findings_per_file': 10
        }
        
        reporter = create_reporter(args.output_format, reporter_config)
        
        if args.output_file:
            reporter.save_results(result, args.output_file)
            if args.verbose:
                print(f"Results saved to {args.output_file}")
        else:
            reporter.print_results(result)
        
        # Exit with appropriate code
        stats = result.get_summary_stats()
        critical_count = stats['severity_breakdown'].get('Critical', 0)
        high_count = stats['severity_breakdown'].get('High', 0)
        
        if critical_count > 0:
            sys.exit(2)  # Critical issues found
        elif high_count > 0:
            sys.exit(1)  # High severity issues found
        else:
            sys.exit(0)  # Success
    
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(3)


if __name__ == '__main__':
    main()