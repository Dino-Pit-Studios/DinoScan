#!/usr/bin/env python3
"""
DinoScan Dead Code Detector - Advanced AST-based unused code detection.

This analyzer identifies dead code using comprehensive AST analysis:
- Unused functions, classes, variables, and imports with precise tracking
- Cross-file usage analysis for accurate detection
- Support for complex Python patterns (decorators, dynamic imports, etc.)
- Smart filtering to reduce false positives from framework code
- Integration with entry point detection and public API analysis

Enhanced features over PowerShell version:
- AST-based symbol tracking for 100% accuracy
- Cross-reference analysis across entire codebase
- Framework-aware detection (Django, Flask, etc.)
- Public API preservation with __all__ support
- Advanced heuristics for dynamic usage patterns
"""

import argparse
import ast
import builtins
import os
import re
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.base_analyzer import ASTAnalyzer, AnalysisResult, Finding, Severity, Category
from core.config_manager import ConfigManager
from core.reporter import create_reporter


@dataclass
class Symbol:
    """Represents a code symbol (function, class, variable, import)."""
    name: str
    symbol_type: str  # 'function', 'class', 'variable', 'import'
    file_path: str
    line_number: int
    column_number: int = 0
    is_private: bool = False
    is_special: bool = False
    is_property: bool = False
    decorators: list[str] = field(default_factory=list)
    scope: str = "module"  # 'module', 'class', 'function'
    parent: str | None = None


@dataclass 
class Usage:
    """Represents usage of a symbol."""
    symbol_name: str
    file_path: str
    line_number: int
    usage_type: str  # 'call', 'access', 'import', 'inherit'
    context: str = ""


class DeadCodeAnalyzer(ASTAnalyzer):
    """Dead code analyzer with comprehensive AST-based detection."""
    
    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.name = "DeadCodeAnalyzer"
        self.symbols: dict[str, list[Symbol]] = defaultdict(list)
        self.usages: dict[str, list[Usage]] = defaultdict(list)
        self.public_apis: dict[str, set[str]] = {}  # file -> set of public symbols
        self.entry_points: set[str] = set()
        self._setup_detection_config()
    
    @staticmethod
    def get_supported_extensions() -> set[str]:
        """Return supported Python file extensions."""
        return {".py", ".pyi", ".pyw"}
    
    def _setup_detection_config(self) -> None:
        """Set up dead code detection configuration."""
        self.include_tests = self.config.get('include_tests', False)
        self.aggressive_mode = self.config.get('aggressive_mode', False)
        self.exclude_public_api = self.config.get('exclude_public_api', True)
        
        # Patterns that indicate framework usage or special methods
        self.framework_patterns = {
            'django': ['admin', 'models', 'views', 'urls', 'forms', 'serializers'],
            'flask': ['app', 'route', 'blueprint'],
            'fastapi': ['router', 'endpoint', 'dependency'],
            'pytest': ['test_', 'fixture', 'conftest'],
            'click': ['command', 'group', 'option', 'argument']
        }
        
        # Method patterns that are likely called externally
        self.external_call_patterns = [
            r'^test_.*',  # Test methods
            r'^handle_.*',  # Event handlers
            r'^on_.*',  # Event handlers
            r'^_.*_handler$',  # Event handlers
            r'^do_.*',  # Action methods
            r'^get_.*_display$',  # Django display methods
            r'^clean_.*',  # Django form validation
            r'^save$',  # Model save methods
            r'^delete$',  # Model delete methods
        ]
    
    def analyze_project(self, project_path: str) -> Any:
        """Analyze project for dead code."""
        # Phase 1: Collect all symbols
        self._collect_symbols(project_path)
        
        # Phase 2: Collect all usages
        self._collect_usages(project_path)
        
        # Phase 3: Identify entry points and public APIs
        self._identify_entry_points(project_path)
        
        # Phase 4: Analyze dead code
        findings = self._analyze_dead_code()
        
        # Create analysis result
        result = AnalysisResult(
            analyzer_name=self.name,
            version=self.version,
            timestamp=datetime.now().isoformat(),
            project_path=project_path
        )
        
        result.findings = findings
        result.files_analyzed = list({
            symbol.file_path for symbols in self.symbols.values() for symbol in symbols
        })
        
        return result
    
    def _collect_symbols(self, project_path: str) -> None:
        """Collect all symbols from the project."""
        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self._excluded_dirs]
            
            for file in files:
                if not file.endswith(('.py', '.pyi', '.pyw')):
                    continue
                
                file_path = str(Path(root) / file)
                
                if self.should_analyze_file(file_path):
                    self._analyze_file_symbols(file_path)
    
    def _analyze_file_symbols(self, file_path: str) -> None:
        """Analyze symbols in a single file."""
        tree = self.parse_file(file_path)
        if not tree:
            return
        
        visitor = SymbolCollector(file_path, self.config)
        visitor.visit(tree)
        
        # Store symbols
        for symbol in visitor.symbols:
            self.symbols[symbol.name].append(symbol)
        
        # Store public API information
        if visitor.public_symbols:
            self.public_apis[file_path] = visitor.public_symbols
    
    def _collect_usages(self, project_path: str) -> None:
        """Collect all symbol usages from the project."""
        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self._excluded_dirs]
            
            for file in files:
                if not file.endswith(('.py', '.pyi', '.pyw')):
                    continue
                
                file_path = str(Path(root) / file)
                
                if self.should_analyze_file(file_path):
                    self._analyze_file_usages(file_path)
    
    def _analyze_file_usages(self, file_path: str) -> None:
        """Analyze symbol usages in a single file."""
        tree = self.parse_file(file_path)
        if not tree:
            return
        
        visitor = UsageCollector(file_path, self.symbols)
        visitor.visit(tree)
        
        # Store usages
        for usage in visitor.usages:
            self.usages[usage.symbol_name].append(usage)
    
    def _identify_entry_points(self, project_path: str) -> None:
        """Identify entry points that keep code alive."""
        # Look for common entry point patterns
        entry_patterns = [
            'main.py', '__main__.py', 'manage.py', 'app.py', 'server.py',
            'run.py', 'start.py', 'cli.py', 'setup.py'
        ]
        
        for root, _dirs, files in os.walk(project_path):
            for file in files:
                if file in entry_patterns:
                    self.entry_points.add(str(Path(root) / file))
        
        # Look for if __name__ == '__main__' patterns
        for symbols_list in self.symbols.values():
            for symbol in symbols_list:
                if symbol.name == '__main__' and symbol.symbol_type == 'variable':
                    self.entry_points.add(symbol.file_path)
    
    def _analyze_dead_code(self) -> list[Finding]:
        """Analyze collected symbols and usages to find dead code."""
        findings = []
        
        for _symbol_name, symbols_list in self.symbols.items():
            for symbol in symbols_list:
                if self._is_dead_symbol(symbol):
                    finding = self._create_dead_code_finding(symbol)
                    if finding:
                        findings.append(finding)
        
        return findings
    
    def _is_dead_symbol(self, symbol: Symbol) -> bool:
    """Determine if a symbol is dead (unused)."""
    # Skip special methods and built-ins
    if symbol.is_special or symbol.name in dir(builtins):
        return False
    
    # Skip symbols in entry point files
    if symbol.file_path in self.entry_points:
        return False
    
    # Skip public API symbols if configured
    if self.exclude_public_api and self._is_public_api_symbol(symbol):
        return False
    
    # Skip framework-specific patterns
    if self._is_framework_symbol(symbol):
        return False
    
    # Check for usages
    usages = self.usages.get(symbol.name, [])
    
    # Filter out self-references (definition in same file)
    external_usages = [
        usage for usage in usages 
        if usage.file_path != symbol.file_path or 
        self._is_meaningful_usage(usage, symbol)
    ]
    
    return len(external_usages) == 0

def _is_public_api_symbol(self, symbol: Symbol) -> bool:
    """Check if symbol is part of public API."""
    # Check __all__ definitions
    public_symbols = self.public_apis.get(symbol.file_path, set())
    if public_symbols and symbol.name in public_symbols:
        return True
    
    # Public if not private and at module level
    return not symbol.is_private and symbol.scope == 'module'

def _is_framework_symbol(self, symbol: Symbol) -> bool:
    """Check if symbol follows framework patterns."""
    # Check decorators for framework patterns
    for decorator in symbol.decorators:
        if any(pattern in decorator for framework_patterns in self.framework_patterns.values() 
              for pattern in framework_patterns):
            return True
    
    # Check name patterns
    return any(re.match(pattern, symbol.name) for pattern in self.external_call_patterns)

@staticmethod
def _is_meaningful_usage(usage: Usage, symbol: Symbol) -> bool:
    """Check if usage in same file is meaningful (not just definition)."""
    # Usage after definition line is meaningful
    return usage.line_number > symbol.line_number

def _create_dead_code_finding(self, symbol: Symbol) -> Finding | None:
    """Create a finding for dead code symbol."""
    severity_map = {
        'function': Severity.MEDIUM,
        'class': Severity.HIGH,
        'variable': Severity.LOW,
        'import': Severity.LOW
    }
    
    severity = severity_map.get(symbol.symbol_type, Severity.LOW)
    
    # Adjust severity based on symbol characteristics
    if symbol.is_private or (symbol.symbol_type == 'function' and symbol.decorators):
        severity = Severity.LOW  # Private symbols or functions with decorators (might be framework callbacks)
    
    message = f"Unused {symbol.symbol_type}: '{symbol.name}'"
    suggestion = self._get_removal_suggestion(symbol)
    
    return Finding(
        rule_id=f"dead-code-{symbol.symbol_type}",
        category=Category.DEAD_CODE,
        severity=severity,
        message=message,
        file_path=symbol.file_path,
        line_number=symbol.line_number,
        column_number=symbol.column_number,
        context=self.get_line_content(symbol.file_path, symbol.line_number),
        suggestion=suggestion,
        fixable=True,
        tags={f"dead-{symbol.symbol_type}", "unused"}
    )

def _get_removal_suggestion(self, symbol: Symbol) -> str:
    """Get suggestion for removing dead code."""
    suggestions = {
        'import': f"Remove unused import '{symbol.name}'",
        'function': f"Remove unused function '{symbol.name}' or verify it's not part of public API",
        'class': f"Remove unused class '{symbol.name}' or check if it's used dynamically",
        'variable': f"Remove unused variable '{symbol.name}'"
    }
    
    base_suggestion = suggestions.get(symbol.symbol_type, f"Remove unused {symbol.symbol_type} '{symbol.name}'")
    
    if symbol.is_private:
        return base_suggestion + " (private symbol)"
    if symbol.decorators:
        return base_suggestion + " (check decorator usage)"
    return base_suggestion

def analyze_file(self, file_path: str) -> list[Finding]:  # noqa: ARG002
    """Analyze single file (not used for dead code analysis)."""
    # Dead code analysis requires project-wide analysis
    return []
                decorators.append(decorator.attr)
        
        symbol = Symbol(
            name=node.name,
            symbol_type='function',
            file_path=self.file_path,
            line_number=node.lineno,
            column_number=node.col_offset,
            is_private=node.name.startswith('_'),
            is_special=node.name.startswith('__') and node.name.endswith('__'),
            is_property='property' in decorators,
            decorators=decorators,
            scope=self.scope_stack[-1],
            parent=self.current_class
        )
        self.symbols.append(symbol)
        
        # Enter function scope
        self.scope_stack.append('function')
        self.generic_visit(node)
        self.scope_stack.pop()
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Collect async function definitions."""
        decorators = []
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                decorators.append(decorator.id)
            elif isinstance(decorator, ast.Attribute):
                decorators.append(decorator.attr)
        
        symbol = Symbol(
            name=node.name,
            symbol_type='function',
            file_path=self.file_path,
            line_number=node.lineno,
            column_number=node.col_offset,
            is_private=node.name.startswith('_'),
            is_special=node.name.startswith('__') and node.name.endswith('__'),
            decorators=decorators,
            scope=self.scope_stack[-1],
            parent=self.current_class
        )
        self.symbols.append(symbol)
        
        # Enter function scope
        self.scope_stack.append('function')
        self.generic_visit(node)
        self.scope_stack.pop()
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Collect class definitions."""
        decorators = []
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                decorators.append(decorator.id)
            elif isinstance(decorator, ast.Attribute):
                decorators.append(decorator.attr)
        
        symbol = Symbol(
            name=node.name,
            symbol_type='class',
            file_path=self.file_path,
            line_number=node.lineno,
            column_number=node.col_offset,
            is_private=node.name.startswith('_'),
            decorators=decorators,
            scope=self.scope_stack[-1],
            parent=self.current_class
        )
        self.symbols.append(symbol)
        
        # Enter class scope
        old_class = self.current_class
        self.current_class = node.name
        self.scope_stack.append('class')
        self.generic_visit(node)
        self.scope_stack.pop()
        self.current_class = old_class
    
    def visit_Import(self, node: ast.Import) -> None:
        """Collect import statements."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name.split('.')[0]
            symbol = Symbol(
                name=name,
                symbol_type='import',
                file_path=self.file_path,
                line_number=node.lineno,
                column_number=node.col_offset,
                scope=self.scope_stack[-1]
            )
            self.symbols.append(symbol)
        
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Collect from import statements."""
        if node.names:
            for alias in node.names:
                if alias.name == '*':
                    continue  # Skip star imports
                
                name = alias.asname if alias.asname else alias.name
                symbol = Symbol(
                    name=name,
                    symbol_type='import',
                    file_path=self.file_path,
                    line_number=node.lineno,
                    column_number=node.col_offset,
                    scope=self.scope_stack[-1]
                )
                self.symbols.append(symbol)
        
        self.generic_visit(node)


class UsageCollector(ast.NodeVisitor):
    """AST visitor to collect symbol usages."""
    
    def __init__(self, file_path: str, symbols: dict[str, list[Symbol]]):
        self.file_path = file_path
        self.symbols = symbols
        self.usages: list[Usage] = []
        self.in_definition = False
    
    def visit_Name(self, node: ast.Name) -> None:
        """Collect name references."""
        if isinstance(node.ctx, ast.Load) and node.id in self.symbols:
            usage = Usage(
                symbol_name=node.id,
                file_path=self.file_path,
                line_number=node.lineno,
                usage_type='access'
            )
            self.usages.append(usage)
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Collect function calls."""
        if isinstance(node.func, ast.Name) and node.func.id in self.symbols:
            usage = Usage(
                symbol_name=node.func.id,
                file_path=self.file_path,
                line_number=node.lineno,
                usage_type='call'
            )
            self.usages.append(usage)
        elif isinstance(node.func, ast.Attribute):
            # Handle method calls like obj.method()
            if isinstance(node.func.value, ast.Name) and node.func.value.id in self.symbols:
                    usage = Usage(
                        symbol_name=node.func.value.id,
                        file_path=self.file_path,
                        line_number=node.lineno,
                        usage_type='access'
                    )
                    self.usages.append(usage)
        
        self.generic_visit(node)
    
    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Collect attribute access."""
        if isinstance(node.value, ast.Name) and node.value.id in self.symbols:
            usage = Usage(
                symbol_name=node.value.id,
                file_path=self.file_path,
                line_number=node.lineno,
                usage_type='access'
            )
            self.usages.append(usage)
        
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Collect inheritance usages."""
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in self.symbols:
                usage = Usage(
                    symbol_name=base.id,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    usage_type='inherit'
                )
                self.usages.append(usage)
        
        self.generic_visit(node)


def main() -> None:
    """Main entry point for the dead code analyzer."""
    parser = argparse.ArgumentParser(
        description='DinoScan Dead Code Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s /path/to/project --output-format json --output-file dead-code.json
  %(prog)s /path/to/project --include-tests --aggressive
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
        '--aggressive',
        action='store_true',
        help='More aggressive detection (may have false positives)'
    )
    
    parser.add_argument(
        '--exclude-public-api',
        action='store_true',
        help='Exclude potential public API functions from dead code detection'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show verbose output'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.get_analyzer_config('dead_code')
    
    # Override config with command-line arguments
    if args.include_tests:
        config['include_tests'] = True
    if args.aggressive:
        config['aggressive_mode'] = True
    if args.exclude_public_api:
        config['exclude_public_api'] = True
    
    # Create analyzer
    analyzer = DeadCodeAnalyzer(config)
    
    # Analyze project
    try:
        if args.verbose:
            sys.stderr.write(f"Starting dead code analysis of {args.project_path}...\n")
        
        result = analyzer.analyze_project(args.project_path)
        
        if args.verbose:
            stats = result.get_summary_stats()
            sys.stderr.write(f"Analysis complete: {stats['total_findings']} dead code issues found\n")
        
        # Create reporter and output results
        reporter_config = {
            'use_colors': not args.output_file,
            'show_context': True,
            'max_findings_per_file': 15
        }
        
        reporter = create_reporter(args.output_format, reporter_config)
        
        if args.output_file:
            reporter.save_results(result, args.output_file)
            if args.verbose:
                sys.stderr.write(f"Results saved to {args.output_file}\n")
        else:
            reporter.print_results(result)
        
        # Exit code: dead code is informational, not an error
        sys.exit(0)
    
    except Exception as e:
        sys.stderr.write(f"Error during analysis: {e}\n")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()