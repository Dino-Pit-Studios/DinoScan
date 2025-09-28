#!/usr/bin/env python3
"""
DinoScan CLI - Unified command-line interface for all analyzers.

This module provides a single entry point to run all DinoScan analyzers
with a consistent interface and comprehensive reporting.
"""

import argparse
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

# Import from package structure
try:
    from .analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
    from .analyzers.circular_import_analyzer import CircularImportAnalyzer
    from .analyzers.dead_code_analyzer import DeadCodeAnalyzer
    from .analyzers.doc_quality_analyzer import DocumentationAnalyzer
    from .analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
    from .core.base_analyzer import AnalysisResult, Finding, Severity
    from .core.config_manager import ConfigManager
    from .core.reporter import create_reporter
except ImportError:
    # Fallback for direct execution
    from analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
    from analyzers.circular_import_analyzer import CircularImportAnalyzer
    from analyzers.dead_code_analyzer import DeadCodeAnalyzer
    from analyzers.doc_quality_analyzer import DocumentationAnalyzer
    from analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
    from core.base_analyzer import AnalysisResult, Finding, Severity
    from core.config_manager import ConfigManager
    from core.reporter import create_reporter


class DinoScanCLI:
    """Unified CLI for DinoScan analyzers."""

    def __init__(self):
        self.analyzers = {
            'security': AdvancedSecurityAnalyzer,
            'circular': CircularImportAnalyzer,
            'deadcode': DeadCodeAnalyzer,
            'docs': DocumentationAnalyzer,
            'duplicates': DuplicateCodeAnalyzer,
        }

    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog='dinoscan',
            description='DinoScan - Comprehensive AST-based Python code analysis',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run all analyzers
  dinoscan /path/to/project

  # Run specific analyzers
  dinoscan /path/to/project --analyzers security,deadcode

  # Security-focused scan
  dinoscan /path/to/project --security-only --min-severity high

  # CI/CD integration
  dinoscan /path/to/project --output-format sarif --output-file results.sarif

  # Quick scan with summary
  dinoscan /path/to/project --quick --summary-only
            """
        )

        parser.add_argument(
            'path',
            help='Path to analyze (file or directory)'
        )

        # Analyzer selection
        analyzer_group = parser.add_argument_group('Analyzer Selection')
        analyzer_group.add_argument(
            '--analyzers',
            help='Comma-separated list of analyzers to run (security,circular,deadcode,docs,duplicates)',
            default='all'
        )
        analyzer_group.add_argument(
            '--security-only',
            action='store_true',
            help='Run only security analysis (equivalent to --analyzers security)'
        )
        analyzer_group.add_argument(
            '--exclude',
            help='Comma-separated list of analyzers to exclude'
        )

        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            '--output-format',
            choices=['console', 'json', 'xml', 'sarif'],
            default='console',
            help='Output format (default: console)'
        )
        output_group.add_argument(
            '--output-file',
            help='Output file path (default: stdout)'
        )
        output_group.add_argument(
            '--summary-only',
            action='store_true',
            help='Show only summary statistics'
        )
        output_group.add_argument(
            '--no-colors',
            action='store_true',
            help='Disable colored output'
        )

        # Filtering options
        filter_group = parser.add_argument_group('Filtering Options')
        filter_group.add_argument(
            '--min-severity',
            choices=['low', 'medium', 'high', 'critical'],
            help='Minimum severity level to report'
        )
        filter_group.add_argument(
            '--max-findings',
            type=int,
            help='Maximum number of findings to report per analyzer'
        )
        filter_group.add_argument(
            '--categories',
            help='Comma-separated list of categories to include'
        )

        # Configuration options
        config_group = parser.add_argument_group('Configuration')
        config_group.add_argument(
            '--config',
            help='Path to configuration file'
        )
        config_group.add_argument(
            '--profile',
            choices=['strict', 'standard', 'relaxed'],
            help='Analysis profile (overrides config settings)'
        )

        # Performance options
        perf_group = parser.add_argument_group('Performance')
        perf_group.add_argument(
            '--quick',
            action='store_true',
            help='Quick scan mode (reduced accuracy, faster execution)'
        )
        perf_group.add_argument(
            '--parallel',
            type=int,
            help='Number of parallel processes (default: auto)'
        )
        perf_group.add_argument(
            '--cache',
            action='store_true',
            help='Enable result caching'
        )

        # Miscellaneous
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )
        parser.add_argument(
            '--version',
            action='version',
            version='DinoScan 2.0.0'
        )

        return parser

    def determine_analyzers(self, args: argparse.Namespace) -> list[str]:
        """Determine which analyzers to run based on arguments."""
        if args.security_only:
            return ['security']

        if args.analyzers == 'all':
            analyzers = list(self.analyzers.keys())
        else:
            analyzers = [a.strip() for a in args.analyzers.split(',')]

        if args.exclude:
            excluded = [a.strip() for a in args.exclude.split(',')]
            analyzers = [a for a in analyzers if a not in excluded]

        return analyzers

    @staticmethod
    def apply_profile(config: dict[str, Any], profile: str) -> None:
        """Apply analysis profile settings."""
        profiles = {
            'strict': {
                'global': {'max_findings_per_file': 50},
                'analyzers': {
                    'security': {'min_severity': 'medium'},
                    'documentation': {
                        'require_parameter_docs': True,
                        'require_return_docs': True,
                        'enforce_style': True
                    },
                    'dead_code': {'exclude_public_api': False}
                }
            },
            'standard': {
                'global': {'max_findings_per_file': 20},
                'analyzers': {
                    'security': {'min_severity': 'medium'},
                    'documentation': {'require_parameter_docs': True}
                }
            },
            'relaxed': {
                'global': {'max_findings_per_file': 10},
                'analyzers': {
                    'security': {'min_severity': 'high'},
                    'documentation': {
                        'require_parameter_docs': False,
                        'check_private_methods': False
                    }
                }
            }
        }

        if profile in profiles:
            profile_config = profiles[profile]
            for section, settings in profile_config.items():
                if section not in config:
                    config[section] = {}
                if section == 'analyzers':
                    for analyzer, analyzer_settings in settings.items():
                        if analyzer not in config[section]:
                            config[section][analyzer] = {}
                        config[section][analyzer].update(analyzer_settings)
                else:
                    config[section].update(settings)

    def run_analysis(self, args: argparse.Namespace) -> int:
        """Run the analysis and return exit code."""
        try:
            # Load configuration
            config_manager = ConfigManager(args.config)
            
            # Apply profile if specified
            if args.profile:
                base_config = config_manager.config.copy()
                self.apply_profile(base_config, args.profile)
                config_manager.config = base_config

            # Determine analyzers to run
            analyzer_names = self.determine_analyzers(args)
            
            if args.verbose:
                sys.stderr.write(f"Running analyzers: {', '.join(analyzer_names)}\n")
                sys.stderr.write(f"Analyzing: {args.path}\n")

            # Run analyzers
            all_results = []
            total_findings = 0
            highest_severity = None

            for analyzer_name in analyzer_names:
                if analyzer_name not in self.analyzers:
                    sys.stderr.write(f"Warning: Unknown analyzer '{analyzer_name}'\n")
                    continue

                analyzer_class = self.analyzers[analyzer_name]
                analyzer_config = config_manager.get_analyzer_config(analyzer_name)
                
                # Apply command-line overrides
                if args.quick:
                    analyzer_config['quick_mode'] = True
                if args.parallel:
                    analyzer_config['parallel_workers'] = args.parallel

                analyzer = analyzer_class(analyzer_config)
                
                if args.verbose:
                    sys.stderr.write(f"Running {analyzer_name} analyzer...\n")

                if Path(args.path).is_file():
                    findings = analyzer.analyze_file(args.path)
                    result = AnalysisResult(
                        analyzer_name=analyzer.name,
                        version=analyzer.version,
                        timestamp=datetime.now().isoformat(),
                        project_path=str(Path(args.path).parent)
                    )
                    result.findings = findings
                    result.files_analyzed = [args.path]
                else:
                    result = analyzer.analyze_project(args.path)

                all_results.append(result)
                total_findings += len(result.findings)

                # Track highest severity
                for finding in result.findings:
                    if highest_severity is None or self._severity_priority(finding.severity) > self._severity_priority(highest_severity):
                        highest_severity = finding.severity

            # Combine results
            combined_result = self._combine_results(all_results, args.path)
            
            # Apply filtering
            if args.min_severity:
                combined_result.findings = self._filter_by_severity(
                    combined_result.findings, args.min_severity
                )
            
            if args.categories:
                categories = [c.strip() for c in args.categories.split(',')]
                combined_result.findings = [
                    f for f in combined_result.findings 
                    if f.category.value in categories
                ]

            if args.max_findings:
                combined_result.findings = combined_result.findings[:args.max_findings]

            # Output results
            reporter_config = {
                'use_colors': not args.no_colors and not args.output_file,
                'show_context': not args.summary_only,
                'summary_only': args.summary_only
            }

            reporter = create_reporter(args.output_format, reporter_config)

            if args.output_file:
                reporter.save_results(combined_result, args.output_file)
                if args.verbose:
                    sys.stderr.write(f"Results saved to {args.output_file}\n")
            else:
                reporter.print_results(combined_result)

            # Determine exit code
            stats = combined_result.get_summary_stats()
            if stats.get('critical_severity', 0) > 0:
                return 2
            elif stats.get('high_severity', 0) > 0:
                return 1
            elif stats.get('medium_severity', 0) > 5:  # Many medium issues
                return 1
            else:
                return 0

        except KeyboardInterrupt:
            sys.stderr.write("\nAnalysis interrupted by user\n")
            return 130
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            if args.verbose:
                traceback.print_exc()
            return 1

    def _severity_priority(self, severity: Severity) -> int:
        """Get numeric priority for severity comparison."""
        priority_map = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        return priority_map.get(severity, 0)

    def _filter_by_severity(self, findings: list[Finding], min_severity: str) -> list[Finding]:
        """Filter findings by minimum severity."""
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL
        }
        
        min_sev = severity_map.get(min_severity, Severity.LOW)
        min_priority = self._severity_priority(min_sev)
        
        return [
            f for f in findings 
            if self._severity_priority(f.severity) >= min_priority
        ]

    @staticmethod
    def _combine_results(results: list[AnalysisResult], project_path: str) -> AnalysisResult:
        """Combine multiple analysis results."""
        combined = AnalysisResult(
            analyzer_name="DinoScan",
            version="2.0.0",
            timestamp=datetime.now().isoformat(),
            project_path=project_path
        )

        all_findings = []
        all_files = set()

        for result in results:
            all_findings.extend(result.findings)
            all_files.update(result.files_analyzed)

        combined.findings = all_findings
        combined.files_analyzed = list(all_files)

        return combined


def main() -> None:
    """Main entry point for DinoScan CLI."""
    cli = DinoScanCLI()
    parser = cli.create_parser()
    args = parser.parse_args()
    
    exit_code = cli.run_analysis(args)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()