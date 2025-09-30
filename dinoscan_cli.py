#!/usr/bin/env python3
"""
DinoScan - Comprehensive Python static analysis toolkit.

A unified command-line interface for running advanced AST-based code analysis.
"""

import argparse
import sys
from pathlib import Path


def create_parser():
    """Create and configure the argument parser for the DinoScan CLI.

    Returns:
        argparse.ArgumentParser: Configured argument parser for command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="DinoScan - Comprehensive Python static analysis toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dinoscan security myproject/                  # Security analysis
  dinoscan all --format json myproject/        # All analyzers, JSON output
  dinoscan --profile strict --exclude tests/   # Strict profile, exclude tests

For more information, visit: https://github.com/DinoAir/DinoScan
        """,
    )

    # Analyzer selection
    parser.add_argument(
        "analyzer",
        choices=["security", "circular", "dead-code", "docs", "duplicates", "all"],
        help="Analyzer to run",
    )

    # Target path
    parser.add_argument("path", type=Path, help="Path to analyze (file or directory)")

    # Output options
    parser.add_argument(
        "--format",
        "-f",
        choices=["console", "json", "xml", "sarif"],
        default="console",
        help="Output format (default: console)",
    )

    parser.add_argument(
        "--output", "-o", type=Path, help="Output file (default: stdout)"
    )

    # Analysis options
    parser.add_argument(
        "--profile",
        choices=["strict", "standard", "relaxed"],
        default="standard",
        help="Analysis profile (default: standard)",
    )
    parser.add_argument("--config", "-c", type=Path, help="Configuration file path")

    parser.add_argument(
        "--exclude",
    )

    return parser


def validate_path(path):
    """
    Validate that the given path exists.
    Prints an error to stderr and returns False if it does not; returns True otherwise.
    """
    if not path.exists():
        print(f"Error: Path '{path}' does not exist.", file=sys.stderr)
        return False
    return True


def load_analyzers(analyzer_name):
    """
    Load and return a list of analyzer instances based on the specified analyzer name.
    Supports individual analyzers and 'all' for all analyzers.
    """
    from analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
    from analyzers.circular_import_analyzer import CircularImportAnalyzer
    from analyzers.dead_code_analyzer import DeadCodeAnalyzer
    from analyzers.doc_quality_analyzer import DocumentationAnalyzer
    from analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer

    if analyzer_name == "all":
        return [
            AdvancedSecurityAnalyzer(),
            CircularImportAnalyzer(),
            DeadCodeAnalyzer(),
            DocumentationAnalyzer(),
            DuplicateCodeAnalyzer(),
        ]
    analyzer_map = {
        "security": AdvancedSecurityAnalyzer,
        "circular": CircularImportAnalyzer,
        "dead-code": DeadCodeAnalyzer,
        "docs": DocumentationAnalyzer,
        "duplicates": DuplicateCodeAnalyzer,
    }
    return [analyzer_map[analyzer_name]()]


def print_run_info(path, analyzers, profile, quiet):
    if not quiet:
        print(f"Running DinoScan analysis on: {path}")
        print(
            f"Analyzers: {', '.join(a.__class__.__name__ for a in analyzers)}"
        )
        print(f"Profile: {profile}")
        print()


def process_analyzer(analyzer, path, verbose):
    if verbose:
        print(f"Running {analyzer.__class__.__name__}...")
    if path.is_file():
        findings = analyzer.analyze_file(str(path))
        files = [str(path)]
    else:
        result = analyzer.analyze_project(str(path))
        findings = result.findings
        files = result.files_analyzed
    return findings, files


def main():
    """Main entry point for DinoScan CLI."""

    parser = create_parser()
    # Remaining CLI logic follows

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-essential output"
    )

    args = parser.parse_args()

    if not validate_path(args.path):
        return 1

    try:
        # Import analyzers here to avoid import issues during setup
        from core.reporter import create_reporter

        analyzers_to_run = load_analyzers(args.analyzer)

        print_run_info(args.path, analyzers_to_run, args.profile, args.quiet)

        all_findings = []
        files_analyzed = []

        for analyzer in analyzers_to_run:
            findings, files = process_analyzer(analyzer, args.path, args.verbose)
            all_findings.extend(findings)
            files_analyzed.extend(files)

        # Create reporter and output results
        from datetime import datetime

        from core.base_analyzer import AnalysisResult

        # Create an AnalysisResult object for the reporter
        result = AnalysisResult(
            analyzer_name=", ".join(a.__class__.__name__ for a in analyzers_to_run),
            version="2.0.0",
            timestamp=datetime.now().isoformat(),
            project_path=str(args.path),
            findings=all_findings,
            files_analyzed=files_analyzed,
        )

        reporter = create_reporter(args.format)
        if args.output:
            reporter.save_results(result, str(args.output))
            if not args.quiet:
                print(f"Report written to: {args.output}")
        else:
            reporter.print_results(result)

        # Return appropriate exit code
        high_severity_count = sum(1 for f in all_findings if f.severity.name == "HIGH")
        if high_severity_count > 0:
            return 1

        medium_severity_count = sum(
            1 for f in all_findings if f.severity.name == "MEDIUM"
        )
        if medium_severity_count > 5:  # Many medium issues
            return 1

        return 0

    except ImportError as e:
        print(f"Error: Failed to import DinoScan modules: {e}", file=sys.stderr)
        print("Please ensure DinoScan is properly installed.", file=sys.stderr)
        return 1
    except Exception as e:
        if args.verbose:
            import traceback

            traceback.print_exc()
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
