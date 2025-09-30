#!/usr/bin/env python3
"""
DinoScan - Comprehensive Python static analysis toolkit.

A unified command-line interface for running advanced AST-based code analysis.
"""

import argparse
import sys
from pathlib import Path


def main():
    """Main entry point for DinoScan CLI."""

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
        action="append",
        help="Exclude pattern (can be used multiple times)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-essential output"
    )

    args = parser.parse_args()

    # Validate path exists
    if not args.path.exists():
        print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
        return 1

    try:
        # Import analyzers here to avoid import issues during setup
        from analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
        from analyzers.circular_import_analyzer import CircularImportAnalyzer
        from analyzers.dead_code_analyzer import DeadCodeAnalyzer
        from analyzers.doc_quality_analyzer import DocumentationAnalyzer
        from analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
        from core.reporter import create_reporter

        # Initialize configuration
        # Select analyzers to run
        analyzers_to_run = []
        if args.analyzer == "all":
            analyzers_to_run = [
                AdvancedSecurityAnalyzer(),
                CircularImportAnalyzer(),
                DeadCodeAnalyzer(),
                DocumentationAnalyzer(),
                DuplicateCodeAnalyzer(),
            ]
        else:
            analyzer_map = {
                "security": AdvancedSecurityAnalyzer,
                "circular": CircularImportAnalyzer,
                "dead-code": DeadCodeAnalyzer,
                "docs": DocumentationAnalyzer,
                "duplicates": DuplicateCodeAnalyzer,
            }
            analyzers_to_run = [analyzer_map[args.analyzer]()]

        # Run analysis
        if not args.quiet:
            print(f"Running DinoScan analysis on: {args.path}")
            print(
                f"Analyzers: {', '.join(a.__class__.__name__ for a in analyzers_to_run)}"
            )
            print(f"Profile: {args.profile}")
            print()

        all_findings = []
        files_analyzed = []

        for analyzer in analyzers_to_run:
            if args.verbose:
                print(f"Running {analyzer.__class__.__name__}...")

            if args.path.is_file():
                # Analyze single file
                findings = analyzer.analyze_file(str(args.path))
                all_findings.extend(findings)
                files_analyzed.append(str(args.path))
            else:
                # Analyze project/directory
                result = analyzer.analyze_project(str(args.path))
                all_findings.extend(result.findings)
                files_analyzed.extend(result.files_analyzed)

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
