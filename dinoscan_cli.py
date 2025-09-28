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
        """
    )
    
    # Analyzer selection
    parser.add_argument(
        'analyzer',
        choices=['security', 'circular', 'dead-code', 'docs', 'duplicates', 'all'],
        help='Analyzer to run'
    )
    
    # Target path
    parser.add_argument(
        'path',
        type=Path,
        help='Path to analyze (file or directory)'
    )
    
    # Output options
    parser.add_argument(
        '--format', '-f',
        choices=['console', 'json', 'xml', 'sarif'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=Path,
        help='Output file (default: stdout)'
    )
    
    # Analysis options
    parser.add_argument(
        '--profile',
        choices=['strict', 'standard', 'relaxed'],
        default='standard',
        help='Analysis profile (default: standard)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=Path,
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--exclude',
        action='append',
        help='Exclude pattern (can be used multiple times)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress non-essential output'
    )
    
    args = parser.parse_args()
    
    # Validate path exists
    if not args.path.exists():
        print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
        return 1
    
    try:
        # Import analyzers here to avoid import issues during setup
        from dinoscan.analyzers import (
            AdvancedSecurityAnalyzer,
            CircularImportAnalyzer, 
            DeadCodeAnalyzer,
            DocumentationAnalyzer,
            DuplicateCodeAnalyzer
        )
        from dinoscan.core.config_manager import ConfigManager
        from dinoscan.core.reporter import create_reporter
        
        # Initialize configuration
        config_manager = ConfigManager(args.config or Path("config.json"))
        
        # Select analyzers to run
        analyzers_to_run = []
        if args.analyzer == 'all':
            analyzers_to_run = [
                AdvancedSecurityAnalyzer(),
                CircularImportAnalyzer(),
                DeadCodeAnalyzer(),
                DocumentationAnalyzer(),
                DuplicateCodeAnalyzer()
            ]
        else:
            analyzer_map = {
                'security': AdvancedSecurityAnalyzer,
                'circular': CircularImportAnalyzer,
                'dead-code': DeadCodeAnalyzer,
                'docs': DocumentationAnalyzer,
                'duplicates': DuplicateCodeAnalyzer
            }
            analyzers_to_run = [analyzer_map[args.analyzer]()]
        
        # Run analysis
        if not args.quiet:
            print(f"Running DinoScan analysis on: {args.path}")
            print(f"Analyzers: {', '.join(a.__class__.__name__ for a in analyzers_to_run)}")
            print(f"Profile: {args.profile}")
            print()
        
        all_findings = []
        for analyzer in analyzers_to_run:
            if args.verbose:
                print(f"Running {analyzer.__class__.__name__}...")
            
            result = analyzer.analyze_file(args.path)
            all_findings.extend(result.findings)
        
        # Create reporter and output results
        reporter = create_reporter(args.format)
        if args.output:
            with open(args.output, 'w') as f:
                reporter.write_report(all_findings, f)
            if not args.quiet:
                print(f"Report written to: {args.output}")
        else:
            reporter.write_report(all_findings, sys.stdout)
        
        # Return appropriate exit code
        high_severity_count = sum(1 for f in all_findings if f.severity.name == 'HIGH')
        if high_severity_count > 0:
            return 1
        
        medium_severity_count = sum(1 for f in all_findings if f.severity.name == 'MEDIUM') 
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

if __name__ == '__main__':
    sys.exit(main())