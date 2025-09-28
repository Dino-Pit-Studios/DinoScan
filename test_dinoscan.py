#!/usr/bin/env python3
"""
Test script for DinoScan functionality without package installation.
"""

import os
import sys
from pathlib import Path

# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(__file__))

try:
    # Import from local directories
    from analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
    from analyzers.circular_import_analyzer import CircularImportAnalyzer
    from analyzers.dead_code_analyzer import DeadCodeAnalyzer
    from analyzers.doc_quality_analyzer import DocumentationAnalyzer
    from analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
    from core.config_manager import ConfigManager
    from core.reporter import create_reporter

    def test_file_analysis(file_path, output_format="json"):
        """Test DinoScan analysis on a single file."""

        target_path = Path(file_path)
        if not target_path.exists():
            print(f"Error: File {file_path} does not exist")
            return None

        # Initialize configuration with default settings
        config_data = {
            "profiles": {
                "standard": {
                    "security": {"enabled": True, "level": "medium"},
                    "circular": {"enabled": True, "max_depth": 10},
                    "dead_code": {"enabled": True, "ignore_private": False},
                    "documentation": {"enabled": True, "require_docstrings": True},
                    "duplicates": {"enabled": True, "min_lines": 4},
                }
            }
        }

        # Create results list
        all_results = []

        try:
            # Run security analysis
            print("Running security analysis...")
            security_analyzer = AdvancedSecurityAnalyzer()
            security_results = security_analyzer.analyze_file(str(target_path))
            all_results.extend(security_results)

            # Run circular import analysis
            print("Running circular import analysis...")
            circular_analyzer = CircularImportAnalyzer()
            circular_results = circular_analyzer.analyze_file(str(target_path))
            all_results.extend(circular_results)

            # Run dead code analysis
            print("Running dead code analysis...")
            deadcode_analyzer = DeadCodeAnalyzer()
            deadcode_results = deadcode_analyzer.analyze_file(str(target_path))
            all_results.extend(deadcode_results)

            # Run documentation analysis
            print("Running documentation analysis...")
            doc_analyzer = DocumentationAnalyzer()
            doc_results = doc_analyzer.analyze_file(str(target_path))
            all_results.extend(doc_results)

            # Run duplicate code analysis
            print("Running duplicate code analysis...")
            duplicate_analyzer = DuplicateCodeAnalyzer()
            duplicate_results = duplicate_analyzer.analyze_file(str(target_path))
            all_results.extend(duplicate_results)

        except Exception as e:
            print(f"Error during analysis: {e}")
            return None

        # Output results
        if output_format == "json":
            import json

            results_data = []
            for result in all_results:
                if hasattr(result, "__dict__"):
                    results_data.append(result.__dict__)
                else:
                    results_data.append(str(result))
            print(json.dumps(results_data, indent=2))
        else:
            print(f"\n=== DinoScan Analysis Results for {file_path} ===")
            if all_results:
                for i, result in enumerate(all_results, 1):
                    print(f"{i}. {result}")
            else:
                print("No issues found!")

        return all_results

except ImportError as e:
    print(f"Error: Failed to import DinoScan modules: {e}")
    print("Please ensure DinoScan modules are available in the current directory.")
    sys.exit(1)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test DinoScan functionality")
    parser.add_argument("file", help="Python file to analyze")
    parser.add_argument(
        "--format", choices=["console", "json"], default="console", help="Output format"
    )

    args = parser.parse_args()
    test_file_analysis(args.file, args.format)
