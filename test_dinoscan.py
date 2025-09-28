#!/usr/bin/env python3
"""
Enhanced test script for DinoScan functionality with improved error handling and settings integration.
"""

import os
from pathlib import Path
import sys
import json
import argparse


# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(__file__))

try:
    # Import from local directories
    from analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
    from analyzers.circular_import_analyzer import CircularImportAnalyzer
    from analyzers.dead_code_analyzer import DeadCodeAnalyzer
    from analyzers.doc_quality_analyzer import DocumentationAnalyzer
    from analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
    from core.settings_manager import SettingsManager
    from core.file_types import FileTypeManager
    from core.error_handler import ErrorHandler

    def create_enhanced_config(workspace_path: str | None = None) -> dict:
        """Create enhanced configuration with proper settings integration."""
        # Initialize settings manager with workspace
        settings_manager = SettingsManager(workspace_path or os.getcwd())

        # Create configuration that respects user settings
        config_data = {
            "workspace_path": workspace_path or os.getcwd(),
            "profiles": {
                "standard": {
                    "security": {
                        "enabled": settings_manager.is_analyzer_enabled("security"),
                        "level": "medium",
                    },
                    "circular": {
                        "enabled": settings_manager.is_analyzer_enabled(
                            "circularImports"
                        ),
                        "max_depth": 10,
                    },
                    "dead_code": {
                        "enabled": settings_manager.is_analyzer_enabled("deadCode"),
                        "ignore_private": False,
                    },
                    "documentation": {
                        "enabled": settings_manager.is_analyzer_enabled(
                            "documentation"
                        ),
                        "require_docstrings": True,
                    },
                    "duplicates": {
                        "enabled": settings_manager.is_analyzer_enabled(
                            "duplicateCode"
                        ),
                        "min_lines": 4,
                    },
                }
            },
            "settings": settings_manager.get_all_settings(),
        }
        return config_data

    def test_file_analysis(file_path, output_format="json", workspace_path=None):
        """Test DinoScan analysis on a single file with enhanced error handling."""

        target_path = Path(file_path)
        if not target_path.exists():
            print(f"Error: File {file_path} does not exist")
            return None

        # Initialize enhanced error handling
        error_handler = ErrorHandler("dinoscan.test")
        file_type_manager = FileTypeManager()

        # Check if file is supported
        if not file_type_manager.is_text_file(str(target_path)):
            print(f"Error: File {file_path} is not a text file or not supported")
            return None

        # Initialize configuration with enhanced settings
        try:
            config_data = create_enhanced_config(workspace_path)
        except Exception as e:
            error_handler.logger.error(f"Failed to create configuration: {e}")
            # Fallback to basic config
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
        analysis_stats = {
            "analyzers_run": 0,
            "analyzers_skipped": 0,
            "total_findings": 0,
            "errors_encountered": 0,
        }

        # Define analyzers with their configurations
        analyzers = [
            ("Security Analysis", AdvancedSecurityAnalyzer, config_data),
            ("Circular Import Analysis", CircularImportAnalyzer, config_data),
            ("Dead Code Analysis", DeadCodeAnalyzer, config_data),
            ("Documentation Analysis", DocumentationAnalyzer, config_data),
            ("Duplicate Code Analysis", DuplicateCodeAnalyzer, config_data),
        ]

        for analyzer_name, analyzer_class, config in analyzers:
            try:
                print(f"Running {analyzer_name.lower()}...")

                # Initialize analyzer with enhanced config
                analyzer = analyzer_class(config)

                # Check if analyzer is enabled
                if hasattr(analyzer, "is_enabled") and not analyzer.is_enabled():
                    print(f"  Skipping {analyzer_name} (disabled in settings)")
                    analysis_stats["analyzers_skipped"] += 1
                    continue

                # Check if file should be analyzed
                if hasattr(
                    analyzer, "should_analyze_file"
                ) and not analyzer.should_analyze_file(str(target_path)):
                    print(f"  Skipping {analyzer_name} (file excluded)")
                    analysis_stats["analyzers_skipped"] += 1
                    continue

                # Run analysis
                results = analyzer.analyze_file(str(target_path))
                all_results.extend(results)
                analysis_stats["analyzers_run"] += 1
                analysis_stats["total_findings"] += len(results)

                print(f"  Found {len(results)} issues")

            except Exception as e:
                error_handler.logger.error(f"Error in {analyzer_name}: {e}")
                analysis_stats["errors_encountered"] += 1
                print(f"  Error in {analyzer_name}: {e}")

        # Output results
        print("\n=== Analysis Summary ===")
        print(f"Analyzers run: {analysis_stats['analyzers_run']}")
        print(f"Analyzers skipped: {analysis_stats['analyzers_skipped']}")
        print(f"Total findings: {analysis_stats['total_findings']}")
        print(f"Errors encountered: {analysis_stats['errors_encountered']}")

        if output_format == "json":
            results_data = {
                "file_path": str(target_path),
                "analysis_stats": analysis_stats,
                "findings": [],
            }

            for result in all_results:
                if hasattr(result, "__dict__"):
                    results_data["findings"].append(result.__dict__)
                elif hasattr(result, "to_dict"):
                    results_data["findings"].append(result.to_dict())
                else:
                    results_data["findings"].append(str(result))

            print(json.dumps(results_data, indent=2, default=str))
        else:
            print(f"\n=== DinoScan Analysis Results for {file_path} ===")
            if all_results:
                for i, result in enumerate(all_results, 1):
                    print(f"{i}. {result}")
            else:
                print("No issues found!")

        return all_results

    def test_directory_analysis(
        directory_path, output_format="json", workspace_path=None
    ):
        """Test DinoScan analysis on an entire directory."""
        dir_path = Path(directory_path)
        if not dir_path.exists() or not dir_path.is_dir():
            print(f"Error: Directory {directory_path} does not exist")
            return None

        error_handler = ErrorHandler("dinoscan.test.directory")
        file_type_manager = FileTypeManager()

        try:
            config_data = create_enhanced_config(workspace_path)
        except Exception as e:
            error_handler.logger.error(f"Failed to create configuration: {e}")
            return None

        # Get analyzable files
        analyzable_files = file_type_manager.get_analyzable_files(
            str(dir_path), config_data
        )

        print(f"Found {len(analyzable_files)} analyzable files in {directory_path}")

        all_results = []
        for file_path in analyzable_files[:10]:  # Limit to first 10 files for testing
            print(f"Analyzing {file_path}...")
            results = test_file_analysis(file_path, "console", workspace_path)
            if results:
                all_results.extend(results)

        if output_format == "json":
            results_data = {
                "directory_path": str(dir_path),
                "total_files_found": len(analyzable_files),
                "files_analyzed": min(10, len(analyzable_files)),
                "total_findings": len(all_results),
                "findings": [
                    r.__dict__ if hasattr(r, "__dict__") else str(r)
                    for r in all_results
                ],
            }
            print(json.dumps(results_data, indent=2, default=str))

        return all_results

except ImportError as e:
    print(f"Error: Failed to import DinoScan modules: {e}")
    print("Please ensure DinoScan modules are available in the current directory.")
    print("Run this from the DinoScan root directory.")
    sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced DinoScan test functionality")
    parser.add_argument("target", help="Python file or directory to analyze")
    parser.add_argument(
        "--format", choices=["console", "json"], default="console", help="Output format"
    )
    parser.add_argument(
        "--workspace",
        help="Workspace path for settings (defaults to current directory)",
    )
    parser.add_argument(
        "--directory",
        action="store_true",
        help="Analyze entire directory instead of single file",
    )

    args = parser.parse_args()

    if args.directory:
        test_directory_analysis(args.target, args.format, args.workspace)
    else:
        test_file_analysis(args.target, args.format, args.workspace)
