#!/usr/bin/env python3
"""
DinoScan command-line interface for VS Code integration
"""

import fnmatch
import json
import sys
from itertools import chain
from pathlib import Path

# Add the DinoScan directory to path
dinoscan_dir = Path(__file__).parent
sys.path.insert(0, str(dinoscan_dir))

try:
    from analyzers.advanced_security_analyzer import AdvancedSecurityAnalyzer
    from analyzers.circular_import_analyzer import CircularImportAnalyzer
    from analyzers.dead_code_analyzer import DeadCodeAnalyzer
    from analyzers.doc_quality_analyzer import DocumentationAnalyzer
    from analyzers.duplicate_code_analyzer import DuplicateCodeAnalyzer
except ImportError as e:
    print(f"Error: Failed to import DinoScan modules: {e}", file=sys.stderr)
    sys.exit(1)


def format_finding_for_vscode(finding):
    """Convert a DinoScan finding to VS Code diagnostic format."""
    return {
        "file": str(finding.file_path),
        "line": finding.line_number,
        "column": finding.column_number,
        "message": finding.message,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "rule_id": finding.rule_id,
        "fix_suggestion": finding.suggestion,
    }


def should_exclude(path: Path, patterns: list[str]) -> bool:
    """Return True if the path matches any exclude pattern."""
    normalized = path.as_posix()
    for pattern in patterns:
        if fnmatch.fnmatch(normalized, pattern) or pattern in normalized:
            return True
    return False


def analyze_path(
    file_path,
    selected: str = "all",
    profile: str = "standard",
    excludes: list[str] | None = None,
):
    """Analyze a single file and return results in JSON format."""
    target_path = Path(file_path)
    if not target_path.exists():
        return []

    patterns = excludes or []
    if should_exclude(target_path, patterns):
        return []

    all_results = []

    try:
        # Run all analyzers
        analyzer_map = {
            "security": AdvancedSecurityAnalyzer,
            "circular": CircularImportAnalyzer,
            "dead-code": DeadCodeAnalyzer,
            "docs": DocumentationAnalyzer,
            "duplicates": DuplicateCodeAnalyzer,
        }

        if selected != "all" and selected not in analyzer_map:
            raise ValueError(f"Unknown analyzer: {selected}")

        if selected == "all":
            analyzers = [cls() for cls in analyzer_map.values()]
        else:
            analyzers = [analyzer_map[selected]()]  # type: ignore[index]

        for analyzer in analyzers:
            try:
                results = analyzer.analyze_file(str(target_path))
                all_results.extend(results)
            except Exception:
                # Silently continue if an analyzer fails
                continue

    except Exception:
        return []

    # Convert to VS Code format
    vscode_results = []
    for result in all_results:
        try:
            vscode_result = format_finding_for_vscode(result)
            vscode_results.append(vscode_result)
        except Exception:
            continue

    return vscode_results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="DinoScan CLI for VS Code")
    parser.add_argument("analyzer", nargs="?", default="all", help="Analyzer to run")
    parser.add_argument("path", nargs="?", help="File or directory to analyze")
    parser.add_argument("--format", choices=["json", "console"], default="json")
    parser.add_argument(
        "--profile", choices=["strict", "standard", "relaxed"], default="standard"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        nargs="+",
        default=[],
        help="Glob pattern(s) to exclude (each flag can accept one or more patterns)",
    )
    parser.add_argument(
        "--path",
        dest="path_option",
        help="Explicit path to analyze (alternative to positional argument)",
    )

    args = parser.parse_args()

    exclude_patterns = list(chain.from_iterable(args.exclude)) if args.exclude else []

    target_arg = args.path_option or args.path
    if not target_arg:
        parser.error("No path provided. Supply a positional path or use --path.")

    targets: list[Path]
    root = Path(target_arg)
    if root.is_dir():
        targets = [
            p for p in root.rglob("*.py") if not should_exclude(p, exclude_patterns)
        ]
    else:
        targets = [root]

    # Analyze the file
    all_results: list[dict] = []
    for target in targets:
        findings = analyze_path(target, args.analyzer, args.profile, exclude_patterns)
        all_results.extend(findings)

    # Output results
    if args.format == "json":
        print(json.dumps(all_results))
    elif all_results:
        for result in all_results:
            print(
                f"{result['file']}:{result['line']}:{result['column']} {result['severity']} {result['message']}"
            )
    else:
        print("No issues found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
