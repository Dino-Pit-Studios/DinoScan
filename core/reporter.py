"""
Output formatting and reporting for DinoScan analysis results.

This module provides various output formats including console, JSON, XML, and SARIF
for integration with different tools and workflows.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import Element, SubElement

from core.base_analyzer import AnalysisResult, Finding, Severity
from core.json_reporter import JSONReporter
from core.xml_reporter import XMLReporter


class Reporter(ABC):
    """Abstract base class for result reporters."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize reporter with configuration."""
        self.config = config or {}

    @abstractmethod
    def format_results(self, result: AnalysisResult) -> str:
        """Format analysis results as string."""

    def save_results(self, result: AnalysisResult, output_path: str) -> None:
        """Save results to file."""
        formatted_output = self.format_results(result)

        with Path(output_path).open("w", encoding="utf-8") as f:
            f.write(formatted_output)

    @staticmethod
    def print_results(reporter, result: AnalysisResult) -> None:
        """Print results to console."""
        print(reporter.format_results(result))


class ConsoleReporter(Reporter):
    """Console output reporter with color support."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.use_colors = config.get("use_colors", True) if config else True
        self.show_context = config.get("show_context", True) if config else True
        self.max_findings_per_file = (
            config.get("max_findings_per_file", 10) if config else 10
        )

    def _colorize(self, text: str, severity: Severity) -> str:
        """Apply color codes based on severity."""
        if not self.use_colors:
            return text

        color_map = {
            Severity.CRITICAL: "\033[91m",  # Red
            Severity.HIGH: "\033[91m",  # Red
            Severity.MEDIUM: "\033[93m",  # Yellow
            Severity.LOW: "\033[94m",  # Blue
            Severity.INFO: "\033[96m",  # Cyan
        }

        reset_code = "\033[0m"
        color_code = color_map.get(severity, "")

        return f"{color_code}{text}{reset_code}"

    def format_results(self, result: AnalysisResult) -> str:
        """Format results into a console-friendly report, combining header, summary, breakdowns, detailed findings, and footer."""
        lines = []

        # Build report sections
        lines.extend(self._format_header(result))
        lines.extend(self._format_summary(result))
        lines.extend(self._format_severity_breakdown(result))
        lines.extend(self._format_category_breakdown(result))
        lines.extend(self._format_detailed_findings(result))
        lines.extend(self._format_footer(result))

        return "\n".join(lines)

    @staticmethod
    def _format_header(result: AnalysisResult) -> list[str]:
        """Format the report header."""
        return [
            "=" * 80,
            f"DinoScan Analysis Report - {result.analyzer_name}",
            "=" * 80,
            "",
        ]

    @staticmethod
    def _format_summary(result: AnalysisResult) -> list[str]:
        """Format the analysis summary section."""
        stats = result.get_summary_stats()
        return [
            "📊 Analysis Summary:",
            f"   Files analyzed: {stats['files_analyzed']}",
            f"   Total findings: {stats['total_findings']}",
            f"   Analysis time: {result.analysis_duration:.2f} seconds",
            "",
        ]


def colorize(self, text: str, severity: Severity) -> str:
    """Delegate to the internal colorization logic to wrap text with ANSI codes based on severity."""
    return self._colorize(text, severity)


def _format_severity_breakdown(self, result: AnalysisResult) -> list[str]:
    """Format the severity breakdown section."""
    stats = result.get_summary_stats()
    if not stats["severity_breakdown"]:
        return []

    lines = ["⚠️  Severity Breakdown:"]
    for severity, count in stats["severity_breakdown"].items():
        severity_enum = Severity(severity)
        colored_line = self.colorize(f"   {severity}: {count}", severity_enum)
        lines.append(colored_line)
    lines.append("")
    return lines


@staticmethod
def _format_category_breakdown(result: AnalysisResult) -> list[str]:
    """Format the category breakdown section."""
    stats = result.get_summary_stats()
    if not stats["category_breakdown"]:
        return []

    lines = ["🔍 Category Breakdown:"]
    for category, count in stats["category_breakdown"].items():
        lines.append(f"   {category}: {count}")
    lines.append("")
    return lines


def group_findings_by_file(self, findings):
    """Group a list of findings by their file path, returning a mapping from each file to its findings."""
    return self._group_findings_by_file(findings)


def format_file_findings(self, file_path, findings, project_path):
    """Format the findings for a single file, including its relative path and detailed finding lines."""
    return self._format_file_findings(file_path, findings, project_path)


def _format_detailed_findings(self, result: AnalysisResult) -> list[str]:
    """Format the detailed findings section."""
    if not result.findings:
        return []

    lines = ["🐛 Detailed Findings:", ""]
    findings_by_file = self.group_findings_by_file(result.findings)

    for file_path in sorted(findings_by_file.keys()):
        file_lines = self.format_file_findings(
            file_path, findings_by_file[file_path], result.project_path
        )
        lines.extend(file_lines)

    return lines


@staticmethod
def _group_findings_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file path."""
    findings_by_file = {}
    for finding in findings:
        if finding.file_path not in findings_by_file:
            findings_by_file[finding.file_path] = []
        findings_by_file[finding.file_path].append(finding)
    return findings_by_file


def _format_file_findings(
    self, file_path: str, file_findings: list[Finding], project_path: str
) -> list[str]:
    """Format findings for a specific file."""
    # Show relative path
    rel_path = self.get_relative_path(file_path, project_path)

    lines = [f"📄 {rel_path}", "-" * len(rel_path)]

    # Sort and limit findings
    sorted_findings = self.sort_and_limit_findings(file_findings)

    for finding in sorted_findings:
        lines.extend(self.format_single_finding(finding))

    # Show remaining count if truncated
    lines.extend(self.format_remaining_count(file_findings))

    return lines


@staticmethod
def _get_relative_path(file_path: str, project_path: str) -> str:
    """Get relative path for display."""
    try:
        return str(Path(file_path).relative_to(project_path))
    except ValueError:
        return file_path


def _sort_and_limit_findings(self, file_findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity and limit the count."""
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    return sorted(
        file_findings[: self.max_findings_per_file],
        key=lambda f: severity_order.index(f.severity),
    )


def _format_single_finding(self, finding: Finding) -> list[str]:
    """Format a single finding with all its details."""
    lines = []

    # Main finding line
    location = self.format_location(finding)
    finding_line = f"  {location}: [{finding.severity.value}] {finding.message}"
    colored_line = self.colorize(finding_line, finding.severity)
    lines.append(colored_line)

    # Context if enabled
    if self.show_context and finding.context:
        lines.append(f"    Context: {finding.context}")

    # Suggestion if available
    if finding.suggestion:
        lines.append(f"    💡 Suggestion: {finding.suggestion}")

    # Rule ID and CWE
    details = self.format_finding_details(finding)
    if details:
        lines.append(f"    ℹ️  {details}")

    lines.append("")
    return lines


@staticmethod
def _format_location(finding: Finding) -> str:
    """Format the location information for a finding."""
    location = f"Line {finding.line_number}"
    if finding.column_number:
        location += f", Col {finding.column_number}"
    return location


@staticmethod
def _format_finding_details(finding: Finding) -> str:
    """Format rule ID and CWE details."""
    details = []
    if finding.rule_id:
        details.append(f"Rule: {finding.rule_id}")
    if finding.cwe:
        details.append(f"CWE: {finding.cwe}")
    return " | ".join(details)


def _format_remaining_count(self, file_findings: list[Finding]) -> list[str]:
    """Format remaining findings count if truncated."""
    if len(file_findings) <= self.max_findings_per_file:
        return []

    remaining = len(file_findings) - self.max_findings_per_file
    return [f"  ... and {remaining} more findings in this file", ""]


@staticmethod
def _format_footer(result: AnalysisResult) -> list[str]:
    """Format the report footer."""
    return ["=" * 80, f"Analysis completed at {result.timestamp}", "=" * 80]


class SARIFReporter(Reporter):
    """SARIF (Static Analysis Results Interchange Format) reporter."""

    def format_results(self, result: AnalysisResult) -> str:
        """Format results in SARIF format."""
        sarif_report = {
            "$schema": (
                "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": result.analyzer_name,
                            "version": result.version,
                            "informationUri": ("https://github.com/dinoscan/dinoscan"),
                            "rules": self._generate_rules(result.findings),
                        }
                    },
                    "results": self._generate_results(result.findings),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": result.timestamp,
                            "endTimeUtc": result.timestamp,  # Simplified
                            "workingDirectory": {
                                "uri": f"file://{result.project_path}"
                            },
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif_report, indent=2, sort_keys=True)

    def _generate_rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate SARIF rules from findings."""
        rules = {}

        for finding in findings:
            if finding.rule_id not in rules:
                rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.message},
                    "fullDescription": {"text": finding.suggestion or finding.message},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity)
                    },
                    "properties": {"category": finding.category.value},
                }

                if finding.cwe:
                    rules[finding.rule_id]["properties"]["cwe"] = finding.cwe

        return list(rules.values())

    def _generate_results(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate SARIF results from findings."""
        results = []

        for finding in findings:
            result_item = {
                "ruleId": finding.rule_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": finding.column_number or 1,
                            },
                        }
                    }
                ],
            }

            if finding.suggestion:
                result_item["fixes"] = [{"description": {"text": finding.suggestion}}]

            results.append(result_item)

        return results

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        """Convert DinoScan severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "note")


def create_reporter(
    output_format: str, config: dict[str, Any] | None = None
) -> Reporter:
    """Factory function to create appropriate reporter."""
    reporters = {
        "console": ConsoleReporter,
        "json": JSONReporter,
        "xml": XMLReporter,
        "sarif": SARIFReporter,
    }

    reporter_class = reporters.get(output_format.lower())
    if not reporter_class:
        raise ValueError(f"Unsupported output format: {output_format}")

    return reporter_class(config)
