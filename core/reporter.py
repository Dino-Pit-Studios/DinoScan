"""
Output formatting and reporting for DinoScan analysis results.

This module provides various output formats including console, JSON, XML, and SARIF
for integration with different tools and workflows.
"""

import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from .base_analyzer import AnalysisResult, Finding, Severity


class Reporter(ABC):
    """Abstract base class for result reporters."""
    
    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize reporter with configuration."""
        self.config = config or {}
    
    @abstractmethod
    def format_results(self, result: AnalysisResult) -> str:
        """Format analysis results as string."""
        pass
    
    def save_results(self, result: AnalysisResult, output_path: str) -> None:
        """Save results to file."""
        formatted_output = self.format_results(result)
        
        with Path(output_path).open('w', encoding='utf-8') as f:
            f.write(formatted_output)
    
    def print_results(self, result: AnalysisResult) -> None:
        """Print results to console."""
        print(self.format_results(result))


class ConsoleReporter(Reporter):
    """Console output reporter with color support."""
    
    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.use_colors = config.get('use_colors', True) if config else True
        self.show_context = config.get('show_context', True) if config else True
        self.max_findings_per_file = config.get('max_findings_per_file', 10) if config else 10
    
    def _colorize(self, text: str, severity: Severity) -> str:
        """Apply color codes based on severity."""
        if not self.use_colors:
            return text
        
        color_map = {
            Severity.CRITICAL: '\033[91m',  # Red
            Severity.HIGH: '\033[91m',      # Red
            Severity.MEDIUM: '\033[93m',    # Yellow
            Severity.LOW: '\033[94m',       # Blue
            Severity.INFO: '\033[96m',      # Cyan
        }
        
        reset_code = '\033[0m'
        color_code = color_map.get(severity, '')
        
        return f"{color_code}{text}{reset_code}"
    
    def format_results(self, result: AnalysisResult) -> str:
        """Format results for console output."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append(f"DinoScan Analysis Report - {result.analyzer_name}")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary statistics
        stats = result.get_summary_stats()
        lines.append("📊 Analysis Summary:")
        lines.append(f"   Files analyzed: {stats['files_analyzed']}")
        lines.append(f"   Total findings: {stats['total_findings']}")
        lines.append(f"   Analysis time: {result.analysis_duration:.2f} seconds")
        lines.append("")
        
        # Severity breakdown
        if stats['severity_breakdown']:
            lines.append("⚠️  Severity Breakdown:")
            for severity, count in stats['severity_breakdown'].items():
                severity_enum = Severity(severity)
                colored_line = self._colorize(f"   {severity}: {count}", severity_enum)
                lines.append(colored_line)
            lines.append("")
        
        # Category breakdown
        if stats['category_breakdown']:
            lines.append("🔍 Category Breakdown:")
            for category, count in stats['category_breakdown'].items():
                lines.append(f"   {category}: {count}")
            lines.append("")
        
        # Detailed findings
        if result.findings:
            lines.append("🐛 Detailed Findings:")
            lines.append("")
            
            # Group findings by file
            findings_by_file = {}
            for finding in result.findings:
                if finding.file_path not in findings_by_file:
                    findings_by_file[finding.file_path] = []
                findings_by_file[finding.file_path].append(finding)
            
            # Sort files and limit findings per file
            for file_path in sorted(findings_by_file.keys()):
                file_findings = findings_by_file[file_path]
                
                # Show relative path
                try:
                    rel_path = str(Path(file_path).relative_to(result.project_path))
                except ValueError:
                    rel_path = file_path
                
                lines.append(f"📄 {rel_path}")
                lines.append("-" * len(rel_path))
                
                # Limit findings per file and sort by severity
                severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
                sorted_findings = sorted(
                    file_findings[:self.max_findings_per_file], 
                    key=lambda f: severity_order.index(f.severity)
                )
                
                for finding in sorted_findings:
                    # Main finding line
                    location = f"Line {finding.line_number}"
                    if finding.column_number:
                        location += f", Col {finding.column_number}"
                    
                    finding_line = f"  {location}: [{finding.severity.value}] {finding.message}"
                    colored_line = self._colorize(finding_line, finding.severity)
                    lines.append(colored_line)
                    
                    # Context if enabled
                    if self.show_context and finding.context:
                        lines.append(f"    Context: {finding.context}")
                    
                    # Suggestion if available
                    if finding.suggestion:
                        lines.append(f"    💡 Suggestion: {finding.suggestion}")
                    
                    # Rule ID and CWE
                    details = []
                    if finding.rule_id:
                        details.append(f"Rule: {finding.rule_id}")
                    if finding.cwe:
                        details.append(f"CWE: {finding.cwe}")
                    if details:
                        lines.append(f"    ℹ️  {' | '.join(details)}")
                    
                    lines.append("")
                
                # Show if there are more findings
                if len(file_findings) > self.max_findings_per_file:
                    remaining = len(file_findings) - self.max_findings_per_file
                    lines.append(f"  ... and {remaining} more findings in this file")
                    lines.append("")
        
        # Recommendations
        if hasattr(result, 'recommendations') and result.recommendations:
            lines.append("💡 Recommendations:")
            for recommendation in result.recommendations:
                lines.append(f"  • {recommendation}")
            lines.append("")
        
        # Footer
        lines.append("=" * 80)
        lines.append(f"Analysis completed at {result.timestamp}")
        lines.append("=" * 80)
        
        return "\n".join(lines)


class JSONReporter(Reporter):
    """JSON output reporter."""
    
    def format_results(self, result: AnalysisResult) -> str:
        """Format results as JSON."""
        return json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str)


class XMLReporter(Reporter):
    """XML output reporter."""
    
    def format_results(self, result: AnalysisResult) -> str:
        """Format results as XML."""
        root = ET.Element('DinoScanReport')
        
        # Metadata
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'analyzer_name').text = result.analyzer_name
        ET.SubElement(metadata, 'version').text = result.version
        ET.SubElement(metadata, 'timestamp').text = result.timestamp
        ET.SubElement(metadata, 'project_path').text = result.project_path
        ET.SubElement(metadata, 'analysis_duration').text = str(result.analysis_duration)
        
        # Statistics
        stats = result.get_summary_stats()
        statistics = ET.SubElement(root, 'statistics')
        ET.SubElement(statistics, 'total_findings').text = str(stats['total_findings'])
        ET.SubElement(statistics, 'files_analyzed').text = str(stats['files_analyzed'])
        ET.SubElement(statistics, 'files_skipped').text = str(stats['files_skipped'])
        
        # Severity breakdown
        severity_elem = ET.SubElement(statistics, 'severity_breakdown')
        for severity, count in stats['severity_breakdown'].items():
            severity_item = ET.SubElement(severity_elem, 'severity')
            severity_item.set('level', severity)
            severity_item.text = str(count)
        
        # Findings
        findings_elem = ET.SubElement(root, 'findings')
        for finding in result.findings:
            finding_elem = ET.SubElement(findings_elem, 'finding')
            finding_elem.set('id', finding.rule_id)
            finding_elem.set('severity', finding.severity.value)
            finding_elem.set('category', finding.category.value)
            
            ET.SubElement(finding_elem, 'message').text = finding.message
            ET.SubElement(finding_elem, 'file_path').text = finding.file_path
            ET.SubElement(finding_elem, 'line_number').text = str(finding.line_number)
            ET.SubElement(finding_elem, 'column_number').text = str(finding.column_number)
            
            if finding.context:
                ET.SubElement(finding_elem, 'context').text = finding.context
            if finding.suggestion:
                ET.SubElement(finding_elem, 'suggestion').text = finding.suggestion
            if finding.cwe:
                ET.SubElement(finding_elem, 'cwe').text = finding.cwe
        
        return ET.tostring(root, encoding='unicode', xml_declaration=True)


class SARIFReporter(Reporter):
    """SARIF (Static Analysis Results Interchange Format) reporter."""
    
    def format_results(self, result: AnalysisResult) -> str:
        """Format results in SARIF format."""
        sarif_report = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": result.analyzer_name,
                            "version": result.version,
                            "informationUri": "https://github.com/dinoscan/dinoscan",
                            "rules": self._generate_rules(result.findings)
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
                            }
                        }
                    ]
                }
            ]
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
                    "shortDescription": {
                        "text": finding.message
                    },
                    "fullDescription": {
                        "text": finding.suggestion or finding.message
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity)
                    },
                    "properties": {
                        "category": finding.category.value
                    }
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
                "message": {
                    "text": finding.message
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": finding.column_number or 1
                            }
                        }
                    }
                ]
            }
            
            if finding.suggestion:
                result_item["fixes"] = [
                    {
                        "description": {
                            "text": finding.suggestion
                        }
                    }
                ]
            
            results.append(result_item)
        
        return results
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Convert DinoScan severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "note")


def create_reporter(output_format: str, config: dict[str, Any] | None = None) -> Reporter:
    """Factory function to create appropriate reporter."""
    reporters = {
        'console': ConsoleReporter,
        'json': JSONReporter,
        'xml': XMLReporter,
        'sarif': SARIFReporter
    }
    
    reporter_class = reporters.get(output_format.lower())
    if not reporter_class:
        raise ValueError(f"Unsupported output format: {output_format}")
    
    return reporter_class(config)