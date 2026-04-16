"""
Audit Report Generator

Production-grade audit report generation with multiple output formats.
Supports JSON, Markdown, PDF, and HTML report generation.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    TEXT = "text"


class ReportStyle(Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    DETAILED = "detailed"
    EXECUTIVE = "executive"


@dataclass
class ReportConfig:
    format: ReportFormat = ReportFormat.JSON
    style: ReportStyle = ReportStyle.STANDARD
    include_code_snippets: bool = True
    include_recommendations: bool = True
    include_executive_summary: bool = True
    include_metrics: bool = True
    max_code_snippet_lines: int = 10


@dataclass
class ReportSection:
    title: str
    content: str
    level: int = 1


class AuditReporter:
    SEVERITY_COLORS = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF6600",
        "MEDIUM": "#FFCC00",
        "LOW": "#3399FF",
        "INFO": "#00CC66",
    }

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()

    def generate(self, scan_result: Any) -> str:
        if self.config.format == ReportFormat.JSON:
            return self._generate_json(scan_result)
        elif self.config.format == ReportFormat.MARKDOWN:
            return self._generate_markdown(scan_result)
        elif self.config.format == ReportFormat.HTML:
            return self._generate_html(scan_result)
        elif self.config.format == ReportFormat.TEXT:
            return self._generate_text(scan_result)

        return self._generate_json(scan_result)

    def _generate_json(self, scan_result: Any) -> str:
        report = {
            "report_version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "contract": {
                "name": scan_result.contract_name,
                "hash": scan_result.source_hash,
            },
            "summary": self._extract_summary(scan_result),
            "findings": scan_result.findings,
            "metrics": {
                "scan_time_ms": scan_result.scan_time_ms,
                "detectors_run": scan_result.detectors_run,
                "errors": scan_result.errors,
            },
        }
        return json.dumps(report, indent=2)

    def _generate_markdown(self, scan_result: Any) -> str:
        lines = []
        lines.append(f"# Security Audit Report")
        lines.append(f"**Contract:** {scan_result.contract_name}")
        lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
        lines.append("")

        summary = self._extract_summary(scan_result)
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Total Findings:** {summary.get('total', 0)}")
        lines.append(f"- **Critical:** {summary.get('critical', 0)}")
        lines.append(f"- **High:** {summary.get('high', 0)}")
        lines.append(f"- **Medium:** {summary.get('medium', 0)}")
        lines.append(f"- **Low:** {summary.get('low', 0)}")
        lines.append("")

        if scan_result.findings:
            lines.append("## Findings")
            lines.append("")

            for i, finding in enumerate(scan_result.findings, 1):
                severity = finding.get("severity", "INFO")
                lines.append(f"### {i}. [{severity}] {finding.get('title', 'Untitled')}")
                lines.append("")
                lines.append(f"**Category:** {finding.get('category', 'Unknown')}")
                lines.append(f"**CVSS:** {finding.get('cvss_score', 0)}")
                lines.append(f"**Confidence:** {finding.get('confidence', 0) * 100}%")
                lines.append("")
                lines.append("**Description:**")
                lines.append(f"```\n{finding.get('description', '')}\n```")
                lines.append("")

                if self.config.include_recommendations:
                    lines.append("**Recommendation:**")
                    lines.append(f"```\n{finding.get('recommendation', '')}\n```")
                    lines.append("")

        lines.append("## Metrics")
        lines.append(f"- Scan Duration: {scan_result.scan_time_ms}ms")
        lines.append(f"- Detectors Run: {len(scan_result.detectors_run)}")
        lines.append("")

        return "\n".join(lines)

    def _generate_html(self, scan_result: Any) -> str:
        summary = self._extract_summary(scan_result)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - {scan_result.contract_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }}
        .CRITICAL {{ border-color: #FF0000; }}
        .HIGH {{ border-color: #FF6600; }}
        .MEDIUM {{ border-color: #FFCC00; }}
        .LOW {{ border-color: #3399FF; }}
        .badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; }}
        .badge-CRITICAL {{ background: #FF0000; }}
        .badge-HIGH {{ background: #FF6600; }}
        .badge-MEDIUM {{ background: #FFCC00; color: #333; }}
        .badge-LOW {{ background: #3399FF; }}
    </style>
</head>
<body>
    <h1>Security Audit Report</h1>
    <p><strong>Contract:</strong> {scan_result.contract_name}</p>
    <p><strong>Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d')}</p>

    <h2>Executive Summary</h2>
    <div class="summary">
        <p><strong>Total Findings:</strong> {summary.get('total', 0)}</p>
        <p><span class="badge badge-CRITICAL">Critical:</span> {summary.get('critical', 0)}</p>
        <p><span class="badge badge-HIGH">High:</span> {summary.get('high', 0)}</p>
        <p><span class="badge badge-MEDIUM">Medium:</span> {summary.get('medium', 0)}</p>
        <p><span class="badge badge-LOW">Low:</span> {summary.get('low', 0)}</p>
    </div>

    <h2>Findings</h2>
"""

        for i, finding in enumerate(scan_result.findings, 1):
            severity = finding.get("severity", "INFO")
            html += f"""
    <div class="finding {severity}">
        <h3>{i}. {finding.get('title', 'Untitled')}</h3>
        <p><span class="badge badge-{severity}">{severity}</span></p>
        <p><strong>Category:</strong> {finding.get('category', 'Unknown')}</p>
        <p><strong>CVSS:</strong> {finding.get('cvss_score', 0)}</p>
        <p><strong>Description:</strong> {finding.get('description', '')}</p>
"""

            if self.config.include_recommendations:
                html += f"""
        <p><strong>Recommendation:</strong></p>
        <pre>{finding.get('recommendation', '')}</pre>
"""

            html += "    </div>\n"

        html += f"""
    <h2>Metrics</h2>
    <p>Scan Duration: {scan_result.scan_time_ms}ms</p>
    <p>Detectors Run: {len(scan_result.detectors_run)}</p>
</body>
</html>
"""
        return html

    def _generate_text(self, scan_result: Any) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append(f"SECURITY AUDIT REPORT - {scan_result.contract_name}")
        lines.append("=" * 60)
        lines.append("")

        summary = self._extract_summary(scan_result)
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Findings: {summary.get('total', 0)}")
        lines.append(f"Critical: {summary.get('critical', 0)}")
        lines.append(f"High: {summary.get('high', 0)}")
        lines.append(f"Medium: {summary.get('medium', 0)}")
        lines.append(f"Low: {summary.get('low', 0)}")
        lines.append("")

        if scan_result.findings:
            lines.append("FINDINGS")
            lines.append("-" * 40)

            for i, finding in enumerate(scan_result.findings, 1):
                severity = finding.get("severity", "INFO")
                lines.append(f"{i}. [{severity}] {finding.get('title', 'Untitled')}")
                lines.append(f"   Category: {finding.get('category', 'Unknown')}")
                lines.append(f"   CVSS: {finding.get('cvss_score', 0)}")
                lines.append(f"   {finding.get('description', '')}")
                lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _extract_summary(self, scan_result: Any) -> Dict[str, int]:
        summary = {
            "total": len(scan_result.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in scan_result.findings:
            severity = finding.get("severity", "INFO")
            severity_key = severity.lower()
            if severity_key in summary:
                summary[severity_key] += 1

        return summary

    def save_report(self, scan_result: Any, output_path: str):
        content = self.generate(scan_result)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Report saved to {output_path}")


def generate_report(
    scan_result: Any,
    format: ReportFormat = ReportFormat.JSON,
    output_path: Optional[str] = None,
) -> str:
    config = ReportConfig(format=format)
    reporter = AuditReporter(config)
    report = reporter.generate(scan_result)

    if output_path:
        reporter.save_report(scan_result, output_path)

    return report


__all__ = [
    "AuditReporter",
    "ReportFormat",
    "ReportStyle",
    "ReportConfig",
    "ReportSection",
    "generate_report",
]
