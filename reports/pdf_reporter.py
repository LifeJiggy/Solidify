"""
PDF Report Generator Module

This module provides comprehensive PDF report generation capabilities
for the Solidify security auditing framework.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import re
import json
import time
import hashlib
import os
import logging
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    CSV = "csv"


class ReportStyle(Enum):
    STANDARD = "standard"
    MINIMAL = "minimal"
    DETAILED = "detailed"
    EXECUTIVE = "executive"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReportSection:
    section_id: str
    title: str
    content: str
    order: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'section_id': self.section_id,
            'title': self.title,
            'content': self.content[:500],
            'order': self.order,
            'metadata': self.metadata
        }


@dataclass
class VulnerabilityEntry:
    vuln_id: str
    title: str
    severity: SeverityLevel
    category: str
    description: str
    impact: str
    recommendation: str
    code_snippet: str
    line_number: int
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'title': self.title,
            'severity': self.severity.value,
            'category': self.category,
            'description': self.description,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'code_snippet': self.code_snippet[:200],
            'line_number': self.line_number,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score
        }


@dataclass
class AuditReport:
    report_id: str
    contract_name: str
    contract_address: str
    audit_date: float
    sections: List[ReportSection] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityEntry] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_section(self, section: ReportSection) -> None:
        self.sections.append(section)

    def add_vulnerability(self, vuln: VulnerabilityEntry) -> None:
        self.vulnerabilities.append(vuln)

    def get_severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return dict(counts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'report_id': self.report_id,
            'contract_name': self.contract_name,
            'contract_address': self.contract_address,
            'audit_date': self.audit_date,
            'section_count': len(self.sections),
            'vulnerability_count': len(self.vulnerabilities),
            'severity_counts': self.get_severity_counts(),
            'statistics': self.statistics,
            'metadata': self.metadata
        }


class PDFStyleConfig:
    """Configuration for PDF styling."""

    def __init__(self) -> None:
        self.page_size = (210, 297)
        self.margin = 20
        self.font_family = "Helvetica"
        self.title_font_size = 24
        self.heading_font_size = 18
        self.subheading_font_size = 14
        self.body_font_size = 10
        self.line_height = 1.5

        self.colors: Dict[str, Tuple[int, int, int]] = {
            'critical': (220, 53, 69),
            'high': (220, 16, 46),
            'medium': (255, 193, 7),
            'low': (25, 135, 84),
            'info': (13, 110, 253),
            'primary': (0, 123, 255),
            'secondary': (108, 117, 125)
        }

        self.page_numbers = True
        self.headers = True
        self.footers = True


class PDFGenerator:
    """Generates PDF-style content from audit reports."""

    def __init__(self) -> None:
        self.style = PDFStyleConfig()
        self.sections: List[ReportSection] = []
        self.vulnerabilities: List[VulnerabilityEntry] = []

    def generate_report(self, audit_report: AuditReport) -> bytes:
        content = self._generate_content(audit_report)
        return content.encode('utf-8')

    def generate_pdf_bytes(self, audit_report: AuditReport) -> bytes:
        """Generate report as raw bytes suitable for PDF writing."""
        content = self._generate_content(audit_report)
        return content.encode('utf-8')

    def _generate_content(self, report: AuditReport) -> str:
        lines: List[str] = []

        lines.extend(self._generate_title(report))
        lines.extend(self._generate_executive_summary(report))
        lines.extend(self._generate_methodology(report))
        lines.extend(self._generate_findings(report))
        lines.extend(self._generate_statistics(report))
        lines.extend(self._generate_recommendations(report))

        return '\n'.join(lines)

    def _generate_title(self, report: AuditReport) -> List[str]:
        return [
            "=" * 60,
            "SECURITY AUDIT REPORT",
            "=" * 60,
            "",
            f"Contract: {report.contract_name}",
            f"Address: {report.contract_address}",
            f"Date: {time.strftime('%Y-%m-%d', time.localtime(report.audit_date))}",
            "",
            "=" * 60,
            ""
        ]

    def _generate_executive_summary(self, report: AuditReport) -> List[str]:
        counts = report.get_severity_counts()

        return [
            "EXECUTIVE SUMMARY",
            "-" * 60,
            "",
            f"Total Findings: {len(report.vulnerabilities)}",
            f"Critical: {counts.get('critical', 0)}",
            f"High: {counts.get('high', 0)}",
            f"Medium: {counts.get('medium', 0)}",
            f"Low: {counts.get('low', 0)}",
            "",
            "-" * 60,
            ""
        ]

    def _generate_methodology(self, report: AuditReport) -> List[str]:
        return [
            "METHODOLOGY",
            "-" * 60,
            "",
            "1. Static Analysis - Pattern-based vulnerability detection",
            "2. Dynamic Analysis - Runtime behavior testing",
            "3. Manual Code Review - Expert security analysis",
            "4. Gas Analysis - Optimization recommendations",
            "",
            "-" * 60,
            ""
        ]

    def _generate_findings(self, report: AuditReport) -> List[str]:
        lines: List[str] = [
            "FINDINGS",
            "-" * 60,
            ""
        ]

        for vuln in report.vulnerabilities:
            lines.extend([
                f"[{vuln.severity.value.upper()}] {vuln.title}",
                f"Category: {vuln.category}",
                f"Line: {vuln.line_number}",
                "",
                "Description:",
                vuln.description,
                "",
                "Impact:",
                vuln.impact,
                "",
                "Recommendation:",
                vuln.recommendation,
                "",
                "-" * 40,
                ""
            ])

        return lines

    def _generate_statistics(self, report: AuditReport) -> List[str]:
        lines: List[str] = [
            "STATISTICS",
            "-" * 60,
            ""
        ]

        for key, value in report.statistics.items():
            lines.append(f"{key}: {value}")

        return lines

    def _generate_recommendations(self, report: AuditReport) -> List[str]:
        lines: List[str] = [
            "RECOMMENDATIONS",
            "-" * 60,
            ""
        ]

        critical = [v for v in report.vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        high = [v for v in report.vulnerabilities if v.severity == SeverityLevel.HIGH]

        if critical:
            lines.append("CRITICAL PRIORITY:")
            for v in critical:
                lines.append(f"- {v.recommendation}")
            lines.append("")

        if high:
            lines.append("HIGH PRIORITY:")
            for v in high:
                lines.append(f"- {v.recommendation}")

        return lines

    def export_to_file(self, report: AuditReport, filepath: str) -> bool:
        try:
            content = self.generate_report(report)

            with open(filepath, 'wb') as f:
                f.write(content)

            logger.info(f"Report exported to: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

    def generate_cover_page(self, report: AuditReport) -> List[str]:
        date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.audit_date))
        counts = report.get_severity_counts()
        total = sum(counts.values())
        risk = "LOW"
        if counts.get('critical', 0) > 0:
            risk = "CRITICAL"
        elif counts.get('high', 0) > 0:
            risk = "HIGH"
        elif counts.get('medium', 0) > 0:
            risk = "MEDIUM"

        return [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "╔" + "═" * 58 + "╗",
            "║" + " " * 58 + "║",
            "║" + "SECURITY AUDIT REPORT".center(58) + "║",
            "║" + " " * 58 + "║",
            "╚" + "═" * 58 + "╝",
            "",
            "",
            f"  Contract Name:     {report.contract_name}",
            f"  Contract Address:  {report.contract_address}",
            f"  Audit Date:        {date_str}",
            f"  Report ID:         {report.report_id}",
            "",
            f"  Overall Risk:      {risk}",
            f"  Total Findings:    {total}",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]

    def generate_table_of_contents(self, report: AuditReport) -> List[str]:
        lines = [
            "TABLE OF CONTENTS",
            "=" * 60,
            "",
            "  1. Executive Summary",
            "  2. Methodology",
            "  3. Findings Overview",
        ]

        vuln_sections = []
        for idx, vuln in enumerate(report.vulnerabilities, 1):
            vuln_sections.append(f"  3.{idx} {vuln.title}")

        if vuln_sections:
            lines.extend(vuln_sections)

        lines.extend([
            "  4. Detailed Findings",
        ])

        detail_sections = []
        for idx, vuln in enumerate(report.vulnerabilities, 1):
            detail_sections.append(f"  4.{idx} [{vuln.severity.value.upper()}] {vuln.title}")

        if detail_sections:
            lines.extend(detail_sections)

        lines.extend([
            "  5. Statistics",
            "  6. Recommendations",
            "  7. Appendix",
            "",
            "=" * 60,
            "",
        ])

        return lines

    def generate_risk_assessment(self, report: AuditReport) -> List[str]:
        counts = report.get_severity_counts()
        total = sum(counts.values())

        lines = [
            "RISK ASSESSMENT",
            "-" * 60,
            "",
        ]

        if total == 0:
            lines.append("  No vulnerabilities identified.")
            lines.append("")
            return lines

        critical = counts.get('critical', 0)
        high = counts.get('high', 0)
        medium = counts.get('medium', 0)
        low = counts.get('low', 0)
        info = counts.get('info', 0)

        lines.append(f"  Total Findings:  {total}")
        lines.append("")

        for label, count in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low), ("INFO", info)]:
            if count > 0:
                pct = (count / total) * 100
                bar_len = max(1, int(pct / 5))
                bar = "█" * bar_len + "░" * (20 - bar_len)
                lines.append(f"  {label:10s}  {bar}  {count:3d}  ({pct:5.1f}%)")

        lines.append("")

        if critical > 0:
            lines.append("  OVERALL RISK: CRITICAL")
            lines.append("  Immediate remediation required.")
        elif high > 0:
            lines.append("  OVERALL RISK: HIGH")
            lines.append("  Prompt remediation recommended.")
        elif medium > 0:
            lines.append("  OVERALL RISK: MEDIUM")
            lines.append("  Remediation should be planned.")
        else:
            lines.append("  OVERALL RISK: LOW")
            lines.append("  No critical issues found.")

        lines.append("")
        lines.append("-" * 60)
        lines.append("")

        return lines

    def generate_appendix(self, report: AuditReport) -> List[str]:
        lines = [
            "APPENDIX",
            "=" * 60,
            "",
        ]

        if report.statistics:
            lines.append("A. Audit Statistics")
            lines.append("-" * 40)
            for key, value in report.statistics.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

        if report.metadata:
            lines.append("B. Report Metadata")
            lines.append("-" * 40)
            for key, value in report.metadata.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

        lines.append("C. Severity Definitions")
        lines.append("-" * 40)
        lines.append("  CRITICAL  - Exploitable with high impact, immediate action required")
        lines.append("  HIGH      - Significant risk, prompt remediation recommended")
        lines.append("  MEDIUM    - Moderate risk, should be addressed")
        lines.append("  LOW       - Minor issue, recommended improvement")
        lines.append("  INFO      - Informational, no immediate risk")
        lines.append("")

        lines.append("D. CWE Reference")
        lines.append("-" * 40)
        cwe_ids = set()
        for vuln in report.vulnerabilities:
            if vuln.cwe_id:
                cwe_ids.add(vuln.cwe_id)
        if cwe_ids:
            for cwe in sorted(cwe_ids):
                lines.append(f"  {cwe}")
        else:
            lines.append("  No CWE references in this report.")
        lines.append("")

        lines.append("=" * 60)

        return lines

    def generate_full_report(self, report: AuditReport) -> bytes:
        """Generate a complete report with cover, TOC, and all sections."""
        lines: List[str] = []
        lines.extend(self.generate_cover_page(report))
        lines.extend(self.generate_table_of_contents(report))
        lines.extend(self._generate_title(report))
        lines.extend(self._generate_executive_summary(report))
        lines.extend(self.generate_risk_assessment(report))
        lines.extend(self._generate_methodology(report))
        lines.extend(self._generate_findings(report))
        lines.extend(self._generate_statistics(report))
        lines.extend(self._generate_recommendations(report))
        lines.extend(self.generate_appendix(report))
        content = '\n'.join(lines)
        return content.encode('utf-8')

    @staticmethod
    def _get_severity_color_hex(severity: SeverityLevel) -> str:
        color_map = {
            SeverityLevel.CRITICAL: '#dc3545',
            SeverityLevel.HIGH: '#e01020',
            SeverityLevel.MEDIUM: '#ffc107',
            SeverityLevel.LOW: '#198754',
            SeverityLevel.INFO: '#0d6efd',
        }
        return color_map.get(severity, '#6c757d')

    def format_vulnerability_summary_line(self, vuln: VulnerabilityEntry) -> str:
        cvss_str = f"CVSS:{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A"
        cwe_str = vuln.cwe_id or "N/A"
        return (
            f"[{vuln.severity.value.upper():8s}] {vuln.title:<40s} "
            f"Line:{vuln.line_number:<6d} CVSS:{cvss_str:<8s} CWE:{cwe_str}"
        )
