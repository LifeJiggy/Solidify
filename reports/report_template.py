"""
Report Template Module

Provides renderable template classes that produce full report strings
from an :class:`AuditReport`.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .pdf_reporter import (
    AuditReport,
    SeverityLevel,
    VulnerabilityEntry,
)
from .report_formatter import (
    ReportFormatter,
    FormatterConfig,
    SEVERITY_ORDER,
    SEVERITY_LABELS,
)

logger = logging.getLogger(__name__)


class ReportTemplate(ABC):
    """Abstract base for report templates."""

    def __init__(self) -> None:
        self.formatter = ReportFormatter()

    @abstractmethod
    def render(self, report: AuditReport) -> str:
        """Return the full rendered report as a string."""

    @abstractmethod
    def render_header(self, report: AuditReport) -> str:
        """Render the title / metadata block."""

    @abstractmethod
    def render_executive_summary(self, report: AuditReport) -> str:
        """Render a high-level overview."""

    @abstractmethod
    def render_findings(self, report: AuditReport) -> str:
        """Render the detailed findings section."""

    @abstractmethod
    def render_recommendations(self, report: AuditReport) -> str:
        """Render prioritised remediation advice."""

    @abstractmethod
    def render_appendix(self, report: AuditReport) -> str:
        """Render supplementary material."""

    def _sorted_vulns(
        self, vulns: Optional[List[VulnerabilityEntry]] = None, report: Optional[AuditReport] = None
    ) -> List[VulnerabilityEntry]:
        source = vulns if vulns is not None else (report.vulnerabilities if report else [])
        return sorted(source, key=lambda v: SEVERITY_ORDER.get(v.severity.value, 99))


# ======================================================================
# Standard Report Template
# ======================================================================

class StandardReportTemplate(ReportTemplate):
    """Full professional audit report."""

    def render(self, report: AuditReport) -> str:
        parts = [
            self.render_header(report),
            self.render_executive_summary(report),
            self.render_findings(report),
            self.render_recommendations(report),
            self.render_appendix(report),
        ]
        return "\n\n".join(parts)

    def render_header(self, report: AuditReport) -> str:
        date_str = self.formatter.format_timestamp(report.audit_date)
        return (
            "=" * 60 + "\n"
            "SECURITY AUDIT REPORT\n"
            "=" * 60 + "\n\n"
            f"Contract:      {report.contract_name}\n"
            f"Address:       {report.contract_address}\n"
            f"Audit Date:    {date_str}\n"
            f"Report ID:     {report.report_id}\n"
            f"Total Findings: {len(report.vulnerabilities)}\n"
        )

    def render_executive_summary(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        lines = [
            "-" * 60,
            "EXECUTIVE SUMMARY",
            "-" * 60,
            "",
            f"This report covers a security audit of {report.contract_name}.",
            f"A total of {len(report.vulnerabilities)} finding(s) were identified.",
            "",
            self.formatter.format_vulnerability_summary(report.vulnerabilities),
            "",
        ]
        return "\n".join(lines)

    def render_findings(self, report: AuditReport) -> str:
        vulns = self._sorted_vulns(report=report)
        lines = [
            "-" * 60,
            "DETAILED FINDINGS",
            "-" * 60,
            "",
        ]
        for idx, vuln in enumerate(vulns, 1):
            badge = self.formatter.format_severity_badge(vuln.severity)
            cvss = self.formatter.format_cvss_score(vuln.cvss_score)
            cwe = self.formatter.format_cwe_id(vuln.cwe_id)
            lines.extend([
                f"Finding #{idx}: {vuln.title}",
                f"  Severity:  {badge}",
                f"  Category:  {vuln.category}",
                f"  Line:      {vuln.line_number}",
                f"  CVSS:      {cvss}",
                f"  CWE:       {cwe}",
                "",
                f"  Description:",
                f"  {self.formatter.truncate_text(vuln.description, 300)}",
                "",
                f"  Impact:",
                f"  {vuln.impact}",
                "",
                f"  Recommendation:",
                f"  {vuln.recommendation}",
                "",
                "-" * 40,
                "",
            ])
        return "\n".join(lines)

    def render_recommendations(self, report: AuditReport) -> str:
        lines = [
            "-" * 60,
            "RECOMMENDATIONS",
            "-" * 60,
            "",
        ]
        for sev in ("critical", "high", "medium", "low"):
            vulns = [v for v in report.vulnerabilities if v.severity.value == sev]
            if not vulns:
                continue
            label = SEVERITY_LABELS.get(sev, sev)
            lines.append(f"{label.upper()} PRIORITY:")
            for v in vulns:
                lines.append(f"  - [{v.vuln_id}] {v.recommendation}")
            lines.append("")
        return "\n".join(lines)

    def render_appendix(self, report: AuditReport) -> str:
        lines = [
            "-" * 60,
            "APPENDIX",
            "-" * 60,
            "",
        ]
        if report.statistics:
            lines.append("Audit Statistics:")
            for k, v in report.statistics.items():
                lines.append(f"  {k}: {v}")
            lines.append("")
        if report.metadata:
            lines.append("Metadata:")
            for k, v in report.metadata.items():
                lines.append(f"  {k}: {v}")
        return "\n".join(lines)


# ======================================================================
# Executive Report Template
# ======================================================================

class ExecutiveReportTemplate(ReportTemplate):
    """High-level summary aimed at non-technical stakeholders."""

    def render(self, report: AuditReport) -> str:
        parts = [
            self.render_header(report),
            self.render_executive_summary(report),
            self.render_findings(report),
            self.render_recommendations(report),
            self.render_appendix(report),
        ]
        return "\n\n".join(parts)

    def render_header(self, report: AuditReport) -> str:
        date_str = self.formatter.format_timestamp(report.audit_date)
        return (
            "=" * 60 + "\n"
            "EXECUTIVE AUDIT SUMMARY\n"
            "=" * 60 + "\n\n"
            f"Contract:   {report.contract_name}\n"
            f"Date:       {date_str}\n"
            f"Findings:   {len(report.vulnerabilities)}\n"
        )

    def render_executive_summary(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)

        risk = "LOW"
        if crit > 0:
            risk = "CRITICAL"
        elif high > 0:
            risk = "HIGH"
        elif counts.get("medium", 0) > 0:
            risk = "MEDIUM"

        lines = [
            "RISK OVERVIEW",
            "-" * 40,
            "",
            f"Overall Risk Level: {risk}",
            f"Total Findings:     {len(report.vulnerabilities)}",
            "",
            self.formatter.format_risk_matrix(counts),
            "",
        ]
        return "\n".join(lines)

    def render_findings(self, report: AuditReport) -> str:
        vulns = self._sorted_vulns(report=report)
        lines = ["FINDINGS SUMMARY", "-" * 40, ""]
        for v in vulns:
            badge = self.formatter.format_severity_badge(v.severity)
            lines.append(f"  {badge}  {v.title}")
        return "\n".join(lines)

    def render_recommendations(self, report: AuditReport) -> str:
        crit_high = [v for v in report.vulnerabilities if v.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]
        lines = ["KEY ACTIONS", "-" * 40, ""]
        if crit_high:
            for v in crit_high:
                lines.append(f"  - {v.title}: {self.formatter.truncate_text(v.recommendation, 120)}")
        else:
            lines.append("  No critical or high-priority items require immediate action.")
        return "\n".join(lines)

    def render_appendix(self, report: AuditReport) -> str:
        return ""


# ======================================================================
# Minimal Report Template
# ======================================================================

class MinimalReportTemplate(ReportTemplate):
    """Condensed findings-only report."""

    def render(self, report: AuditReport) -> str:
        parts = [
            self.render_header(report),
            self.render_executive_summary(report),
            self.render_findings(report),
            self.render_recommendations(report),
            self.render_appendix(report),
        ]
        return "\n\n".join(parts)

    def render_header(self, report: AuditReport) -> str:
        date_str = self.formatter.format_timestamp(report.audit_date)
        return (
            f"# {report.contract_name} — Security Audit\n\n"
            f"Date: {date_str} | Findings: {len(report.vulnerabilities)}\n"
        )

    def render_executive_summary(self, report: AuditReport) -> str:
        return self.formatter.format_vulnerability_summary(report.vulnerabilities)

    def render_findings(self, report: AuditReport) -> str:
        vulns = self._sorted_vulns(report=report)
        lines = ["## Findings", ""]
        for v in vulns:
            badge = self.formatter.format_severity_badge(v.severity)
            lines.append(f"- **{v.title}** ({badge}) — Line {v.line_number}")
        return "\n".join(lines)

    def render_recommendations(self, report: AuditReport) -> str:
        lines = ["## Recommendations", ""]
        for v in self._sorted_vulns(report=report):
            lines.append(f"- {v.recommendation}")
        return "\n".join(lines)

    def render_appendix(self, report: AuditReport) -> str:
        return ""


# ======================================================================
# Detailed Report Template
# ======================================================================

class DetailedReportTemplate(ReportTemplate):
    """Exhaustive report with code snippets and methodology."""

    def render(self, report: AuditReport) -> str:
        parts = [
            self.render_header(report),
            self.render_executive_summary(report),
            self._render_methodology(),
            self.render_findings(),
            self.render_recommendations(report),
            self.render_appendix(report),
        ]
        return "\n\n".join(parts)

    def render_header(self, report: AuditReport) -> str:
        date_str = self.formatter.format_timestamp(report.audit_date)
        return (
            "=" * 70 + "\n"
            "DETAILED SECURITY AUDIT REPORT\n"
            "=" * 70 + "\n\n"
            f"Contract:       {report.contract_name}\n"
            f"Address:        {report.contract_address}\n"
            f"Audit Date:     {date_str}\n"
            f"Report ID:      {report.report_id}\n"
            f"Total Findings: {len(report.vulnerabilities)}\n"
        )

    def render_executive_summary(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        lines = [
            "-" * 70,
            "EXECUTIVE SUMMARY",
            "-" * 70,
            "",
            f"A comprehensive security audit was performed on {report.contract_name}.",
            f"The audit identified {len(report.vulnerabilities)} issue(s) across "
            f"{len(report.sections)} section(s).",
            "",
            self.formatter.format_vulnerability_summary(report.vulnerabilities),
            "",
            self.formatter.format_risk_matrix(counts),
            "",
        ]
        return "\n".join(lines)

    def _render_methodology(self) -> str:
        return (
            "-" * 70 + "\n"
            "METHODOLOGY\n"
            "-" * 70 + "\n\n"
            "1. Automated Static Analysis\n"
            "   Pattern-based detection of known vulnerability classes.\n\n"
            "2. Manual Code Review\n"
            "   Line-by-line expert review of contract logic.\n\n"
            "3. Dynamic Analysis\n"
            "   Runtime behaviour testing and state transition validation.\n\n"
            "4. Gas Optimisation Review\n"
            "   Identification of gas-efficient alternatives.\n\n"
            "5. Access Control Audit\n"
            "   Verification of role-based permissions and privilege escalation paths.\n"
        )

    def render_findings(self, report: Optional[AuditReport] = None) -> str:
        vulns = self._sorted_vulns(report=report)
        lines = [
            "-" * 70,
            "DETAILED FINDINGS",
            "-" * 70,
            "",
        ]
        for idx, vuln in enumerate(vulns, 1):
            badge = self.formatter.format_severity_badge(vuln.severity)
            cvss = self.formatter.format_cvss_score(vuln.cvss_score)
            cwe = self.formatter.format_cwe_id(vuln.cwe_id)
            lines.extend([
                f"[{idx}] {vuln.title}",
                f"    Vuln ID:   {vuln.vuln_id}",
                f"    Severity:  {badge}",
                f"    Category:  {vuln.category}",
                f"    Line:      {vuln.line_number}",
                f"    CVSS:      {cvss}",
                f"    CWE:       {cwe}",
                "",
                "    Description:",
                f"    {vuln.description}",
                "",
                "    Impact:",
                f"    {vuln.impact}",
                "",
            ])
            if vuln.code_snippet:
                lines.extend([
                    "    Code Snippet:",
                    self.formatter.format_code_block(vuln.code_snippet),
                    "",
                ])
            lines.extend([
                "    Recommendation:",
                f"    {vuln.recommendation}",
                "",
                "=" * 50,
                "",
            ])
        return "\n".join(lines)

    def render_recommendations(self, report: AuditReport) -> str:
        lines = [
            "-" * 70,
            "RECOMMENDATIONS",
            "-" * 70,
            "",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            vulns = [v for v in report.vulnerabilities if v.severity.value == sev]
            if not vulns:
                continue
            label = SEVERITY_LABELS.get(sev, sev)
            lines.append(f"{label.upper()} PRIORITY:")
            for v in vulns:
                lines.append(f"  [{v.vuln_id}] {v.title}")
                lines.append(f"    → {v.recommendation}")
            lines.append("")
        return "\n".join(lines)

    def render_appendix(self, report: AuditReport) -> str:
        lines = [
            "-" * 70,
            "APPENDIX",
            "-" * 70,
            "",
        ]
        if report.statistics:
            lines.append("Audit Statistics:")
            for k, v in report.statistics.items():
                lines.append(f"  {k}: {v}")
            lines.append("")
        if report.sections:
            lines.append("Report Sections:")
            for s in sorted(report.sections, key=lambda x: x.order):
                lines.append(f"  [{s.order}] {s.title}")
            lines.append("")
        if report.metadata:
            lines.append("Additional Metadata:")
            for k, v in report.metadata.items():
                lines.append(f"  {k}: {v}")
        return "\n".join(lines)


# ======================================================================
# Template Registry
# ======================================================================

class _TemplateRegistry:
    """Singleton registry for report templates."""

    _instance: Optional["_TemplateRegistry"] = None

    def __new__(cls) -> "_TemplateRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._templates: Dict[str, ReportTemplate] = {}
            cls._instance._register_defaults()
        return cls._instance

    def _register_defaults(self) -> None:
        self._templates["standard"] = StandardReportTemplate()
        self._templates["executive"] = ExecutiveReportTemplate()
        self._templates["minimal"] = MinimalReportTemplate()
        self._templates["detailed"] = DetailedReportTemplate()

    def get_template(self, name: str) -> Optional[ReportTemplate]:
        return self._templates.get(name)

    def register(self, name: str, template: ReportTemplate) -> None:
        self._templates[name] = template

    def list_templates(self) -> List[str]:
        return list(self._templates.keys())


TemplateRegistry = _TemplateRegistry
