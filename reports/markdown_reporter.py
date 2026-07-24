"""
Markdown Report Reporter

Generates GitHub-Flavoured Markdown (GFM) audit reports with tables,
task-lists, and anchor-linked tables of contents.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional

from .pdf_reporter import (
    AuditReport,
    ReportFormat,
    SeverityLevel,
    VulnerabilityEntry,
)
from .reporter import BaseReporter
from .report_formatter import (
    ReportFormatter,
    FormatterConfig,
    SEVERITY_ORDER,
    SEVERITY_LABELS,
    SEVERITY_EMOJIS,
)

logger = logging.getLogger(__name__)


class MarkdownReporter(BaseReporter):
    """Produces GFM-compatible Markdown audit reports."""

    def __init__(self) -> None:
        super().__init__()
        self._formatter = ReportFormatter()

    def get_format(self) -> ReportFormat:
        return ReportFormat.MARKDOWN

    def generate(self, report: AuditReport) -> bytes:
        return self._generate_markdown_content(report).encode('utf-8')

    def generate_to_file(self, report: AuditReport, filepath: str) -> bool:
        try:
            content = self._generate_markdown_content(report)
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write(content)
            logger.info("Markdown report written to %s", filepath)
            return True
        except Exception as exc:
            logger.error("Markdown export failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _generate_markdown_content(self, report: AuditReport) -> str:
        parts = [
            self._render_toc(report),
            self._render_header(report),
            self._render_executive_summary(report),
            self._render_vulnerability_table(report.vulnerabilities),
            self._render_findings_detail(report.vulnerabilities),
            self._render_checklist(report.vulnerabilities),
            self._render_recommendations(report),
            self._render_appendix(report),
        ]
        return "\n\n".join(p for p in parts if p)

    def _render_header(self, report: AuditReport) -> str:
        date_str = self._formatter.format_timestamp(report.audit_date)
        return (
            f"# Security Audit Report\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| Contract | `{self._escape(report.contract_name)}` |\n"
            f"| Address | `{self._escape(report.contract_address)}` |\n"
            f"| Date | {date_str} |\n"
            f"| Report ID | `{self._escape(report.report_id)}` |\n"
            f"| Total Findings | {len(report.vulnerabilities)} |\n"
        )

    def _render_toc(self, report: AuditReport) -> str:
        lines = ["## Table of Contents\n"]
        lines.append("- [Executive Summary](#executive-summary)")
        lines.append("- [Findings Table](#findings-table)")
        lines.append("- [Detailed Findings](#detailed-findings)")
        lines.append("- [Checklist](#checklist)")
        lines.append("- [Recommendations](#recommendations)")
        if report.statistics or report.metadata:
            lines.append("- [Appendix](#appendix)")
        lines.append("")
        for idx, v in enumerate(report.vulnerabilities, 1):
            anchor = self._slugify(v.title)
            lines.append(f"  - [{self._escape(v.title)}](#{anchor})")
        return "\n".join(lines)

    def _render_executive_summary(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        lines = [
            "## Executive Summary\n",
            f"A total of **{len(report.vulnerabilities)}** finding(s) were identified "
            f"in `{self._escape(report.contract_name)}`.\n",
        ]
        badge_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c:
                badge = self._render_severity_badge(SeverityLevel(sev))
                badge_parts.append(f"{badge} **{c}**")
        if badge_parts:
            lines.append(" | ".join(badge_parts) + "\n")
        return "\n".join(lines)

    def _render_vulnerability_table(self, vulns: List[VulnerabilityEntry]) -> str:
        if not vulns:
            return ""
        sorted_vulns = self._sort(vulns)
        lines = [
            "## Findings Table\n",
            "| # | Severity | Title | Category | Line | CVSS | CWE |",
            "|---|----------|-------|----------|------|------|-----|",
        ]
        for idx, v in enumerate(sorted_vulns, 1):
            badge = self._render_severity_badge(v.severity)
            cvss = self._formatter.format_cvss_score(v.cvss_score)
            cwe = self._formatter.format_cwe_id(v.cwe_id)
            anchor = self._slugify(v.title)
            lines.append(
                f"| {idx} | {badge} | [{self._escape(v.title)}](#{anchor}) "
                f"| {self._escape(v.category)} | {v.line_number} "
                f"| {self._escape(cvss)} | {self._escape(cwe)} |"
            )
        return "\n".join(lines)

    def _render_findings_detail(self, vulns: List[VulnerabilityEntry]) -> str:
        sorted_vulns = self._sort(vulns)
        lines = ["## Detailed Findings\n"]
        for idx, v in enumerate(sorted_vulns, 1):
            badge = self._render_severity_badge(v.severity)
            lines.extend([
                f"### {idx}. {self._escape(v.title)} {badge}\n",
                f"- **ID:** `{self._escape(v.vuln_id)}`",
                f"- **Category:** {self._escape(v.category)}",
                f"- **Line:** {v.line_number}",
                f"- **CVSS:** {self._escape(self._formatter.format_cvss_score(v.cvss_score))}",
                f"- **CWE:** {self._escape(self._formatter.format_cwe_id(v.cwe_id))}",
                "",
                f"**Description:**\n\n{self._escape(v.description)}\n",
                f"**Impact:**\n\n{self._escape(v.impact)}\n",
            ])
            if v.code_snippet:
                lines.append("**Code Snippet:**\n")
                lines.append(self._render_code_block(v.code_snippet))
                lines.append("")
            lines.extend([
                "**Recommendation:**",
                "",
                f"> {self._escape(v.recommendation)}",
                "",
                "---",
                "",
            ])
        return "\n".join(lines)

    def _render_checklist(self, vulns: List[VulnerabilityEntry]) -> str:
        sorted_vulns = self._sort(vulns)
        lines = ["## Checklist\n"]
        for v in sorted_vulns:
            badge = self._render_severity_badge(v.severity)
            lines.append(f"- [ ] {badge} {self._escape(v.title)}")
        return "\n".join(lines)

    def _render_recommendations(self, report: AuditReport) -> str:
        lines = ["## Recommendations\n"]
        for sev in ("critical", "high", "medium", "low", "info"):
            vulns = [v for v in report.vulnerabilities if v.severity.value == sev]
            if not vulns:
                continue
            label = SEVERITY_LABELS.get(sev, sev)
            lines.append(f"### {label} Priority\n")
            for v in vulns:
                lines.append(f"- **{self._escape(v.title)}:** {self._escape(v.recommendation)}")
            lines.append("")
        return "\n".join(lines)

    def _render_appendix(self, report: AuditReport) -> str:
        parts: List[str] = []
        if report.statistics:
            parts.append("## Appendix\n### Statistics\n")
            for k, v in report.statistics.items():
                parts.append(f"- **{self._escape(str(k))}:** {self._escape(str(v))}")
            parts.append("")
        if report.metadata:
            if not parts:
                parts.append("## Appendix\n")
            parts.append("### Metadata\n")
            for k, v in report.metadata.items():
                parts.append(f"- **{self._escape(str(k))}:** {self._escape(str(v))}")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def generate_github_readme(self, report: AuditReport) -> str:
        """Return a GitHub-optimised README string."""
        return self._generate_markdown_content(report)

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _render_vulnerability_table_standalone(self, vulns: List[VulnerabilityEntry]) -> str:
        return self._render_vulnerability_table(vulns)

    def _render_severity_badge(self, severity: SeverityLevel) -> str:
        emoji = SEVERITY_EMOJIS.get(severity.value, "")
        label = SEVERITY_LABELS.get(severity.value, severity.value)
        return f"{emoji} **{label}**"

    def _render_code_block(self, code: str, language: str = "solidity") -> str:
        safe = self._escape(code)
        return f"```{language}\n{safe}\n```"

    @staticmethod
    def _escape(text: str) -> str:
        """Escape pipe characters for Markdown table cells."""
        return text.replace("|", "\\|")

    @staticmethod
    def _slugify(text: str) -> str:
        slug = text.lower().strip()
        slug = re.sub(r"[^\w\s-]", "", slug)
        slug = re.sub(r"[\s_]+", "-", slug)
        return slug.strip("-")

    @staticmethod
    def _sort(vulns: List[VulnerabilityEntry]) -> List[VulnerabilityEntry]:
        return sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity.value, 99))

    def _render_methodology(self) -> str:
        return (
            "## Methodology\n\n"
            "1. **Static Analysis** — Pattern-based vulnerability detection\n"
            "2. **Dynamic Analysis** — Runtime behaviour testing\n"
            "3. **Manual Code Review** — Expert security analysis\n"
            "4. **Gas Optimisation** — Efficiency recommendations\n"
        )

    def _render_category_summary(self, vulns: List[VulnerabilityEntry]) -> str:
        categories: Dict[str, int] = {}
        for v in vulns:
            categories[v.category] = categories.get(v.category, 0) + 1
        if not categories:
            return ""
        lines = ["## Findings by Category\n"]
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- **{self._escape(cat)}:** {count}")
        return "\n".join(lines)

    def _render_risk_assessment(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        risk = self._get_risk_level(counts)
        total = sum(counts.values())
        lines = [
            "## Risk Assessment\n",
            f"**Overall Risk Level:** {risk}\n",
            f"**Total Findings:** {total}\n",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c > 0:
                badge = self._render_severity_badge(SeverityLevel(sev))
                pct = (c / total) * 100 if total > 0 else 0
                bar_len = max(1, int(pct / 5))
                bar = "█" * bar_len + "░" * (20 - bar_len)
                lines.append(f"- {badge} `{bar}` {c} ({pct:.1f}%)")
        return "\n".join(lines)

    def _render_severity_breakdown_table(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        total = sum(counts.values())
        lines = [
            "## Severity Breakdown\n",
            "| Severity | Count | Percentage |",
            "|----------|-------|------------|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            badge = self._render_severity_badge(SeverityLevel(sev))
            pct = f"{(c / total) * 100:.1f}%" if total > 0 else "0.0%"
            lines.append(f"| {badge} | {c} | {pct} |")
        lines.append(f"| **Total** | **{total}** | **100.0%** |")
        return "\n".join(lines)

    def _render_cvss_summary(self, vulns: List[VulnerabilityEntry]) -> str:
        scores = [v.cvss_score for v in vulns if v.cvss_score is not None]
        if not scores:
            return ""
        avg = sum(scores) / len(scores)
        mx = max(scores)
        mn = min(scores)
        lines = [
            "## CVSS Summary\n",
            f"- **Average CVSS:** {avg:.2f}",
            f"- **Max CVSS:** {mx:.2f}",
            f"- **Min CVSS:** {mn:.2f}",
            f"- **Vulns with CVSS:** {len(scores)}",
        ]
        return "\n".join(lines)

    def _render_cwe_summary(self, vulns: List[VulnerabilityEntry]) -> str:
        cwe_counts: Dict[str, int] = {}
        for v in vulns:
            if v.cwe_id:
                cwe_counts[v.cwe_id] = cwe_counts.get(v.cwe_id, 0) + 1
        if not cwe_counts:
            return ""
        lines = ["## CWE Summary\n"]
        for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- **{self._escape(cwe)}:** {count} finding(s)")
        return "\n".join(lines)

    def _render_line_distribution(self, vulns: List[VulnerabilityEntry]) -> str:
        if not vulns:
            return ""
        lines_list = sorted(v.line_number for v in vulns)
        min_line = lines_list[0]
        max_line = lines_list[-1]
        avg_line = sum(lines_list) / len(lines_list)
        return (
            "## Line Distribution\n\n"
            f"- **First finding:** Line {min_line}\n"
            f"- **Last finding:** Line {max_line}\n"
            f"- **Average line:** {avg_line:.0f}\n"
        )

    def generate_summary_only(self, report: AuditReport) -> str:
        parts = [
            self._render_header(report),
            self._render_executive_summary(report),
            self._render_risk_assessment(report),
            self._render_severity_breakdown_table(report),
        ]
        return "\n\n".join(p for p in parts if p)

    def generate_findings_only(self, report: AuditReport) -> str:
        parts = [
            self._render_vulnerability_table(report.vulnerabilities),
            self._render_findings_detail(report.vulnerabilities),
        ]
        return "\n\n".join(p for p in parts if p)

    def generate_appendix_only(self, report: AuditReport) -> str:
        parts = [
            self._render_category_summary(report.vulnerabilities),
            self._render_cvss_summary(report.vulnerabilities),
            self._render_cwe_summary(report.vulnerabilities),
            self._render_line_distribution(report.vulnerabilities),
            self._render_appendix(report),
        ]
        return "\n\n".join(p for p in parts if p)

    @staticmethod
    def _get_risk_level(counts: Dict[str, int]) -> str:
        if counts.get('critical', 0) > 0:
            return "CRITICAL"
        if counts.get('high', 0) > 0:
            return "HIGH"
        if counts.get('medium', 0) > 0:
            return "MEDIUM"
        return "LOW"
