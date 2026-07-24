"""
HTML Report Reporter

Generates standalone HTML5 reports with inline CSS and severity-coloured
vulnerability cards.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import html
import logging
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
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    SEVERITY_EMOJIS,
)

logger = logging.getLogger(__name__)

_INLINE_CSS = """\
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#212529;background:#f8f9fa;line-height:1.6}
.container{max-width:960px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.8rem;border-bottom:3px solid #0d6efd;padding-bottom:.5rem}
h2{font-size:1.4rem;margin:1.5rem 0 .75rem;color:#333}
h3{font-size:1.15rem;margin:1rem 0 .5rem}
.header{text-align:center;margin-bottom:2rem}
.meta{color:#6c757d;font-size:.9rem}
.summary{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.stat-card{flex:1;min-width:120px;padding:1rem;border-radius:8px;text-align:center;color:#fff;font-weight:700}
.stat-card .count{font-size:2rem}
.stat-card .label{font-size:.85rem;opacity:.9}
.sev-critical{background:#dc3545}
.sev-high{background:#e01020}
.sev-medium{background:#ffc107;color:#212529}
.sev-low{background:#198754}
.sev-info{background:#0d6efd}
.vuln-card{background:#fff;border-radius:8px;padding:1.25rem;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,.12)}
.vuln-card .badge{display:inline-block;padding:.25rem .6rem;border-radius:4px;color:#fff;font-size:.8rem;font-weight:600}
.vuln-card .meta{font-size:.85rem;color:#6c757d;margin-bottom:.5rem}
.vuln-card .desc{margin:.5rem 0}
.vuln-card pre{background:#272822;color:#f8f8f2;padding:1rem;border-radius:6px;overflow-x:auto;font-size:.85rem}
.vuln-card .recommendation{background:#e7f1ff;padding:.75rem 1rem;border-left:4px solid #0d6efd;border-radius:4px;margin-top:.75rem}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.6rem .75rem;text-align:left;border-bottom:1px solid #dee2e6}
th{background:#e9ecef;font-weight:600}
.footer{text-align:center;color:#adb5bd;font-size:.8rem;margin-top:3rem;padding-top:1rem;border-top:1px solid #dee2e6}
@media print{body{background:#fff}.vuln-card{box-shadow:none;border:1px solid #dee2even}}
"""


class HTMLReporter(BaseReporter):
    """Produces standalone HTML5 audit reports."""

    def __init__(self) -> None:
        super().__init__()
        self._formatter = ReportFormatter()

    def get_format(self) -> ReportFormat:
        return ReportFormat.HTML

    def generate(self, report: AuditReport) -> bytes:
        return self._generate_html_content(report).encode('utf-8')

    def generate_to_file(self, report: AuditReport, filepath: str) -> bool:
        try:
            content = self._generate_html_content(report)
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write(content)
            logger.info("HTML report written to %s", filepath)
            return True
        except Exception as exc:
            logger.error("HTML export failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal rendering
    # ------------------------------------------------------------------

    def _generate_html_content(self, report: AuditReport) -> str:
        severity_counts = report.get_severity_counts()
        cards = "\n".join(
            self._render_vulnerability_card(v) for v in report.vulnerabilities
        )
        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "<meta charset=\"UTF-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
            f"<title>Security Audit — {html.escape(report.contract_name)}</title>\n"
            f"<style>\n{_INLINE_CSS}</style>\n"
            "</head>\n<body>\n"
            f"<div class=\"container\">\n"
            f"{self._render_executive_summary(report)}\n"
            f"{self._render_severity_chart(severity_counts)}\n"
            "<h2>Findings</h2>\n"
            f"{cards}\n"
            f"{self._render_recommendations(report)}\n"
            f"{self._render_footer(report)}\n"
            "</div>\n</body>\n</html>"
        )

    def _render_vulnerability_card(self, vuln: VulnerabilityEntry) -> str:
        sev_val = vuln.severity.value
        color = SEVERITY_COLORS.get(sev_val, "#6c757d")
        label = SEVERITY_LABELS.get(sev_val, sev_val)
        emoji = SEVERITY_EMOJIS.get(sev_val, "")
        cvss = self._formatter.format_cvss_score(vuln.cvss_score)
        cwe = self._formatter.format_cwe_id(vuln.cwe_id)
        code_html = ""
        if vuln.code_snippet:
            code_html = self._render_code_snippet(vuln.code_snippet)
        rec_html = html.escape(vuln.recommendation)

        return (
            "<div class=\"vuln-card\">\n"
            f"  <span class=\"badge\" style=\"background:{color}\">{emoji} {html.escape(label)}</span>\n"
            f"  <h3>{html.escape(vuln.title)}</h3>\n"
            f"  <div class=\"meta\">Category: {html.escape(vuln.category)} | Line: {vuln.line_number} | CVSS: {html.escape(cvss)} | CWE: {html.escape(cwe)}</div>\n"
            f"  <div class=\"desc\">{html.escape(vuln.description)}</div>\n"
            f"  <div class=\"desc\"><strong>Impact:</strong> {html.escape(vuln.impact)}</div>\n"
            f"  {code_html}\n"
            f"  <div class=\"recommendation\"><strong>Recommendation:</strong> {rec_html}</div>\n"
            "</div>\n"
        )

    def _render_severity_chart(self, severity_counts: Dict[str, int]) -> str:
        total = sum(severity_counts.values())
        if total == 0:
            return "<p>No findings.</p>\n"
        items: List[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count == 0:
                continue
            color = SEVERITY_COLORS.get(sev, "#6c757d")
            label = SEVERITY_LABELS.get(sev, sev)
            pct = (count / total) * 100
            items.append(
                f"<rect x=\"0\" y=\"0\" width=\"{pct}\" height=\"24\" fill=\"{color}\" rx=\"4\"/>"
            )

        svg_width = max(100, total * 20)
        rects = ""
        x_offset = 0
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count == 0:
                continue
            color = SEVERITY_COLORS.get(sev, "#6c757d")
            label = SEVERITY_LABELS.get(sev, sev)
            pct = (count / total) * 100
            bar_w = max(1, pct)
            rects += (
                f'<rect x="{x_offset}" y="0" width="{bar_w}" height="24" fill="{color}" rx="4"/>'
                f'<text x="{x_offset + bar_w / 2}" y="16" text-anchor="middle" fill="#fff" font-size="11" font-weight="600">{label}: {count}</text>'
            )
            x_offset += bar_w

        return (
            "<h2>Severity Distribution</h2>\n"
            f'<svg viewBox="0 0 {int(x_offset)} 24" style="width:100%;height:24px;margin:.5rem 0">{rects}</svg>\n'
            f'<div class="meta">Total: {total}</div>\n'
        )

    def _render_executive_summary(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        cards = ""
        for sev in ("critical", "high", "medium", "low", "info"):
            count = counts.get(sev, 0)
            color_cls = f"sev-{sev}"
            label = SEVERITY_LABELS.get(sev, sev)
            cards += (
                f'<div class="stat-card {color_cls}">'
                f'<div class="count">{count}</div>'
                f'<div class="label">{label}</div></div>\n'
            )
        return (
            "<div class=\"header\">\n"
            f"<h1>Security Audit Report</h1>\n"
            f"<div class=\"meta\">{html.escape(report.contract_name)} — {html.escape(report.contract_address)}</div>\n"
            f"<div class=\"meta\">{self._formatter.format_timestamp(report.audit_date)}</div>\n"
            "</div>\n"
            f'<div class="summary">{cards}</div>\n'
        )

    def _render_code_snippet(self, code: str) -> str:
        safe = html.escape(code)
        return f"<pre><code>{safe}</code></pre>"

    def _render_recommendations(self, report: AuditReport) -> str:
        lines = ["<h2>Recommendations</h2>\n"]
        for v in report.vulnerabilities:
            color = SEVERITY_COLORS.get(v.severity.value, "#6c757d")
            label = SEVERITY_LABELS.get(v.severity.value, v.severity.value)
            lines.append(
                f'<div style="margin:.5rem 0;padding:.5rem;border-left:4px solid {color}">'
                f"<strong>{html.escape(label)}</strong> — {html.escape(v.title)}: "
                f"{html.escape(v.recommendation)}</div>"
            )
        return "\n".join(lines)

    def _render_footer(self, report: AuditReport) -> str:
        return (
            '<div class="footer">'
            f"Solidify Security Audit | {html.escape(report.contract_name)} | "
            f"{self._formatter.format_timestamp(report.audit_date)}"
            "</div>"
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def generate_printable_version(self, report: AuditReport) -> str:
        """Return an HTML string with print-friendly CSS."""
        content = self._generate_html_content(report)
        print_css = "\n@media print{body{background:#fff;font-size:10pt}.vuln-card{box-shadow:none;border:1px solid #ccc;break-inside:avoid}}\n"
        return content.replace("</style>", print_css + "</style>")

    def export_standalone_html(self, report: AuditReport, filepath: str) -> bool:
        """Write a single-file HTML report with embedded CSS."""
        return self.generate_to_file(report, filepath)

    def _render_methodology_section(self) -> str:
        return (
            "<h2>Methodology</h2>\n"
            "<div style=\"background:#f8f9fa;padding:1rem;border-radius:6px;margin:1rem 0\">\n"
            "<ol>\n"
            "<li><strong>Static Analysis</strong> — Pattern-based vulnerability detection</li>\n"
            "<li><strong>Dynamic Analysis</strong> — Runtime behaviour testing</li>\n"
            "<li><strong>Manual Code Review</strong> — Expert security analysis</li>\n"
            "<li><strong>Gas Optimisation</strong> — Efficiency recommendations</li>\n"
            "</ol>\n"
            "</div>\n"
        )

    def _render_statistics_table(self, report: AuditReport) -> str:
        if not report.statistics:
            return ""
        rows = ""
        for key, value in report.statistics.items():
            rows += (
                f"<tr><td>{html.escape(str(key))}</td>"
                f"<td>{html.escape(str(value))}</td></tr>\n"
            )
        return (
            "<h2>Statistics</h2>\n"
            "<table>\n"
            "<thead><tr><th>Metric</th><th>Value</th></tr></thead>\n"
            f"<tbody>\n{rows}</tbody>\n"
            "</table>\n"
        )

    def _render_category_breakdown(self, report: AuditReport) -> str:
        categories: Dict[str, int] = {}
        for v in report.vulnerabilities:
            categories[v.category] = categories.get(v.category, 0) + 1
        if not categories:
            return ""
        rows = ""
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            rows += (
                f"<tr><td>{html.escape(cat)}</td>"
                f"<td>{count}</td></tr>\n"
            )
        return (
            "<h2>Findings by Category</h2>\n"
            "<table>\n"
            "<thead><tr><th>Category</th><th>Count</th></tr></thead>\n"
            f"<tbody>\n{rows}</tbody>\n"
            "</table>\n"
        )

    def _render_toc(self, report: AuditReport) -> str:
        items = '<li><a href="#summary">Executive Summary</a></li>\n'
        items += '<li><a href="#distribution">Severity Distribution</a></li>\n'
        items += '<li><a href="#findings">Findings</a></li>\n'
        for idx, v in enumerate(report.vulnerabilities, 1):
            anchor = f"vuln-{idx}"
            items += f'<li><a href="#{anchor}">{html.escape(v.title)}</a></li>\n'
        items += '<li><a href="#recommendations">Recommendations</a></li>\n'
        if report.statistics:
            items += '<li><a href="#statistics">Statistics</a></li>\n'
        return (
            "<nav style=\"background:#e9ecef;padding:1rem;border-radius:6px;margin:1rem 0\">\n"
            "<strong>Table of Contents</strong>\n"
            f"<ul style=\"list-style:none;padding-left:1rem\">\n{items}</ul>\n"
            "</nav>\n"
        )

    def _render_appendix(self, report: AuditReport) -> str:
        if not report.metadata:
            return ""
        rows = ""
        for key, value in report.metadata.items():
            rows += (
                f"<tr><td>{html.escape(str(key))}</td>"
                f"<td>{html.escape(str(value))}</td></tr>\n"
            )
        return (
            "<h2>Appendix</h2>\n"
            "<table>\n"
            "<thead><tr><th>Key</th><th>Value</th></tr></thead>\n"
            f"<tbody>\n{rows}</tbody>\n"
            "</table>\n"
        )

    def _render_severity_bar_inline(self, severity: SeverityLevel, count: int) -> str:
        color = SEVERITY_COLORS.get(severity.value, "#6c757d")
        label = SEVERITY_LABELS.get(severity.value, severity.value)
        width = max(10, count * 20)
        return (
            f'<div style="display:flex;align-items:center;gap:.5rem;margin:.25rem 0">'
            f'<div style="width:80px;font-size:.85rem">{label}</div>'
            f'<div style="background:{color};width:{width}px;height:16px;border-radius:3px"></div>'
            f'<div style="font-size:.85rem;font-weight:600">{count}</div>'
            f'</div>'
        )

    def _render_severity_bars(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        bars = ""
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c > 0:
                sev_enum = SeverityLevel(sev)
                bars += self._render_severity_bar_inline(sev_enum, c)
        return (
            "<h2>Severity Overview</h2>\n"
            f'<div style="background:#f8f9fa;padding:1rem;border-radius:6px">{bars}</div>\n'
        )

    def generate_interactive_report(self, report: AuditReport) -> str:
        """Return an HTML string with basic JS filtering."""
        base = self._generate_html_content(report)
        js = (
            "\n<script>\n"
            "document.querySelectorAll('.vuln-card').forEach(card => {\n"
            "  card.addEventListener('click', () => card.classList.toggle('expanded'));\n"
            "});\n"
            "</script>\n"
        )
        return base.replace("</body>", js + "\n</body>")

    def _render_category_table(self, report: AuditReport) -> str:
        categories: Dict[str, int] = {}
        for v in report.vulnerabilities:
            categories[v.category] = categories.get(v.category, 0) + 1
        if not categories:
            return ""
        rows = ""
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            rows += (
                f"<tr><td>{html.escape(cat)}</td><td>{count}</td></tr>\n"
            )
        return (
            "<h2>Categories</h2>\n"
            "<table>\n<thead><tr><th>Category</th><th>Count</th></tr></thead>\n"
            f"<tbody>\n{rows}</tbody>\n</table>\n"
        )

    def _render_risk_gauge(self, report: AuditReport) -> str:
        counts = report.get_severity_counts()
        risk = "LOW"
        color = "#198754"
        if counts.get('critical', 0) > 0:
            risk = "CRITICAL"
            color = "#dc3545"
        elif counts.get('high', 0) > 0:
            risk = "HIGH"
            color = "#e01020"
        elif counts.get('medium', 0) > 0:
            risk = "MEDIUM"
            color = "#ffc107"
        return (
            '<div style="text-align:center;padding:1.5rem;margin:1rem 0;'
            f'border:3px solid {color};border-radius:12px">'
            f'<div style="font-size:2rem;font-weight:700;color:{color}">{risk}</div>'
            '<div style="font-size:.9rem;color:#6c757d">Overall Risk Level</div>'
            '</div>\n'
        )

    def _render_cvss_summary(self, report: AuditReport) -> str:
        scores = [v.cvss_score for v in report.vulnerabilities if v.cvss_score is not None]
        if not scores:
            return ""
        avg = sum(scores) / len(scores)
        mx = max(scores)
        return (
            '<div style="display:flex;gap:1rem;margin:1rem 0">'
            f'<div class="stat-card" style="background:#6c757d"><div class="count">{avg:.1f}</div><div class="label">Avg CVSS</div></div>'
            f'<div class="stat-card" style="background:#dc3545"><div class="count">{mx:.1f}</div><div class="label">Max CVSS</div></div>'
            f'<div class="stat-card" style="background:#0d6efd"><div class="count">{len(scores)}</div><div class="label">Scored Vulns</div></div>'
            '</div>\n'
        )

    def _render_filter_bar(self) -> str:
        return (
            '<div style="display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0">'
            '<button onclick="filterBySeverity(\'all\')" style="padding:.4rem .8rem;border:1px solid #dee2e6;border-radius:4px;cursor:pointer;background:#f8f9fa">All</button>'
            '<button onclick="filterBySeverity(\'critical\')" style="padding:.4rem .8rem;border:1px solid #dc3545;border-radius:4px;cursor:pointer;background:#fff;color:#dc3545">Critical</button>'
            '<button onclick="filterBySeverity(\'high\')" style="padding:.4rem .8rem;border:1px solid #e01020;border-radius:4px;cursor:pointer;background:#fff;color:#e01020">High</button>'
            '<button onclick="filterBySeverity(\'medium\')" style="padding:.4rem .8rem;border:1px solid #ffc107;border-radius:4px;cursor:pointer;background:#fff;color:#856404">Medium</button>'
            '<button onclick="filterBySeverity(\'low\')" style="padding:.4rem .8rem;border:1px solid #198754;border-radius:4px;cursor:pointer;background:#fff;color:#198754">Low</button>'
            '<button onclick="filterBySeverity(\'info\')" style="padding:.4rem .8rem;border:1px solid #0d6efd;border-radius:4px;cursor:pointer;background:#fff;color:#0d6efd">Info</button>'
            '</div>\n'
        )

    def generate_filtered_html(self, report: AuditReport, severity: str) -> str:
        filtered_vulns = [v for v in report.vulnerabilities if v.severity.value == severity]
        from .pdf_reporter import AuditReport as AR
        import copy
        filtered_report = copy.deepcopy(report)
        filtered_report.vulnerabilities = filtered_vulns
        return self._generate_html_content(filtered_report)
