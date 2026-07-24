"""
Report Formatter Module

Shared formatting utilities consumed by every reporter backend.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import html
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .pdf_reporter import SeverityLevel, VulnerabilityEntry

logger = logging.getLogger(__name__)


SEVERITY_ORDER: Dict[str, int] = {
    SeverityLevel.CRITICAL.value: 0,
    SeverityLevel.HIGH.value: 1,
    SeverityLevel.MEDIUM.value: 2,
    SeverityLevel.LOW.value: 3,
    SeverityLevel.INFO.value: 4,
}

SEVERITY_LABELS: Dict[str, str] = {
    SeverityLevel.CRITICAL.value: "Critical",
    SeverityLevel.HIGH.value: "High",
    SeverityLevel.MEDIUM.value: "Medium",
    SeverityLevel.LOW.value: "Low",
    SeverityLevel.INFO.value: "Info",
}

SEVERITY_COLORS: Dict[str, str] = {
    SeverityLevel.CRITICAL.value: "#dc3545",
    SeverityLevel.HIGH.value: "#e01020",
    SeverityLevel.MEDIUM.value: "#ffc107",
    SeverityLevel.LOW.value: "#198754",
    SeverityLevel.INFO.value: "#0d6efd",
}

SEVERITY_EMOJIS: Dict[str, str] = {
    SeverityLevel.CRITICAL.value: "\U0001f534",
    SeverityLevel.HIGH.value: "\U0001f7e0",
    SeverityLevel.MEDIUM.value: "\U0001f7e1",
    SeverityLevel.LOW.value: "\U0001f535",
    SeverityLevel.INFO.value: "\u26aa",
}


@dataclass
class SeverityColorMap:
    """Maps severity levels to CSS hex colours."""
    critical: str = "#dc3545"
    high: str = "#e01020"
    medium: str = "#ffc107"
    low: str = "#198754"
    info: str = "#0d6efd"

    def as_dict(self) -> Dict[str, str]:
        return {
            SeverityLevel.CRITICAL.value: self.critical,
            SeverityLevel.HIGH.value: self.high,
            SeverityLevel.MEDIUM.value: self.medium,
            SeverityLevel.LOW.value: self.low,
            SeverityLevel.INFO.value: self.info,
        }


@dataclass
class FormatterConfig:
    """Tweakable knobs for all formatting helpers."""
    code_block_language: str = "solidity"
    max_text_length: int = 500
    timestamp_format: str = "%Y-%m-%d %H:%M:%S"
    use_emoji_severity: bool = True
    color_map: SeverityColorMap = field(default_factory=SeverityColorMap)


class ReportFormatter:
    """Stateless helper class with pure formatting methods."""

    def __init__(self, config: Optional[FormatterConfig] = None) -> None:
        self.config = config or FormatterConfig()

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    def format_severity_badge(self, severity: SeverityLevel) -> str:
        """Return an emoji + label string for *severity*."""
        emoji = SEVERITY_EMOJIS.get(severity.value, "")
        label = SEVERITY_LABELS.get(severity.value, severity.value)
        if self.config.use_emoji_severity and emoji:
            return f"{emoji} {label}"
        return label

    def format_impact_level(self, severity: SeverityLevel) -> str:
        """Return a human-readable impact description."""
        mapping = {
            SeverityLevel.CRITICAL.value: "Critical impact — immediate action required",
            SeverityLevel.HIGH.value: "High impact — address promptly",
            SeverityLevel.MEDIUM.value: "Medium impact — should be resolved",
            SeverityLevel.LOW.value: "Low impact — recommended improvement",
            SeverityLevel.INFO.value: "Informational — no immediate risk",
        }
        return mapping.get(severity.value, "Unknown impact")

    # ------------------------------------------------------------------
    # Code / text helpers
    # ------------------------------------------------------------------

    def format_code_block(self, code: str, language: Optional[str] = None) -> str:
        lang = language or self.config.code_block_language
        safe = html.escape(code)
        return f"```{lang}\n{safe}\n```"

    def format_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """Build a GFM-style Markdown table."""
        if not headers:
            return ""
        col_widths = [len(h) for h in headers]
        for row in rows:
            for idx, cell in enumerate(row):
                if idx < len(col_widths):
                    col_widths[idx] = max(col_widths[idx], len(cell))

        def _fmt_row(cells: List[str]) -> str:
            parts = []
            for i, cell in enumerate(cells):
                w = col_widths[i] if i < len(col_widths) else len(cell)
                parts.append(cell.ljust(w))
            return "| " + " | ".join(parts) + " |"

        sep = "| " + " | ".join("-" * w for w in col_widths) + " |"
        lines = [_fmt_row(headers), sep]
        lines.extend(_fmt_row(r) for r in rows)
        return "\n".join(lines)

    def truncate_text(self, text: str, max_len: Optional[int] = None) -> str:
        limit = max_len or self.config.max_text_length
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    def sanitize_html(self, text: str) -> str:
        return html.escape(text)

    # ------------------------------------------------------------------
    # Vulnerability aggregation
    # ------------------------------------------------------------------

    def format_vulnerability_summary(self, vulns: List[VulnerabilityEntry]) -> str:
        counts: Dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c:
                badge = self.format_severity_badge(SeverityLevel(sev))
                parts.append(f"{badge}: {c}")
        return ", ".join(parts) if parts else "No findings"

    # ------------------------------------------------------------------
    # CVSS / CWE
    # ------------------------------------------------------------------

    def format_cvss_score(self, score: Optional[float]) -> str:
        if score is None:
            return "N/A"
        if score >= 9.0:
            return f"{score:.1f} (Critical)"
        if score >= 7.0:
            return f"{score:.1f} (High)"
        if score >= 4.0:
            return f"{score:.1f} (Medium)"
        if score >= 0.1:
            return f"{score:.1f} (Low)"
        return f"{score:.1f} (Info)"

    def format_cwe_id(self, cwe_id: Optional[str]) -> str:
        if not cwe_id:
            return "N/A"
        if cwe_id.startswith("CWE-"):
            return cwe_id
        return f"CWE-{cwe_id}"

    # ------------------------------------------------------------------
    # Timestamp / risk
    # ------------------------------------------------------------------

    def format_timestamp(self, ts: float) -> str:
        return time.strftime(self.config.timestamp_format, time.localtime(ts))

    def format_risk_matrix(self, severity_counts: Dict[str, int]) -> str:
        total = sum(severity_counts.values())
        if total == 0:
            return "No findings"

        lines = ["Risk Assessment:", ""]
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count == 0:
                continue
            pct = (count / total) * 100
            bar_len = max(1, int(pct / 5))
            badge = self.format_severity_badge(SeverityLevel(sev))
            lines.append(f"{badge}: {'█' * bar_len} {count} ({pct:.1f}%)")
        return "\n".join(lines)

    def format_severity_counts_table(self, severity_counts: Dict[str, int]) -> str:
        total = sum(severity_counts.values())
        headers = ["Severity", "Count", "Percentage"]
        rows: List[List[str]] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count == 0 and sev == "info":
                continue
            pct = f"{(count / total) * 100:.1f}%" if total > 0 else "0.0%"
            badge = self.format_severity_badge(SeverityLevel(sev))
            rows.append([badge, str(count), pct])
        rows.append(["Total", str(total), "100.0%"])
        return self.format_table(headers, rows)

    def format_vuln_card_text(self, vuln: VulnerabilityEntry) -> str:
        badge = self.format_severity_badge(vuln.severity)
        cvss = self.format_cvss_score(vuln.cvss_score)
        cwe = self.format_cwe_id(vuln.cwe_id)
        lines = [
            f"[{vuln.vuln_id}] {vuln.title}",
            f"  Severity: {badge}  |  Category: {vuln.category}",
            f"  Line: {vuln.line_number}  |  CVSS: {cvss}  |  CWE: {cwe}",
            "",
            f"  Description: {self.truncate_text(vuln.description, 200)}",
            f"  Impact: {self.truncate_text(vuln.impact, 200)}",
            f"  Recommendation: {self.truncate_text(vuln.recommendation, 200)}",
        ]
        if vuln.code_snippet:
            lines.append(f"  Code: {self.truncate_text(vuln.code_snippet, 100)}")
        return "\n".join(lines)

    def format_inline_badge(self, severity: SeverityLevel, text: Optional[str] = None) -> str:
        label = text or SEVERITY_LABELS.get(severity.value, severity.value)
        emoji = SEVERITY_EMOJIS.get(severity.value, "")
        if self.config.use_emoji_severity and emoji:
            return f"`{emoji} {label}`"
        return f"`{label}`"

    def format_code_inline(self, code: str) -> str:
        return f"`{code}`"

    def format_link(self, text: str, url: str) -> str:
        return f"[{text}]({url})"

    def format_checkbox(self, checked: bool = False) -> str:
        return "[x]" if checked else "[ ]"

    def format_list(self, items: List[str], ordered: bool = False) -> str:
        lines: List[str] = []
        for idx, item in enumerate(items, 1):
            if ordered:
                lines.append(f"{idx}. {item}")
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)

    def format_blockquote(self, text: str) -> str:
        quoted = "\n".join(f"> {line}" for line in text.split("\n"))
        return quoted

    def format_horizontal_rule(self) -> str:
        return "---"

    def format_divider(self, char: str = "=", length: int = 60) -> str:
        return char * length

    def escape_markdown(self, text: str) -> str:
        chars_to_escape = ["\\", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|", "~", "`", ">"]
        result = text
        for ch in chars_to_escape:
            result = result.replace(ch, f"\\{ch}")
        return result

    def format_percentage(self, value: float, total: float) -> str:
        if total == 0:
            return "0.0%"
        return f"{(value / total) * 100:.1f}%"

    def format_number(self, value: float, decimals: int = 1) -> str:
        if value >= 1_000_000:
            return f"{value / 1_000_000:.{decimals}f}M"
        if value >= 1_000:
            return f"{value / 1_000:.{decimals}f}K"
        return f"{value:.{decimals}f}"

    def format_duration(self, seconds: float) -> str:
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"

    def format_severity_bar(self, severity: SeverityLevel, width: int = 20) -> str:
        order = SEVERITY_ORDER.get(severity.value, 4)
        filled = max(1, int((5 - order) / 5 * width))
        empty = width - filled
        return f"[{'█' * filled}{'░' * empty}]"

    def get_risk_label(self, severity_counts: Dict[str, int]) -> str:
        if severity_counts.get('critical', 0) > 0:
            return "CRITICAL"
        if severity_counts.get('high', 0) > 0:
            return "HIGH"
        if severity_counts.get('medium', 0) > 0:
            return "MEDIUM"
        return "LOW"

    def format_findings_overview(self, vulns: List[VulnerabilityEntry]) -> str:
        counts: Dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        total = len(vulns)
        lines = [
            f"Findings Overview ({total} total)",
            "",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            badge = self.format_severity_badge(SeverityLevel(sev))
            bar = self.format_severity_bar(SeverityLevel(sev))
            lines.append(f"  {badge:20s} {bar} {c}")
        return "\n".join(lines)

    def format_severity_label(self, severity: SeverityLevel) -> str:
        return SEVERITY_LABELS.get(severity.value, severity.value)

    def format_severity_color(self, severity: SeverityLevel) -> str:
        return self.config.color_map.as_dict().get(severity.value, "#6c757d")

    def format_status_badge(self, status: str) -> str:
        status_colors = {
            'open': '#dc3545',
            'fixed': '#198754',
            'in_progress': '#ffc107',
            'accepted': '#0d6efd',
            'deferred': '#6c757d',
        }
        color = status_colors.get(status.lower(), '#6c757d')
        return f"[{status.upper()}]({color})"

    def format_section_header(self, title: str, level: int = 2) -> str:
        prefix = "#" * level
        return f"{prefix} {title}"

    def format_kv_pairs(self, data: Dict[str, Any], indent: int = 2) -> str:
        space = " " * indent
        lines = [f"{space}{k}: {v}" for k, v in data.items()]
        return "\n".join(lines)

    def wrap_in_box(self, text: str, width: int = 60) -> str:
        lines = text.split("\n")
        max_len = max(len(line) for line in lines) if lines else 0
        box_width = min(width, max_len + 4)
        border_top = "╔" + "═" * (box_width - 2) + "╗"
        border_bottom = "╚" + "═" * (box_width - 2) + "╝"
        result = [border_top]
        for line in lines:
            padded = line.ljust(box_width - 4)
            result.append(f"║ {padded} ║")
        result.append(border_bottom)
        return "\n".join(result)

    def format_compact_summary(self, vulns: List[VulnerabilityEntry]) -> str:
        counts: Dict[str, int] = {}
        for v in vulns:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c:
                parts.append(f"{sev[0].upper()}:{c}")
        return f"[{','.join(parts)}]" if parts else "[]"
