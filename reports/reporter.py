"""
Base Reporter Module

Provides the abstract base class and common utilities for all report
generation backends in the Solidify auditing framework.

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
    ReportFormat,
    ReportSection,
    SeverityLevel,
    VulnerabilityEntry,
)

logger = logging.getLogger(__name__)


class ReporterError(Exception):
    """Raised when a reporter encounters an unrecoverable error."""
    pass


class BaseReporter(ABC):
    """Abstract base class for all report generators.

    Every concrete reporter (PDF, HTML, Markdown, etc.) must implement
    the three abstract methods declared here.
    """

    def __init__(self) -> None:
        self._start_time: Optional[float] = None

    @abstractmethod
    def generate(self, report: AuditReport) -> bytes:
        """Return the report serialised as *bytes*."""

    @abstractmethod
    def generate_to_file(self, report: AuditReport, filepath: str) -> bool:
        """Write the report to *filepath*.  Return True on success."""

    @abstractmethod
    def get_format(self) -> ReportFormat:
        """Return the :class:`ReportFormat` this reporter handles."""

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    def validate_report(self, report: AuditReport) -> bool:
        """Return True when *report* contains the minimum required data."""
        if not report.contract_name:
            logger.warning("Report missing contract_name")
            return False
        if not report.contract_address:
            logger.warning("Report missing contract_address")
            return False
        if not isinstance(report.audit_date, (int, float)):
            logger.warning("Report audit_date is not numeric")
            return False
        return True

    def get_severity_summary(self, report: AuditReport) -> Dict[str, int]:
        """Return a dict mapping severity value names to counts."""
        return report.get_severity_counts()

    def filter_by_severity(
        self, report: AuditReport, severity: SeverityLevel
    ) -> List[VulnerabilityEntry]:
        """Return only vulnerabilities matching *severity*."""
        return [
            v for v in report.vulnerabilities if v.severity == severity
        ]

    def sort_vulnerabilities(
        self,
        vulns: Optional[List[VulnerabilityEntry]] = None,
        report: Optional[AuditReport] = None,
        by: str = 'severity',
    ) -> List[VulnerabilityEntry]:
        """Sort vulnerabilities descending by severity or ascending by line."""
        _order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }

        source = vulns if vulns is not None else (report.vulnerabilities if report else [])

        if by == 'severity':
            return sorted(source, key=lambda v: _order.get(v.severity, 99))
        if by == 'line':
            return sorted(source, key=lambda v: v.line_number)
        if by == 'title':
            return sorted(source, key=lambda v: v.title.lower())
        return list(source)

    def _elapsed(self) -> float:
        """Seconds elapsed since the reporter started working."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def start_timer(self) -> None:
        self._start_time = time.time()

    def get_elapsed_seconds(self) -> float:
        return self._elapsed()

    def get_report_summary(self, report: AuditReport) -> Dict[str, Any]:
        counts = report.get_severity_counts()
        total = sum(counts.values())
        risk = "LOW"
        if counts.get('critical', 0) > 0:
            risk = "CRITICAL"
        elif counts.get('high', 0) > 0:
            risk = "HIGH"
        elif counts.get('medium', 0) > 0:
            risk = "MEDIUM"

        return {
            'report_id': report.report_id,
            'contract_name': report.contract_name,
            'total_findings': total,
            'risk_level': risk,
            'severity_counts': counts,
            'section_count': len(report.sections),
            'has_statistics': bool(report.statistics),
            'has_metadata': bool(report.metadata),
        }

    def count_by_category(self, report: AuditReport) -> Dict[str, int]:
        categories: Dict[str, int] = {}
        for vuln in report.vulnerabilities:
            categories[vuln.category] = categories.get(vuln.category, 0) + 1
        return dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))

    def get_highest_severity(self, report: AuditReport) -> Optional[SeverityLevel]:
        order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        if not report.vulnerabilities:
            return None
        return min(report.vulnerabilities, key=lambda v: order.get(v.severity, 99)).severity

    def get_avg_cvss(self, report: AuditReport) -> Optional[float]:
        scores = [v.cvss_score for v in report.vulnerabilities if v.cvss_score is not None]
        if not scores:
            return None
        return round(sum(scores) / len(scores), 2)

    def has_critical(self, report: AuditReport) -> bool:
        return any(v.severity == SeverityLevel.CRITICAL for v in report.vulnerabilities)

    def has_high(self, report: AuditReport) -> bool:
        return any(v.severity == SeverityLevel.HIGH for v in report.vulnerabilities)

    def get_findings_by_cvss_range(
        self, report: AuditReport, min_score: float, max_score: float
    ) -> List[VulnerabilityEntry]:
        return [
            v for v in report.vulnerabilities
            if v.cvss_score is not None and min_score <= v.cvss_score <= max_score
        ]

    def get_unique_categories(self, report: AuditReport) -> List[str]:
        seen: set[str] = set()
        result: List[str] = []
        for vuln in report.vulnerabilities:
            if vuln.category not in seen:
                seen.add(vuln.category)
                result.append(vuln.category)
        return result

    def get_cwe_ids(self, report: AuditReport) -> List[str]:
        seen: set[str] = set()
        result: List[str] = []
        for vuln in report.vulnerabilities:
            if vuln.cwe_id and vuln.cwe_id not in seen:
                seen.add(vuln.cwe_id)
                result.append(vuln.cwe_id)
        return result

    def validate_vulnerability(self, vuln: VulnerabilityEntry) -> bool:
        if not vuln.title:
            logger.warning("Vulnerability missing title")
            return False
        if not vuln.category:
            logger.warning("Vulnerability %s missing category", vuln.vuln_id)
            return False
        if not isinstance(vuln.severity, SeverityLevel):
            logger.warning("Vulnerability %s has invalid severity", vuln.vuln_id)
            return False
        if not vuln.description:
            logger.warning("Vulnerability %s missing description", vuln.vuln_id)
            return False
        return True

    def get_export_path(self, report: AuditReport, extension: str) -> str:
        safe_name = report.contract_name.replace(' ', '_').lower()
        return f"{safe_name}_audit_{report.report_id}.{extension}"

    def get_all_cvss_scores(self, report: AuditReport) -> List[float]:
        return [v.cvss_score for v in report.vulnerabilities if v.cvss_score is not None]

    def get_max_cvss(self, report: AuditReport) -> Optional[float]:
        scores = self.get_all_cvss_scores(report)
        return max(scores) if scores else None

    def get_min_cvss(self, report: AuditReport) -> Optional[float]:
        scores = self.get_all_cvss_scores(report)
        return min(scores) if scores else None

    def get_findings_above_cvss(self, report: AuditReport, threshold: float) -> List[VulnerabilityEntry]:
        return [
            v for v in report.vulnerabilities
            if v.cvss_score is not None and v.cvss_score >= threshold
        ]

    def has_cwe(self, report: AuditReport, cwe_id: str) -> bool:
        return any(v.cwe_id == cwe_id for v in report.vulnerabilities)

    def count_by_severity(self, report: AuditReport) -> Dict[str, int]:
        return report.get_severity_counts()

    def get_severity_percentage(self, report: AuditReport, severity: SeverityLevel) -> float:
        total = len(report.vulnerabilities)
        if total == 0:
            return 0.0
        count = sum(1 for v in report.vulnerabilities if v.severity == severity)
        return (count / total) * 100

    def get_sorted_categories(
        self, report: AuditReport, by: str = "count"
    ) -> List[tuple[str, int]]:
        cats = self.count_by_category(report)
        items = list(cats.items())
        if by == "count":
            return sorted(items, key=lambda x: x[1], reverse=True)
        return sorted(items, key=lambda x: x[0].lower())
