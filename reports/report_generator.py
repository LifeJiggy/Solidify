"""
Report Generator Orchestrator

High-level facade that coordinates report creation, formatting, and
export across all supported output backends.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional

from .pdf_reporter import (
    AuditReport,
    PDFGenerator,
    ReportFormat,
    ReportSection,
    SeverityLevel,
    VulnerabilityEntry,
)
from .report_factory import ReportFactory, ReportFormatError
from .reporter import BaseReporter, ReporterError

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Orchestrator that creates, stores, and exports audit reports.

    Reports are kept in an in-memory store keyed by ``report_id``.
    Use :meth:`export_report` to persist them to disk in any
    supported format.
    """

    def __init__(self) -> None:
        self._factory = ReportFactory()
        self._reports: Dict[str, AuditReport] = {}

    # ------------------------------------------------------------------
    # Report creation
    # ------------------------------------------------------------------

    def create_report(
        self,
        contract_name: str,
        contract_address: str,
        vulnerabilities: List[Dict[str, Any]],
        statistics: Dict[str, Any],
    ) -> AuditReport:
        """Build a new :class:`AuditReport` from raw vulnerability data.

        The report is stored internally and can be retrieved later via
        :meth:`get_report_by_id`.
        """
        report_id = self._generate_report_id()

        report = AuditReport(
            report_id=report_id,
            contract_name=contract_name,
            contract_address=contract_address,
            audit_date=time.time(),
        )

        for vuln_data in vulnerabilities:
            vuln = VulnerabilityEntry(
                vuln_id=vuln_data.get('vuln_id', f'VULN_{len(report.vulnerabilities)}'),
                title=vuln_data.get('title', 'Unknown'),
                severity=SeverityLevel(vuln_data.get('severity', 'info')),
                category=vuln_data.get('category', 'unknown'),
                description=vuln_data.get('description', ''),
                impact=vuln_data.get('impact', ''),
                recommendation=vuln_data.get('recommendation', ''),
                code_snippet=vuln_data.get('code_snippet', ''),
                line_number=vuln_data.get('line_number', 0),
                cwe_id=vuln_data.get('cwe_id'),
                cvss_score=vuln_data.get('cvss_score'),
            )
            report.add_vulnerability(vuln)

        report.statistics = statistics
        self._reports[report_id] = report

        logger.info(
            "Created report %s for contract %s",
            report_id,
            contract_name,
        )
        return report

    # ------------------------------------------------------------------
    # Format-specific generation
    # ------------------------------------------------------------------

    def generate_pdf(self, report: AuditReport) -> bytes:
        """Return the report rendered as raw PDF-style bytes."""
        gen = PDFGenerator()
        return gen.generate_report(report)

    def generate_html(self, report: AuditReport) -> str:
        """Return the report rendered as an HTML string."""
        from .html_reporter import HTMLReporter
        reporter = HTMLReporter()
        return reporter.generate(report).decode('utf-8')

    def generate_markdown(self, report: AuditReport) -> str:
        """Return the report rendered as a Markdown string."""
        from .markdown_reporter import MarkdownReporter
        reporter = MarkdownReporter()
        return reporter.generate(report).decode('utf-8')

    def generate_json(self, report: AuditReport) -> dict:
        """Return the report as a JSON-serialisable dict."""
        return report.to_dict()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_report(
        self,
        report: AuditReport,
        filepath: str,
        format: ReportFormat = ReportFormat.PDF,
    ) -> bool:
        """Write *report* to *filepath* in the given *format*.

        Returns True on success, False on failure.
        """
        try:
            reporter = self._factory.create_reporter(format)
            ok = reporter.generate_to_file(report, filepath)
            if ok:
                logger.info("Exported %s to %s (%s)", report.report_id, filepath, format.value)
            return ok
        except (ReportFormatError, Exception) as exc:
            logger.error("Export failed for %s: %s", report.report_id, exc)
            return False

    # ------------------------------------------------------------------
    # Report store
    # ------------------------------------------------------------------

    def get_report_by_id(self, report_id: str) -> Optional[AuditReport]:
        """Retrieve a previously created report by its ID."""
        return self._reports.get(report_id)

    def list_reports(self) -> List[str]:
        """Return all stored report IDs."""
        return list(self._reports.keys())

    def delete_report(self, report_id: str) -> bool:
        """Remove a report from the store.  Return True if it existed."""
        if report_id in self._reports:
            del self._reports[report_id]
            logger.info("Deleted report %s", report_id)
            return True
        logger.warning("Report %s not found for deletion", report_id)
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_report_id() -> str:
        """Produce a unique report identifier."""
        raw = f"{time.time_ns()}-{id(object)}"
        return f"RPT_{hashlib.sha256(raw.encode()).hexdigest()[:12]}"

    def duplicate_report(self, report_id: str, new_name: Optional[str] = None) -> Optional[AuditReport]:
        source = self._reports.get(report_id)
        if source is None:
            return None
        new_id = self._generate_report_id()
        import copy
        new_report = copy.deepcopy(source)
        new_report.report_id = new_id
        if new_name:
            new_report.contract_name = new_name
        self._reports[new_id] = new_report
        logger.info("Duplicated %s as %s", report_id, new_id)
        return new_report

    def get_reports_by_contract(self, contract_name: str) -> List[AuditReport]:
        return [
            r for r in self._reports.values()
            if r.contract_name == contract_name
        ]

    def get_reports_with_critical(self) -> List[AuditReport]:
        return [
            r for r in self._reports.values()
            if any(v.severity == SeverityLevel.CRITICAL for v in r.vulnerabilities)
        ]

    def get_report_count(self) -> int:
        return len(self._reports)

    def clear_reports(self) -> int:
        count = len(self._reports)
        self._reports.clear()
        logger.info("Cleared %d reports", count)
        return count

    def export_all_reports(self, output_dir: str, format: ReportFormat = ReportFormat.PDF) -> Dict[str, bool]:
        results: Dict[str, bool] = {}
        for rid, report in self._reports.items():
            safe_name = report.contract_name.replace(' ', '_').lower()
            filepath = f"{output_dir}/{safe_name}_{rid}.{format.value}"
            results[rid] = self.export_report(report, filepath, format)
        return results

    def generate_all_formats(self, report: AuditReport) -> Dict[str, bytes]:
        results: Dict[str, bytes] = {}
        results['pdf'] = self.generate_pdf(report)
        results['html'] = self.generate_html(report).encode('utf-8')
        results['markdown'] = self.generate_markdown(report).encode('utf-8')
        results['json'] = json.dumps(self.generate_json(report), indent=2).encode('utf-8')
        return results

    def get_report_stats(self) -> Dict[str, Any]:
        total = len(self._reports)
        total_vulns = sum(len(r.vulnerabilities) for r in self._reports.values())
        all_counts: Dict[str, int] = {}
        for r in self._reports.values():
            for sev, count in r.get_severity_counts().items():
                all_counts[sev] = all_counts.get(sev, 0) + count
        return {
            'total_reports': total,
            'total_vulnerabilities': total_vulns,
            'severity_totals': all_counts,
        }


def create_security_report(
    contract_name: str,
    contract_address: str,
    vulnerabilities: List[Dict[str, Any]],
    statistics: Dict[str, Any],
) -> Dict[str, Any]:
    """Convenience function that builds and returns a report dict."""
    generator = ReportGenerator()
    report = generator.create_report(
        contract_name, contract_address, vulnerabilities, statistics
    )
    return report.to_dict()


def create_report_with_sections(
    contract_name: str,
    contract_address: str,
    sections: List[Dict[str, Any]],
    vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    statistics: Optional[Dict[str, Any]] = None,
) -> AuditReport:
    """Build a report with pre-defined sections."""
    generator = ReportGenerator()
    report = generator.create_report(
        contract_name,
        contract_address,
        vulnerabilities or [],
        statistics or {},
    )
    for sec_data in sections:
        section = ReportSection(
            section_id=sec_data.get('section_id', f'SEC_{len(report.sections)}'),
            title=sec_data.get('title', ''),
            content=sec_data.get('content', ''),
            order=sec_data.get('order', len(report.sections)),
            metadata=sec_data.get('metadata', {}),
        )
        report.add_section(section)
    return report


def bulk_export(
    reports: List[AuditReport],
    output_dir: str,
    formats: Optional[List[ReportFormat]] = None,
) -> Dict[str, bool]:
    """Export multiple reports in the given formats.

    Returns a dict mapping ``"report_id:format"`` to success booleans.
    """
    if formats is None:
        formats = [ReportFormat.PDF]

    results: Dict[str, bool] = {}
    generator = ReportGenerator()

    for report in reports:
        for fmt in formats:
            ext = fmt.value
            safe_name = report.contract_name.replace(' ', '_').lower()
            filepath = f"{output_dir}/{safe_name}_{report.report_id}.{ext}"
            key = f"{report.report_id}:{fmt.value}"
            results[key] = generator.export_report(report, filepath, fmt)

    return results


def merge_reports(
    reports: List[AuditReport],
    contract_name: str,
    contract_address: str,
) -> AuditReport:
    """Merge multiple reports into a single consolidated report."""
    generator = ReportGenerator()
    all_vulns: List[Dict[str, Any]] = []
    merged_stats: Dict[str, Any] = {}
    merged_metadata: Dict[str, Any] = {}

    for report in reports:
        for vuln in report.vulnerabilities:
            all_vulns.append({
                'vuln_id': vuln.vuln_id,
                'title': vuln.title,
                'severity': vuln.severity.value,
                'category': vuln.category,
                'description': vuln.description,
                'impact': vuln.impact,
                'recommendation': vuln.recommendation,
                'code_snippet': vuln.code_snippet,
                'line_number': vuln.line_number,
                'cwe_id': vuln.cwe_id,
                'cvss_score': vuln.cvss_score,
            })
        for k, v in report.statistics.items():
            merged_stats[k] = v
        for k, v in report.metadata.items():
            merged_metadata[k] = v

    merged = generator.create_report(
        contract_name, contract_address, all_vulns, merged_stats
    )
    merged.metadata = merged_metadata
    merged.metadata['merged_from'] = [r.report_id for r in reports]
    return merged


def get_risk_level(report: AuditReport) -> str:
    """Determine the overall risk level for a report."""
    counts = report.get_severity_counts()
    if counts.get('critical', 0) > 0:
        return "CRITICAL"
    if counts.get('high', 0) > 0:
        return "HIGH"
    if counts.get('medium', 0) > 0:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(report: AuditReport) -> float:
    """Calculate a numeric risk score from 0 (safe) to 100 (critical)."""
    weights = {
        'critical': 40,
        'high': 25,
        'medium': 15,
        'low': 5,
        'info': 1,
    }
    counts = report.get_severity_counts()
    score = 0.0
    for sev, weight in weights.items():
        score += counts.get(sev, 0) * weight
    return min(100.0, score)


def generate_summary_dict(report: AuditReport) -> Dict[str, Any]:
    """Return a concise summary dict for API responses."""
    counts = report.get_severity_counts()
    total = sum(counts.values())
    cvss_scores = [v.cvss_score for v in report.vulnerabilities if v.cvss_score is not None]

    return {
        'report_id': report.report_id,
        'contract_name': report.contract_name,
        'contract_address': report.contract_address,
        'audit_date': report.audit_date,
        'total_findings': total,
        'risk_level': get_risk_level(report),
        'risk_score': calculate_risk_score(report),
        'severity_counts': counts,
        'avg_cvss': round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None,
        'max_cvss': max(cvss_scores) if cvss_scores else None,
        'unique_categories': len(set(v.category for v in report.vulnerabilities)),
    }
