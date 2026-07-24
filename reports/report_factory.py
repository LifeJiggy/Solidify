"""
Report Factory Module

Factory pattern for creating the appropriate reporter backend based on
the requested :class:`ReportFormat`.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Type

from .pdf_reporter import (
    AuditReport,
    ReportFormat,
    SeverityLevel,
    VulnerabilityEntry,
)
from .reporter import BaseReporter

logger = logging.getLogger(__name__)


class ReportFormatError(Exception):
    """Raised when an unsupported report format is requested."""
    pass


class ReportFactory:
    """Central factory that dispatches to the correct reporter.

    Supported formats are auto-registered on construction.  Additional
    reporters can be added at runtime via :meth:`register_reporter`.
    """

    def __init__(self) -> None:
        self._registry: Dict[ReportFormat, Type[BaseReporter]] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        from .pdf_reporter import ReportFormat as RF

        self._registry[RF.PDF] = self._lazy_pdf_reporter()
        self._register_html()
        self._register_markdown()

    def _lazy_pdf_reporter(self) -> Type[BaseReporter]:
        from .html_reporter import HTMLReporter  # noqa: F811 – ensures package importable
        from .pdf_reporter import ReportFormat as RF

        class _PDFReporter(BaseReporter):
            def generate(self, report: AuditReport) -> bytes:
                from .pdf_reporter import PDFGenerator
                return PDFGenerator().generate_report(report)

            def generate_to_file(self, report: AuditReport, filepath: str) -> bool:
                from .pdf_reporter import PDFGenerator
                return PDFGenerator().export_to_file(report, filepath)

            def get_format(self) -> ReportFormat:
                return RF.PDF

        return _PDFReporter

    def _register_html(self) -> None:
        from .html_reporter import HTMLReporter
        self._registry[ReportFormat.HTML] = HTMLReporter

    def _register_markdown(self) -> None:
        from .markdown_reporter import MarkdownReporter
        self._registry[ReportFormat.MARKDOWN] = MarkdownReporter

    def create_reporter(self, format: ReportFormat) -> BaseReporter:
        """Return a new reporter instance for *format*."""
        if format not in self._registry:
            raise ReportFormatError(f"Unsupported report format: {format.value}")
        return self._registry[format]()

    def register_reporter(
        self, format: ReportFormat, reporter_class: Type[BaseReporter]
    ) -> None:
        """Register *reporter_class* as the handler for *format*."""
        self._registry[format] = reporter_class
        logger.info(f"Registered reporter for {format.value}: {reporter_class.__name__}")

    def get_supported_formats(self) -> List[ReportFormat]:
        """Return all currently supported formats."""
        return list(self._registry.keys())

    def create_report(
        self,
        format: ReportFormat,
        contract_name: str,
        contract_address: str,
        vulns: List[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> AuditReport:
        """Build an :class:`AuditReport` from raw data and return it.

        The report is *not* yet written to disk; call the reporter's
        ``generate`` / ``generate_to_file`` method to produce output.
        """
        report_id = f"RPT_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

        report = AuditReport(
            report_id=report_id,
            contract_name=contract_name,
            contract_address=contract_address,
            audit_date=time.time(),
        )

        for vuln_data in vulns:
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

        report.statistics = stats
        return report

    def unregister_reporter(self, format: ReportFormat) -> bool:
        if format in self._registry:
            del self._registry[format]
            logger.info("Unregistered reporter for %s", format.value)
            return True
        return False

    def has_reporter(self, format: ReportFormat) -> bool:
        return format in self._registry

    def get_reporter_class(self, format: ReportFormat) -> Optional[Type[BaseReporter]]:
        return self._registry.get(format)

    def create_and_export(
        self,
        format: ReportFormat,
        contract_name: str,
        contract_address: str,
        vulns: List[Dict[str, Any]],
        stats: Dict[str, Any],
        filepath: str,
    ) -> bool:
        try:
            report = self.create_report(format, contract_name, contract_address, vulns, stats)
            reporter = self.create_reporter(format)
            return reporter.generate_to_file(report, filepath)
        except Exception as exc:
            logger.error("Create-and-export failed: %s", exc)
            return False

    def generate_all_formats(
        self,
        contract_name: str,
        contract_address: str,
        vulns: List[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> Dict[str, bytes]:
        results: Dict[str, bytes] = {}
        for fmt in self.get_supported_formats():
            try:
                report = self.create_report(fmt, contract_name, contract_address, vulns, stats)
                reporter = self.create_reporter(fmt)
                results[fmt.value] = reporter.generate(report)
            except Exception as exc:
                logger.error("Generation failed for %s: %s", fmt.value, exc)
        return results

    def get_format_info(self) -> List[Dict[str, Any]]:
        info: List[Dict[str, Any]] = []
        for fmt, cls in self._registry.items():
            info.append({
                'format': fmt.value,
                'class_name': cls.__name__,
                'module': cls.__module__,
            })
        return info

    def validate_vulns(self, vulns: List[Dict[str, Any]]) -> List[str]:
        errors: List[str] = []
        for idx, vuln in enumerate(vulns):
            if 'title' not in vuln:
                errors.append(f"Vulnerability at index {idx} missing 'title'")
            if 'severity' not in vuln:
                errors.append(f"Vulnerability at index {idx} missing 'severity'")
            elif vuln['severity'] not in [s.value for s in SeverityLevel]:
                errors.append(f"Vulnerability at index {idx} has invalid severity: {vuln['severity']}")
            if 'category' not in vuln:
                errors.append(f"Vulnerability at index {idx} missing 'category'")
        return errors

    def build_report_from_findings(
        self,
        findings: List[Dict[str, Any]],
        contract_name: str = "Unknown",
        contract_address: str = "0x0",
    ) -> AuditReport:
        stats = {
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
            'high': sum(1 for f in findings if f.get('severity') == 'high'),
            'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
            'low': sum(1 for f in findings if f.get('severity') == 'low'),
            'info': sum(1 for f in findings if f.get('severity') == 'info'),
        }
        return self.create_report(
            ReportFormat.PDF, contract_name, contract_address, findings, stats
        )

    def export_to_directory(
        self,
        report: AuditReport,
        output_dir: str,
        formats: Optional[List[ReportFormat]] = None,
    ) -> Dict[str, bool]:
        import os
        if formats is None:
            formats = self.get_supported_formats()
        os.makedirs(output_dir, exist_ok=True)
        results: Dict[str, bool] = {}
        for fmt in formats:
            ext = fmt.value
            safe_name = report.contract_name.replace(' ', '_').lower()
            filepath = os.path.join(output_dir, f"{safe_name}_{report.report_id}.{ext}")
            try:
                reporter = self.create_reporter(fmt)
                results[fmt.value] = reporter.generate_to_file(report, filepath)
            except Exception as exc:
                logger.error("Export to directory failed for %s: %s", fmt.value, exc)
                results[fmt.value] = False
        return results

    def generate_bytes(self, report: AuditReport, format: ReportFormat) -> bytes:
        reporter = self.create_reporter(format)
        return reporter.generate(report)

    def generate_string(self, report: AuditReport, format: ReportFormat) -> str:
        raw = self.generate_bytes(report, format)
        return raw.decode('utf-8')

    def get_format_extensions(self) -> Dict[str, str]:
        return {
            ReportFormat.PDF.value: ".pdf",
            ReportFormat.HTML.value: ".html",
            ReportFormat.MARKDOWN.value: ".md",
            ReportFormat.JSON.value: ".json",
            ReportFormat.CSV.value: ".csv",
        }

    def get_reporter_info(self, format: ReportFormat) -> Dict[str, Any]:
        cls = self._registry.get(format)
        if cls is None:
            return {'format': format.value, 'registered': False}
        return {
            'format': format.value,
            'registered': True,
            'class_name': cls.__name__,
            'module': cls.__module__,
            'docstring': cls.__doc__ or '',
        }

    def export_json(self, report: AuditReport, filepath: str) -> bool:
        try:
            data = report.to_dict()
            with open(filepath, 'w', encoding='utf-8') as fh:
                import json
                json.dump(data, fh, indent=2, ensure_ascii=False)
            logger.info("JSON report written to %s", filepath)
            return True
        except Exception as exc:
            logger.error("JSON export failed: %s", exc)
            return False

    def export_markdown(self, report: AuditReport, filepath: str) -> bool:
        try:
            from .markdown_reporter import MarkdownReporter
            reporter = MarkdownReporter()
            return reporter.generate_to_file(report, filepath)
        except Exception as exc:
            logger.error("Markdown export failed: %s", exc)
            return False

    def export_html(self, report: AuditReport, filepath: str) -> bool:
        try:
            from .html_reporter import HTMLReporter
            reporter = HTMLReporter()
            return reporter.generate_to_file(report, filepath)
        except Exception as exc:
            logger.error("HTML export failed: %s", exc)
            return False

    def export_all_formats(
        self, report: AuditReport, output_dir: str
    ) -> Dict[str, bool]:
        import os
        os.makedirs(output_dir, exist_ok=True)
        results: Dict[str, bool] = {}
        for fmt in self.get_supported_formats():
            safe_name = report.contract_name.replace(' ', '_').lower()
            filepath = os.path.join(output_dir, f"{safe_name}_{report.report_id}.{fmt.value}")
            try:
                reporter = self.create_reporter(fmt)
                results[fmt.value] = reporter.generate_to_file(report, filepath)
            except Exception as exc:
                logger.error("Export failed for %s: %s", fmt.value, exc)
                results[fmt.value] = False
        return results

    def create_batch_reports(
        self,
        contracts: List[Dict[str, Any]],
    ) -> List[AuditReport]:
        reports: List[AuditReport] = []
        for contract_data in contracts:
            try:
                report = self.create_report(
                    ReportFormat.PDF,
                    contract_data.get('name', 'Unknown'),
                    contract_data.get('address', '0x0'),
                    contract_data.get('vulnerabilities', []),
                    contract_data.get('statistics', {}),
                )
                reports.append(report)
            except Exception as exc:
                logger.error("Batch report creation failed: %s", exc)
        return reports
