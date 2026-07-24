"""
Solidify Reports Module
=======================

Report generation, formatting, and export for the Solidify security
auditing framework.  Supports PDF, HTML, Markdown, and JSON output.

Author: Solidify Security Team
Version: 1.0.0
"""

from __future__ import annotations

from .pdf_reporter import (
    AuditReport,
    PDFGenerator,
    PDFStyleConfig,
    ReportFormat,
    ReportSection,
    ReportStyle,
    SeverityLevel,
    VulnerabilityEntry,
)
from .reporter import BaseReporter, ReporterError
from .report_generator import ReportGenerator, create_security_report
from .report_factory import ReportFactory, ReportFormatError
from .report_formatter import (
    FormatterConfig,
    ReportFormatter,
    SEVERITY_ORDER,
    SeverityColorMap,
)
from .report_template import (
    DetailedReportTemplate,
    ExecutiveReportTemplate,
    MinimalReportTemplate,
    ReportTemplate,
    StandardReportTemplate,
    TemplateRegistry,
)
from .html_reporter import HTMLReporter
from .markdown_reporter import MarkdownReporter

__all__ = [
    "AuditReport",
    "BaseReporter",
    "DetailedReportTemplate",
    "ExecutiveReportTemplate",
    "FormatterConfig",
    "HTMLReporter",
    "MarkdownReporter",
    "MinimalReportTemplate",
    "PDFGenerator",
    "PDFStyleConfig",
    "ReportFactory",
    "ReportFormat",
    "ReportFormatError",
    "ReportGenerator",
    "ReportSection",
    "ReportStyle",
    "ReportTemplate",
    "ReportFormatter",
    "ReporterError",
    "SEVERITY_ORDER",
    "SeverityColorMap",
    "SeverityLevel",
    "StandardReportTemplate",
    "TemplateRegistry",
    "VulnerabilityEntry",
    "create_security_report",
]

__version__ = "1.0.0"
