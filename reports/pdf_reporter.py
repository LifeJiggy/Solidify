"""
PDF Report Generator Module

This module provides comprehensive PDF report generation capabilities
for the Solidify security auditing framework.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
import os
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
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
    
    def add_section(self, section: ReportSection):
        self.sections.append(section)
    
    def add_vulnerability(self, vuln: VulnerabilityEntry):
        self.vulnerabilities.append(vuln)
    
    def get_severity_counts(self) -> Dict[str, int]:
        counts = defaultdict(int)
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
    def __init__(self):
        self.page_size = (210, 297)
        self.margin = 20
        self.font_family = "Helvetica"
        self.title_font_size = 24
        self.heading_font_size = 18
        self.subheading_font_size = 14
        self.body_font_size = 10
        self.line_height = 1.5
        
        self.colors = {
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
    def __init__(self):
        self.style = PDFStyleConfig()
        self.sections: List[ReportSection] = []
        self.vulnerabilities: List[VulnerabilityEntry] = []
    
    def generate_report(self, audit_report: AuditReport) -> bytes:
        content = self._generate_content(audit_report)
        return content.encode('utf-8')
    
    def _generate_content(self, report: AuditReport) -> str:
        lines = []
        
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
            f"SECURITY AUDIT REPORT",
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
        lines = [
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
        lines = [
            "STATISTICS",
            "-" * 60,
            ""
        ]
        
        for key, value in report.statistics.items():
            lines.append(f"{key}: {value}")
        
        return lines
    
    def _generate_recommendations(self, report: AuditReport) -> List[str]:
        lines = [
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
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Report exported to: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


class ReportGenerator:
    def __init__(self):
        self.pdf_generator = PDFGenerator()
        self.temp_reports: Dict[str, AuditReport] = {}
    
    def create_report(self, contract_name: str, contract_address: str,
                   vulnerabilities: List[Dict[str, Any]],
                   statistics: Dict[str, Any]) -> AuditReport:
        
        report_id = f"RPT_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        
        report = AuditReport(
            report_id=report_id,
            contract_name=contract_name,
            contract_address=contract_address,
            audit_date=time.time()
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
                cvss_score=vuln_data.get('cvss_score')
            )
            report.add_vulnerability(vuln)
        
        report.statistics = statistics
        
        self.temp_reports[report_id] = report
        
        return report
    
    def generate_pdf(self, report: AuditReport) -> bytes:
        return self.pdf_generator.generate_report(report)
    
    def export_pdf(self, report: AuditReport, filepath: str) -> bool:
        return self.pdf_generator.export_to_file(report, filepath)
    
    def get_report_by_id(self, report_id: str) -> Optional[AuditReport]:
        return self.temp_reports.get(report_id)


def create_security_report(contract_name: str, contract_address: str,
                          vulnerabilities: List[Dict[str, Any]],
                          statistics: Dict[str, Any]) -> Dict[str, Any]:
    
    generator = ReportGenerator()
    
    report = generator.create_report(contract_name, contract_address, vulnerabilities, statistics)
    
    return report.to_dict()


if __name__ == '__main__':
    sample_vulns = [
        {
            'title': 'Reentrancy Vulnerability',
            'severity': 'critical',
            'category': 'Reentrancy',
            'description': 'External call before state update',
            'impact': 'Can lead to fund drain',
            'recommendation': 'Use ReentrancyGuard',
            'code_snippet': 'msg.sender.call{value: amount}("")',
            'line_number': 42
        },
        {
            'title': 'Missing Access Control',
            'severity': 'high',
            'category': 'Access Control',
            'description': 'Function lacks access control',
            'impact': 'Unauthorized access possible',
            'recommendation': 'Add onlyOwner modifier',
            'code_snippet': 'function withdraw() public',
            'line_number': 15
        }
    ]
    
    stats = {
        'lines_scanned': 500,
        'functions_scanned': 20,
        'execution_time': 2.5
    }
    
    result = create_security_report('TestContract', '0x1234...', sample_vulns, stats)
    print(json.dumps(result, indent=2))