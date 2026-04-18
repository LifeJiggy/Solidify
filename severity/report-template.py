"""
Severity Report Template Module

This module provides comprehensive report templates for security audit findings,
formatted for different output types and stakeholder audiences.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    TEXT = "text"


class ReportAudience(Enum):
    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    DEVELOPMENT = "development"
    COMPLIANCE = "compliance"


class ReportSection(Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    METHODOLOGY = "methodology"
    FINDINGS = "findings"
    RECOMMENDATIONS = "recommendations"
    APPENDIX = "appendix"
    RISK_MATRIX = "risk_matrix"
    STATISTICS = "statistics"


@dataclass
class ReportMetadata:
    title: str
    version: str
    author: str
    created_at: float
    updated_at: float
    audit_scope: List[str]
    target_contracts: List[str]
    audit_standard: str
    compiler_version: Optional[str] = None
    chain_id: Optional[str] = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        self.updated_at = time.time()


@dataclass
class ReportFinding:
    finding_id: str
    title: str
    severity: str
    status: str
    category: str
    contract_name: str
    function_name: Optional[str]
    line_number: int
    description: str
    impact: str
    recommendation: str
    code_snippet: str
    cvss_vector: str
    cwe_id: Optional[str] = None
    false_positive_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'category': self.category,
            'contract_name': self.contract_name,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'description': self.description,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'code_snippet': self.code_snippet,
            'cvss_vector': self.cvss_vector,
            'cwe_id': self.cwe_id,
            'false_positive_rate': self.false_positive_rate
        }


class ReportTemplateBase(ABC):
    @abstractmethod
    def generate(self, data: Dict[str, Any]) -> str:
        pass
    
    @abstractmethod
    def get_format(self) -> ReportFormat:
        pass


class MarkdownReportTemplate(ReportTemplateBase):
    def get_format(self) -> ReportFormat:
        return ReportFormat.MARKDOWN
    
    def generate(self, data: Dict[str, Any]) -> str:
        lines = []
        
        lines.extend(self._generate_header(data))
        lines.extend(self._generate_executive_summary(data))
        lines.extend(self._generate_methodology(data))
        lines.extend(self._generate_findings(data))
        lines.extend(self._generate_recommendations(data))
        lines.extend(self._generate_statistics(data))
        lines.extend(self._generate_appendix(data))
        
        return '\n'.join(lines)
    
    def _generate_header(self, data: Dict[str, Any]) -> List[str]:
        metadata = data.get('metadata', {})
        return [
            f"# {metadata.get('title', 'Security Audit Report')}",
            "",
            f"**Version:** {metadata.get('version', '1.0.0')}",
            f"**Author:** {metadata.get('author', 'Solidify Security Team')}",
            f"**Date:** {time.strftime('%Y-%m-%d', time.localtime(metadata.get('created_at', time.time())))}",
            "",
            "---",
            ""
        ]
    
    def _generate_executive_summary(self, data: Dict[str, Any]) -> List[str]:
        summary = data.get('summary', {})
        
        return [
            "## Executive Summary",
            "",
            f"Total Findings: **{summary.get('total_findings', 0)}**",
            "",
            "| Severity | Count |",
            "|---------|-------|",
            f"| Critical | {summary.get('critical_count', 0)} |",
            f"| High | {summary.get('high_count', 0)} |",
            f"| Medium | {summary.get('medium_count', 0)} |",
            f"| Low | {summary.get('low_count', 0)} |",
            "",
            "---",
            ""
        ]
    
    def _generate_methodology(self, data: Dict[str, Any]) -> List[str]:
        return [
            "## Methodology",
            "",
            "### Scope",
            "- Static Analysis",
            "- Dynamic Analysis", 
            "- Manual Code Review",
            "- Gas Analysis",
            "",
            "### Tools Used",
            "- Solidify Security Scanner",
            "- Slither",
            "- Mythril",
            "- Custom Static Analyzers",
            "",
            "---",
            ""
        ]
    
    def _generate_findings(self, data: Dict[str, Any]) -> List[str]:
        findings = data.get('findings', [])
        
        lines = [
            "## Findings",
            ""
        ]
        
        for finding in findings:
            lines.extend([
                f"### {finding.get('title', 'Untitled')}",
                "",
                f"**Severity:** {finding.get('severity', 'Unknown')}",
                f"**Status:** {finding.get('status', 'Open')}",
                f"**Category:** {finding.get('category', 'Other')}",
                "",
                "**Location:**",
                f"- Contract: `{finding.get('contract_name', 'Unknown')}`",
                f"- Function: `{finding.get('function_name', 'N/A')}`",
                f"- Line: {finding.get('line_number', 0)}",
                "",
                "**Description:**",
                finding.get('description', ''),
                "",
                "**Impact:**",
                finding.get('impact', ''),
                "",
                "**Recommendation:**",
                finding.get('recommendation', ''),
                "",
                "```solidity",
                finding.get('code_snippet', ''),
                "```",
                "",
                "---",
                ""
            ])
        
        return lines
    
    def _generate_recommendations(self, data: Dict[str, Any]) -> List[str]:
        return [
            "## Recommendations",
            "",
            "### Critical Priority",
            "1. Address all critical and high severity findings immediately",
            "2. Implement reentrancy guards on all externally callable functions",
            "3. Add proper access control to sensitive functions",
            "",
            "### High Priority",
            "1. Review and fix arithmetic operations for overflow/underflow",
            "2. Implement SafeMath or use Solidity 0.8+",
            "3. Add event emissions for critical state changes",
            "",
            "### Medium Priority",
            "1. Optimize gas usage in loops",
            "2. Add NatSpec documentation",
            "3. Implement proper error handling",
            "",
            "---",
            ""
        ]
    
    def _generate_statistics(self, data: Dict[str, Any]) -> List[str]:
        return [
            "## Statistics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Contracts Audited | {data.get('metadata', {}).get('target_contracts', []).__len__()} |",
            f"| Total Lines of Code | {data.get('summary', {}).get('total_lines', 0)} |",
            f"| Vulnerabilities Found | {data.get('summary', {}).get('total_findings', 0)} |",
            "",
            "---",
            ""
        ]
    
    def _generate_appendix(self, data: Dict[str, Any]) -> List[str]:
        return [
            "## Appendix",
            "",
            "### References",
            "- SWC Registry: https://swcregistry.io/",
            "- Solidity Documentation: https://docs.soliditylang.org/",
            "- OpenZeppelin: https://openzeppelin.com/",
            "",
            "### Glossary",
            "- **Reentrancy**: Attack where a malicious contract calls back into the calling contract",
            "- **Flash Loan**: Uncollateralized loan that must be repaid within one transaction",
            "- **Oracle**: External data source used by smart contracts",
            ""
        ]


class HTMLReportTemplate(ReportTemplateBase):
    def get_format(self) -> ReportFormat:
        return ReportFormat.HTML
    
    def generate(self, data: Dict[str, Any]) -> str:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ border: 1px solid #ddd; padding: 15px; flex: 1; }}
        .critical {{ background: #ff4444; }}
        .high {{ background: #ff8800; }}
        .medium {{ background: #ffaa00; }}
        .low {{ background: #44aa44; }}
        .finding {{ border-left: 4px solid #ccc; padding-left: 15px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{data.get('metadata', {}).get('title', 'Security Audit Report')}</h1>
    </div>
    
    <div class="summary">
        <div class="card critical">
            <h3>Critical</h3>
            <p>{data.get('summary', {}).get('critical_count', 0)}</p>
        </div>
        <div class="card high">
            <h3>High</h3>
            <p>{data.get('summary', {}).get('high_count', 0)}</p>
        </div>
        <div class="card medium">
            <h3>Medium</h3>
            <p>{data.get('summary', {}).get('medium_count', 0)}</p>
        </div>
        <div class="card low">
            <h3>Low</h3>
            <p>{data.get('summary', {}).get('low_count', 0)}</p>
        </div>
    </div>
</body>
</html>
"""


class JSONReportTemplate(ReportTemplateBase):
    def get_format(self) -> ReportFormat:
        return ReportFormat.JSON
    
    def generate(self, data: Dict[str, Any]) -> str:
        return json.dumps(data, indent=2)


class CSVReportTemplate(ReportTemplateBase):
    def get_format(self) -> ReportFormat:
        return ReportFormat.CSV
    
    def generate(self, data: Dict[str, Any]) -> str:
        lines = []
        lines.append("ID,Title,Severity,Status,Category,Contract,Function,Line,Description,Impact,Recommendation")
        
        for finding in data.get('findings', []):
            row = [
                finding.get('finding_id', ''),
                finding.get('title', ''),
                finding.get('severity', ''),
                finding.get('status', ''),
                finding.get('category', ''),
                finding.get('contract_name', ''),
                finding.get('function_name', ''),
                str(finding.get('line_number', 0)),
                finding.get('description', '').replace(',', ';'),
                finding.get('impact', '').replace(',', ';'),
                finding.get('recommendation', '').replace(',', ';')
            ]
            lines.append(','.join(f'"{v}"' for v in row))
        
        return '\n'.join(lines)


class ReportGenerator:
    def __init__(self):
        self.templates: Dict[ReportFormat, ReportTemplateBase] = {
            ReportFormat.MARKDOWN: MarkdownReportTemplate(),
            ReportFormat.HTML: HTMLReportTemplate(),
            ReportFormat.JSON: JSONReportTemplate(),
            ReportFormat.CSV: CSVReportTemplate(),
        }
    
    def register_template(self, format_type: ReportFormat, template: ReportTemplateBase):
        self.templates[format_type] = template
    
    def generate(
        self,
        data: Dict[str, Any],
        format_type: ReportFormat,
        output_path: Optional[str] = None
    ) -> str:
        template = self.templates.get(format_type)
        
        if not template:
            raise ValueError(f"No template found for format: {format_type}")
        
        report = template.generate(data)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report generated: {output_path}")
        
        return report
    
    def generate_multi_format(
        self,
        data: Dict[str, Any],
        output_dir: str
    ) -> Dict[str, str]:
        import os
        
        os.makedirs(output_dir, exist_ok=True)
        results = {}
        
        for format_type in ReportFormat:
            try:
                output_path = os.path.join(output_dir, f"report.{format_type.value}")
                self.generate(data, format_type, output_path)
                results[format_type.value] = output_path
            except Exception as e:
                logger.error(f"Failed to generate {format_type.value}: {e}")
        
        return results


class ReportDataBuilder:
    def __init__(self):
        self.data: Dict[str, Any] = {
            'metadata': {},
            'summary': {},
            'findings': [],
            'recommendations': []
        }
    
    def set_metadata(self, metadata: Dict[str, Any]) -> 'ReportDataBuilder':
        self.data['metadata'].update(metadata)
        return self
    
    def set_summary(self, summary: Dict[str, Any]) -> 'ReportDataBuilder':
        self.data['summary'].update(summary)
        return self
    
    def add_finding(self, finding: Dict[str, Any]) -> 'ReportDataBuilder':
        self.data['findings'].append(finding)
        return self
    
    def add_findings(self, findings: List[Dict[str, Any]]) -> 'ReportDataBuilder':
        self.data['findings'].extend(findings)
        return self
    
    def add_recommendation(self, recommendation: str) -> 'ReportDataBuilder':
        self.data['recommendations'].append(recommendation)
        return self
    
    def build(self) -> Dict[str, Any]:
        self._calculate_summary()
        return self.data
    
    def _calculate_summary(self):
        findings = self.data['findings']
        
        severity_counts = Counter()
        category_counts = Counter()
        
        for finding in findings:
            severity = finding.get('severity', 'Unknown')
            category = finding.get('category', 'Other')
            severity_counts[severity] += 1
            category_counts[category] += 1
        
        self.data['summary'].update({
            'total_findings': len(findings),
            'critical_count': severity_counts.get('Critical', 0),
            'high_count': severity_counts.get('High', 0),
            'medium_count': severity_counts.get('Medium', 0),
            'low_count': severity_counts.get('Low', 0),
            'by_category': dict(category_counts)
        })


def create_report(
    findings: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    format_type: ReportFormat = ReportFormat.MARKDOWN,
    output_path: Optional[str] = None
) -> str:
    builder = ReportDataBuilder()
    builder.set_metadata(metadata)
    builder.add_findings(findings)
    
    data = builder.build()
    
    generator = ReportGenerator()
    return generator.generate(data, format_type, output_path)


if __name__ == '__main__':
    sample_findings = [
        {
            'finding_id': 'VULN-001',
            'title': 'Reentrancy Vulnerability',
            'severity': 'Critical',
            'status': 'Open',
            'category': 'Reentrancy',
            'contract_name': 'Bank',
            'function_name': 'withdraw',
            'line_number': 42,
            'description': 'External call before state update',
            'impact': 'Funds can be drained',
            'recommendation': 'Use ReentrancyGuard',
            'code_snippet': '(bool success,) = msg.sender.call{value: amount}("");',
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        }
    ]
    
    metadata = {
        'title': 'Sample Audit Report',
        'version': '1.0.0',
        'author': 'Solidify Team',
        'target_contracts': ['Bank.sol', 'Token.sol']
    }
    
    report = create_report(sample_findings, metadata, ReportFormat.MARKDOWN)
    print(report[:500])