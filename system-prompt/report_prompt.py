"""
Solidify Report Prompt
Report generation prompts

Author: Peace Stephen (Tech Lead)
Description: Prompts for generating audit reports
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Report formats"""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    TEXT = "text"


class ReportStyle(Enum):
    """Report styles"""
    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    ACADEMIC = "academic"


class ReportSection(Enum):
    """Report sections"""
    EXECUTIVE_SUMMARY = "executive_summary"
    METHODOLOGY = "methodology"
    FINDINGS = "findings"
    RISK_ASSESSMENT = "risk_assessment"
    RECOMMENDATIONS = "recommendations"
    CODE_QUALITY = "code_quality"
    GAS_OPTIMIZATIONS = "gas_optimizations"
    APPENDIX = "appendix"


REPORT_TEMPLATES = {
    ReportStyle.EXECUTIVE: {
        "title": "Security Assessment Report",
        "sections": [
            "executive_summary",
            "findings",
            "recommendations"
        ]
    },
    ReportStyle.TECHNICAL: {
        "title": "Technical Security Audit Report",
        "sections": [
            "executive_summary",
            "methodology",
            "findings",
            "risk_assessment",
            "recommendations",
            "code_quality",
            "gas_optimizations"
        ]
    }
}


@dataclass
class ReportData:
    contract_name: str
    contract_address: Optional[str] = None
    chain: str = "ethereum"
    audit_date: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    location: str
    cwe: Optional[str] = None
    cvss_score: float = 0.0
    impact: str = ""
    recommendation: str = ""
    code_snippet: Optional[str] = None


class ReportBuilder:
    """Build report prompts"""
    
    def __init__(self):
        self.templates = REPORT_TEMPLATES
    
    def build_executive_summary(
        self,
        data: ReportData
    ) -> str:
        return f"""## Executive Summary

Contract: {data.contract_name}
Chain: {data.chain}
Date: {data.audit_date}

### Overview
{data.summary}

### Risk Score
**Overall Risk: {data.risk_score}/10**

### Summary
- Critical: {len([v for v in data.vulnerabilities if v.get('severity') == 'critical'])}
- High: {len([v for v in data.vulnerabilities if v.get('severity') == 'high'])}
- Medium: {len([v for v in data.vulnerabilities if v.get('severity') == 'medium'])}
- Low: {len([v for v in data.vulnerabilities if v.get('severity') == 'low'])}"""
    
    def build_findings_section(
        self,
        findings: List[Finding]
    ) -> str:
        lines = ["## Findings\n"]
        
        severities = {"critical": [], "high": [], "medium": [], "low": []}
        for f in findings:
            severities.get(f.severity, []).append(f)
        
        for severity, items in severities.items():
            if items:
                lines.append(f"\n### {severity.upper()}\n")
                for i, finding in enumerate(items, 1):
                    lines.append(f"**{i}. {finding.title}**")
                    lines.append(f"- Severity: {finding.severity}")
                    lines.append(f"- Location: {finding.location}")
                    lines.append(f"- Description: {finding.description}")
                    if finding.cwe:
                        lines.append(f"- CWE: {finding.cwe}")
                    if finding.cvss_score:
                        lines.append(f"- CVSS: {finding.cvss_score}")
                    lines.append(f"- Impact: {finding.impact}")
                    lines.append(f"- Recommendation: {finding.recommendation}")
                    lines.append("")
        
        return "\n".join(lines)
    
    def build_recommendations(
        self,
        recommendations: List[str]
    ) -> str:
        lines = ["## Recommendations\n"]
        
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        
        return "\n".join(lines)
    
    def build_full_report(
        self,
        data: ReportData,
        style: ReportStyle = ReportStyle.TECHNICAL
    ) -> str:
        template = self.templates.get(style, self.templates[ReportStyle.TECHNICAL])
        
        report = [f"# {template['title']}\n"]
        report.append(f"**Contract:** {data.contract_name}")
        report.append(f"**Chain:** {data.chain}")
        report.append(f"**Date:** {data.audit_date}\n")
        
        if "executive_summary" in template["sections"]:
            report.append("\n" + self.build_executive_summary(data))
        
        if "findings" in template["sections"]:
            findings = [Finding(
                title=v.get("title", ""),
                severity=v.get("severity", "medium"),
                description=v.get("description", ""),
                location=v.get("location", ""),
                cwe=v.get("cwe"),
                cvss_score=v.get("cvss_score", 0.0),
                impact=v.get("impact", ""),
                recommendation=v.get("recommendation", "")
            ) for v in data.vulnerabilities]
            report.append("\n" + self.build_findings_section(findings))
        
        if "recommendations" in template["sections"]:
            report.append("\n" + self.build_recommendations(data.recommendations))
        
        return "\n".join(report)
    
    def build_json_report(self, data: ReportData) -> str:
        return json.dumps({
            "contract_name": data.contract_name,
            "contract_address": data.contract_address,
            "chain": data.chain,
            "audit_date": data.audit_date,
            "vulnerabilities": data.vulnerabilities,
            "risk_score": data.risk_score,
            "summary": data.summary,
            "recommendations": data.recommendations
        }, indent=2)


class ReportPrompt:
    """Main report prompt manager"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = ReportBuilder()
        
        logger.info("✅ Report Prompt initialized")
    
    def create_report_data(
        self,
        contract_name: str,
        vulnerabilities: List[Dict[str, Any]],
        risk_score: float,
        summary: str
    ) -> ReportData:
        return ReportData(
            contract_name=contract_name,
            vulnerabilities=vulnerabilities,
            risk_score=risk_score,
            summary=summary
        )
    
    def build_prompt(
        self,
        data: ReportData,
        style: ReportStyle = ReportStyle.TECHNICAL
    ) -> str:
        return self.builder.build_full_report(data, style)
    
    def build_executive_prompt(self, data: ReportData) -> str:
        return self.builder.build_executive_summary(data)
    
    def build_markdown(
        self,
        data: ReportData
    ) -> str:
        return self.builder.build_full_report(data)
    
    def build_json(self, data: ReportData) -> str:
        return self.builder.build_json_report(data)