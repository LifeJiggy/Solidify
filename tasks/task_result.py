"""
Task Result Module for Solidify Security Scanner

This module provides comprehensive task result handling, aggregation, and reporting
for security scan operations. Manages scan results, vulnerability findings,
metrics aggregation, and result formatting for compliance and documentation.

Author: Solidify Security Team
Version: 1.0.0
"""

import json
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResultStatus(Enum):
    """Result status enumeration"""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    PENDING = "pending"
    RUNNING = "running"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResultCategory(Enum):
    """Result categories"""
    SECURITY_SCAN = "security_scan"
    CODE_ANALYSIS = "code_analysis"
    PATTERN_MATCH = "pattern_match"
    GAS_OPTIMIZATION = "gas_optimization"
    COMPLIANCE_CHECK = "compliance_check"
    DEPENDENCY_SCAN = "dependency_scan"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"


@dataclass
class VulnerabilityFinding:
    """Represents a detected vulnerability"""
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str
    cwe_id: str
    cwe_url: str = ""
    line_number: Optional[int] = None
    code_snippet: str = ""
    recommendation: str = ""
    impact: str = ""
    likelihood: str = ""
    false_positive: bool = False
    verified: bool = False
    duplicate: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category,
            'cwe_id': self.cwe_id,
            'cwe_url': self.cwe_url,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'recommendation': self.recommendation,
            'impact': self.impact,
            'likelihood': self.likelihood,
            'false_positive': self.false_positive,
            'verified': self.verified,
            'duplicate': self.duplicate,
            'metadata': self.metadata,
            'references': self.references,
            'timestamp': self.timestamp
        }
    
    def to_markdown(self) -> str:
        """Convert to markdown format"""
        md = f"## {self.title}\n\n"
        md += f"**Severity:** {self.severity.value.upper()}\n\n"
        md += f"**Rule ID:** {self.rule_id}\n\n"
        if self.line_number:
            md += f"**Line:** {self.line_number}\n\n"
        md += f"**CWE:** [{self.cwe_id}]({self.cwe_url})\n\n"
        md += f"### Description\n\n{self.description}\n\n"
        if self.code_snippet:
            md += f"### Code\n\n```solidity\n{self.code_snippet}\n```\n\n"
        if self.recommendation:
            md += f"### Recommendation\n\n{self.recommendation}\n\n"
        return md
    
    def to_html(self) -> str:
        """Convert to HTML format"""
        severity_class = self.severity.value.lower()
        html = f'<div class="finding {severity_class}">\n'
        html += f'<h3>{self.title}</h3>\n'
        html += f'<p class="severity">{self.severity.value.upper()}</p>\n'
        html += f'<p class="rule-id">Rule: {self.rule_id}</p>\n'
        if self.line_number:
            html += f'<p class="line">Line: {self.line_number}</p>\n'
        html += f'<p class="cwe"><a href="{self.cwe_url}">{self.cwe_id}</a></p>\n'
        html += f'<div class="description">{self.description}</div>\n'
        if self.recommendation:
            html += f'<div class="recommendation">{self.recommendation}</div>\n'
        html += '</div>\n'
        return html


@dataclass
class ScanMetrics:
    """Scan execution metrics"""
    start_time: float
    end_time: float = 0.0
    duration: float = 0.0
    files_scanned: int = 0
    lines_scanned: int = 0
    rules_applied: int = 0
    matches_found: int = 0
    false_positives: int = 0
    errors: int = 0
    warnings: int = 0
    memory_used: int = 0
    peak_memory: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'files_scanned': self.files_scanned,
            'lines_scanned': self.lines_scanned,
            'rules_applied': self.rules_applied,
            'matches_found': self.matches_found,
            'false_positives': self.false_positives,
            'errors': self.errors,
            'warnings': self.warnings,
            'memory_used': self.memory_used,
            'peak_memory': self.peak_memory
        }


@dataclass
class TaskResult:
    """Represents a complete task result"""
    task_id: str
    task_name: str
    task_type: str
    status: ResultStatus
    category: ResultCategory
    contract_name: str
    contract_address: Optional[str]
    start_time: float
    end_time: float = 0.0
    metrics: ScanMetrics = field(default_factory=lambda: ScanMetrics(start_time=0))
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    result_hash: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_name': self.task_name,
            'task_type': self.task_type,
            'status': self.status.value,
            'category': self.category.value,
            'contract_name': self.contract_name,
            'contract_address': self.contract_address,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'metrics': self.metrics.to_dict(),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'errors': self.errors,
            'warnings': self.warnings,
            'metadata': self.metadata,
            'result_hash': self.result_hash
        }
    
    def severity_counts(self) -> Dict[str, int]:
        """Get severity counts"""
        counts = defaultdict(int)
        for vuln in self.vulnerabilities:
            if not vuln.false_positive:
                counts[vuln.severity.value] += 1
        return dict(counts)
    
    def total_findings(self) -> int:
        """Get total non-false-positive findings"""
        return sum(1 for v in self.vulnerabilities if not v.false_positive)
    
    def critical_findings(self) -> List[VulnerabilityFinding]:
        """Get critical severity findings"""
        return [v for v in self.vulnerabilities 
                if v.severity == SeverityLevel.CRITICAL and not v.false_positive]
    
    def high_findings(self) -> List[VulnerabilityFinding]:
        """Get high severity findings"""
        return [v for v in self.vulnerabilities 
                if v.severity == SeverityLevel.HIGH and not v.false_positive]
    
    def calculate_hash(self) -> str:
        """Calculate result hash for integrity"""
        data = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()


class ResultAggregator:
    """Aggregates multiple task results"""
    
    def __init__(self):
        self.results: List[TaskResult] = []
        self.aggregated_vulnerabilities: List[VulnerabilityFinding] = []
        self.lock = threading.Lock()
    
    def add_result(self, result: TaskResult) -> None:
        """Add a result to aggregation"""
        with self.lock:
            self.results.append(result)
            self.aggregated_vulnerabilities.extend(result.vulnerabilities)
    
    def aggregate_by_severity(self) -> Dict[str, List[TaskResult]]:
        """Group results by severity"""
        aggregated = defaultdict(list)
        for result in self.results:
            severity = "no_findings"
            for vuln in result.vulnerabilities:
                if not vuln.false_positive:
                    if vuln.severity == SeverityLevel.CRITICAL:
                        severity = "critical"
                        break
                    elif vuln.severity == SeverityLevel.HIGH:
                        severity = "high"
                    elif vuln.severity == SeverityLevel.MEDIUM:
                        if severity not in ["critical", "high"]:
                            severity = "medium"
            aggregated[severity].append(result)
        return dict(aggregated)
    
    def aggregate_by_contract(self) -> Dict[str, List[TaskResult]]:
        """Group results by contract"""
        aggregated = defaultdict(list)
        for result in self.results:
            aggregated[result.contract_name].append(result)
        return dict(aggregated)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get aggregation summary"""
        total_scans = len(self.results)
        total_findings = len([v for v in self.aggregated_vulnerabilities 
                         if not v.false_positive])
        critical = len([v for v in self.aggregated_vulnerabilities 
                      if v.severity == SeverityLevel.CRITICAL and not v.false_positive])
        high = len([v for v in self.aggregated_vulnerabilities 
                  if v.severity == SeverityLevel.HIGH and not v.false_positive])
        medium = len([v for v in self.aggregated_vulnerabilities 
                    if v.severity == SeverityLevel.MEDIUM and not v.false_positive])
        low = len([v for v in self.aggregated_vulnerabilities 
                if v.severity == SeverityLevel.LOW and not v.false_positive])
        
        return {
            'total_scans': total_scans,
            'total_findings': total_findings,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'false_positives': len([v for v in self.aggregated_vulnerabilities 
                                if v.false_positive])
        }
    
    def export_to_json(self, filepath: str) -> bool:
        """Export aggregated results to JSON"""
        try:
            data = {
                'summary': self.get_summary(),
                'results': [r.to_dict() for r in self.results]
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def export_to_html(self, filepath: str) -> bool:
        """Export aggregated results to HTML"""
        try:
            summary = self.get_summary()
            html = '''<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #1a73e8; color: white; padding: 20px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #f5f5f5; padding: 20px; border-radius: 8px; flex: 1; }
        .critical { color: #d93025; }
        .high { color: #f29900; }
        .medium { color: #f9ab00; }
        .low { color: #1a73e8; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 4px; }
        .finding.critical { border-left: 4px solid #d93025; }
        .finding.high { border-left: 4px solid #f29900; }
        .finding.medium { border-left: 4px solid #f9ab00; }
        .finding.low { border-left: 4px solid #1a73e8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Results</h1>
        <p>Generated: ''' + datetime.now().isoformat() + '''</p>
    </div>
    <div class="summary">
        <div class="stat-box">
            <h3>Summary</h3>
            <p>Total Scans: ''' + str(summary['total_scans']) + '''</p>
            <p>Total Findings: ''' + str(summary['total_findings']) + '''</p>
        </div>
        <div class="stat-box">
            <h3>By Severity</h3>
            <p class="critical">Critical: ''' + str(summary['critical']) + '''</p>
            <p class="high">High: ''' + str(summary['high']) + '''</p>
            <p class="medium">Medium: ''' + str(summary['medium']) + '''</p>
            <p class="low">Low: ''' + str(summary['low']) + '''</p>
        </div>
    </div>
    <h2>Findings</h2>
'''
            for result in self.results:
                for vuln in result.vulnerabilities:
                    if not vuln.false_positive:
                        html += vuln.to_html()
            
            html += '''
</body>
</html>
'''
            with open(filepath, 'w') as f:
                f.write(html)
            return True
        except Exception as e:
            logger.error(f"HTML export failed: {e}")
            return False


class ResultFormatter:
    """Formats task results in various output formats"""
    
    @staticmethod
    def format_json(result: TaskResult, indent: int = 2) -> str:
        """Format as JSON string"""
        return json.dumps(result.to_dict(), indent=indent)
    
    @staticmethod
    def format_markdown(result: TaskResult) -> str:
        """Format as Markdown"""
        md = f"# Scan Result: {result.task_name}\n\n"
        md += f"**Contract:** {result.contract_name}\n\n"
        md += f"**Status:** {result.status.value}\n\n"
        md += f"**Duration:** {result.metrics.duration:.2f}s\n\n"
        
        severity_counts = result.severity_counts()
        md += "## Findings Summary\n\n"
        md += f"- Critical: {severity_counts.get('critical', 0)}\n"
        md += f"- High: {severity_counts.get('high', 0)}\n"
        md += f"- Medium: {severity_counts.get('medium', 0)}\n"
        md += f"- Low: {severity_counts.get('low', 0)}\n\n"
        
        if result.critical_findings():
            md += "## Critical Findings\n\n"
            for finding in result.critical_findings():
                md += finding.to_markdown() + "\n"
        
        if result.high_findings():
            md += "## High Severity Findings\n\n"
            for finding in result.high_findings():
                md += finding.to_markdown() + "\n"
        
        return md
    
    @staticmethod
    def format_html(result: TaskResult) -> str:
        """Format as HTML"""
        severity_counts = result.severity_counts()
        html = '''<!DOCTYPE html>
<html>
<head>
    <title>''' + result.task_name + '''</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #1a73e8; color: white; padding: 20px; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-box { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .critical { color: #d93025; }
        .high { color: #f29900; }
        .medium { color: #f9ab00; }
        .low { color: #1a73e8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>''' + result.task_name + '''</h1>
        <p>Contract: ''' + result.contract_name + '''</p>
    </div>
    <div class="stats">
        <div class="stat-box">
            <h3>Status: ''' + result.status.value + '''</h3>
            <p>Duration: ''' + f"{result.metrics.duration:.2f}s" + '''</p>
        </div>
        <div class="stat-box">
            <h3>Findings</h3>
            <p class="critical">Critical: ''' + str(severity_counts.get('critical', 0)) + '''</p>
            <p class="high">High: ''' + str(severity_counts.get('high', 0)) + '''</p>
            <p class="medium">Medium: ''' + str(severity_counts.get('medium', 0)) + '''</p>
            <p class="low">Low: ''' + str(severity_counts.get('low', 0)) + '''</p>
        </div>
    </div>
</body>
</html>
'''
        return html
    
    @staticmethod
    def format_text(result: TaskResult) -> str:
        """Format as plain text"""
        severity_counts = result.severity_counts()
        text = f"Scan Result: {result.task_name}\n"
        text += f"Contract: {result.contract_name}\n"
        text += f"Status: {result.status.value}\n"
        text += f"Duration: {result.metrics.duration:.2f}s\n\n"
        text += "Findings:\n"
        text += f"  Critical: {severity_counts.get('critical', 0)}\n"
        text += f"  High: {severity_counts.get('high', 0)}\n"
        text += f"  Medium: {severity_counts.get('medium', 0)}\n"
        text += f"  Low: {severity_counts.get('low', 0)}\n\n"
        
        for vuln in result.vulnerabilities[:10]:
            if not vuln.false_positive:
                text += f"[{vuln.severity.value.upper()}] {vuln.title}\n"
                text += f"  Rule: {vuln.rule_id}\n"
                text += f"  Description: {vuln.description[:100]}...\n\n"
        
        return text
    
    @staticmethod
    def format_sarif(result: TaskResult) -> Dict[str, Any]:
        """Format as SARIF (Static Analysis Results Interchange Format)"""
        runs = []
        
        results_list = []
        for vuln in result.vulnerabilities:
            if not vuln.false_positive:
                results_list.append({
                    'ruleId': vuln.rule_id,
                    'level': vuln.severity.value,
                    'message': {
                        'text': vuln.description
                    },
                    'locations': [{
                        'physicalLocation': {
                            'artifactLocation': {
                                'uri': result.contract_name + '.sol'
                            },
                            'region': {
                                'startLine': vuln.line_number
                            } if vuln.line_number else {}
                        }
                    }]
                })
        
        runs.append({
            'tool': {
                'driver': {
                    'name': 'Solidify Security Scanner',
                    'version': '1.0.0'
                }
            },
            'results': results_list
        })
        
        return {
            'version': '2.1.0',
            'runs': runs
        }


class ResultComparator:
    """Compares task results for changes"""
    
    @staticmethod
    def compare_results(baseline: TaskResult, current: TaskResult) -> Dict[str, Any]:
        """Compare two results"""
        baseline_ids = {v.finding_id for v in baseline.vulnerabilities 
                     if not v.false_positive}
        current_ids = {v.finding_id for v in current.vulnerabilities 
                    if not v.false_positive}
        
        new_findings = current_ids - baseline_ids
        fixed_findings = baseline_ids - current_ids
        persistent_findings = baseline_ids & current_ids
        
        return {
            'baseline_task_id': baseline.task_id,
            'current_task_id': current.task_id,
            'new_findings_count': len(new_findings),
            'fixed_findings_count': len(fixed_findings),
            'persistent_findings_count': len(persistent_findings),
            'new_findings': list(new_findings),
            'fixed_findings': list(fixed_findings)
        }
    
    @staticmethod
    def calculate_fixing_rate(baseline: TaskResult, current: TaskResult) -> float:
        """Calculate vulnerability fixing rate"""
        comparison = ResultComparator.compare_results(baseline, current)
        baseline_count = baseline.total_findings()
        if baseline_count == 0:
            return 0.0
        fixed = comparison['fixed_findings_count']
        return (fixed / baseline_count) * 100


class ResultCache:
    """Caches task results for quick access"""
    
    def __init__(self, max_size: int = 100):
        self.cache: Dict[str, TaskResult] = {}
        self.max_size = max_size
        self.lock = threading.Lock()
        self.access_times: Dict[str, float] = {}
    
    def put(self, task_id: str, result: TaskResult) -> None:
        """Cache a result"""
        with self.lock:
            if len(self.cache) >= self.max_size:
                oldest = min(self.access_times.keys(), key=lambda k: self.access_times.get(k, 0))
                del self.cache[oldest]
                del self.access_times[oldest]
            
            self.cache[task_id] = result
            self.access_times[task_id] = time.time()
    
    def get(self, task_id: str) -> Optional[TaskResult]:
        """Get a cached result"""
        with self.lock:
            if task_id in self.cache:
                self.access_times[task_id] = time.time()
                return self.cache[task_id]
        return None
    
    def clear(self) -> None:
        """Clear cache"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
    
    def size(self) -> int:
        """Get cache size"""
        with self.lock:
            return len(self.cache)


class ResultReporter:
    """Generates reports from task results"""
    
    def __init__(self, aggregator: ResultAggregator):
        self.aggregator = aggregator
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary report"""
        summary = self.aggregator.get_summary()
        
        report = "# Executive Security Summary\n\n"
        report += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report += "## Overview\n\n"
        report += f"Total scans performed: {summary['total_scans']}\n"
        report += f"Total vulnerabilities found: {summary['total_findings']}\n\n"
        
        report += "## Risk Assessment\n\n"
        
        risk_score = (summary['critical'] * 10 + summary['high'] * 5 + 
                  summary['medium'] * 2 + summary['low'] * 1)
        
        if risk_score >= 50:
            risk_level = "CRITICAL"
            risk_color = "🔴"
        elif risk_score >= 25:
            risk_level = "HIGH"
            risk_color = "🟠"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        else:
            risk_level = "LOW"
            risk_color = "🟢"
        
        report += f"Risk Level: {risk_color} {risk_score} ({risk_level})\n\n"
        
        report += "## Vulnerabilities by Severity\n\n"
        report += f"- 🔴 Critical: {summary['critical']}\n"
        report += f"- 🟠 High: {summary['high']}\n"
        report += f"- 🟡 Medium: {summary['medium']}\n"
        report += f"- 🟢 Low: {summary['low']}\n\n"
        
        return report
    
    def generate_findings_report(self, min_severity: str = "low") -> str:
        """Generate detailed findings report"""
        min_level = SeverityLevel(min_severity)
        
        report = "# Security Findings Report\n\n"
        report += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, 
                SeverityLevel.MEDIUM, SeverityLevel.LOW]
        
        for severity in order:
            if severity.value not in [s.value for s in order[:order.index(min_level)+1]]:
                continue
                
            findings = [v for v in self.aggregator.aggregated_vulnerabilities
                      if v.severity == severity and not v.false_positive]
            
            if not findings:
                continue
            
            report += f"## {severity.value.upper()} Severity ({len(findings)})\n\n"
            
            for finding in findings:
                report += f"### {finding.title}\n\n"
                report += f"**Rule:** {finding.rule_id}\n"
                report += f"**CWE:** {finding.cwe_id}\n"
                if finding.line_number:
                    report += f"**Line:** {finding.line_number}\n"
                report += f"\n{finding.description}\n\n"
                if finding.recommendation:
                    report += f"**Recommendation:** {finding.recommendation}\n\n"
                report += "---\n\n"
        
        return report
    
    def generate_remediation_plan(self) -> str:
        """Generate remediation plan"""
        summary = self.aggregator.get_summary()
        
        plan = "# Remediation Plan\n\n"
        
        criticals = [v for v in self.aggregator.aggregated_vulnerabilities
                   if v.severity == SeverityLevel.CRITICAL and not v.false_positive]
        
        if criticals:
            plan += "## Immediate Actions (Critical)\n\n"
            for i, vuln in enumerate(criticals, 1):
                plan += f"{i}. **{vuln.title}**\n"
                plan += f"   - Rule: {vuln.rule_id}\n"
                plan += f"   - Recommendation: {vuln.recommendation}\n\n"
        
        highs = [v for v in self.aggregator.aggregated_vulnerabilities
               if v.severity == SeverityLevel.HIGH and not v.false_positive]
        
        if highs:
            plan += "## Short-term Actions (High)\n\n"
            for i, vuln in enumerate(highs, 1):
                plan += f"{i}. **{vuln.title}**\n"
                plan += f"   - Rule: {vuln.rule_id}\n"
                plan += f"   - Recommendation: {vuln.recommendation}\n\n"
        
        mediums = [v for v in self.aggregator.aggregated_vulnerabilities
                 if v.severity == SeverityLevel.MEDIUM and not v.false_positive]
        
        if mediums:
            plan += "## Medium-term Actions (Medium)\n\n"
            for i, vuln in enumerate(mediums, 1):
                plan += f"{i}. **{vuln.title}**\n"
                plan += f"   - Rule: {vuln.rule_id}\n\n"
        
        return plan
    
    def export_full_report(self, filepath: str, format: str = "markdown") -> bool:
        """Export full report"""
        try:
            if format == "markdown":
                content = self.generate_executive_summary()
                content += "\n\n" + self.generate_findings_report()
                content += "\n\n" + self.generate_remediation_plan()
                with open(filepath, 'w') as f:
                    f.write(content)
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


_default_cache: Optional[ResultCache] = None


def get_result_cache() -> ResultCache:
    """Get or create result cache"""
    global _default_cache
    if _default_cache is None:
        _default_cache = ResultCache()
    return _default_cache


def save_result(task_id: str, result: TaskResult) -> None:
    """Quick helper to save result"""
    cache = get_result_cache()
    cache.put(task_id, result)


def load_result(task_id: str) -> Optional[TaskResult]:
    """Quick helper to load result"""
    cache = get_result_cache()
    return cache.get(task_id)


if __name__ == "__main__":
    finding = VulnerabilityFinding(
        finding_id="VULN-001",
        rule_id="REENT-001",
        title="Reentrancy Vulnerability",
        description="Function allows recursive calls",
        severity=SeverityLevel.CRITICAL,
        category="reentrancy",
        cwe_id="CWE-362",
        cwe_url="https://cwe.mitre.org/data/definitions/362.html",
        line_number=42,
        code_snippet="function withdraw() public { ... }",
        recommendation="Use reentrancy guard"
    )
    
    result = TaskResult(
        task_id="scan-001",
        task_name="Contract Scan",
        task_type="security_scan",
        status=ResultStatus.SUCCESS,
        category=ResultCategory.SECURITY_SCAN,
        contract_name="MyContract",
        contract_address="0x123",
        start_time=time.time(),
        vulnerabilities=[finding]
    )
    
    print(ResultFormatter.format_text(result))