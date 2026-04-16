"""
Solidify Smart Contract Diff Analyzer Module

This module provides comprehensive diff analysis capabilities for comparing smart contract
versions, identifying changes, and analyzing security implications of code modifications.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
import difflib
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging
import subprocess
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DiffType(Enum):
    ADDITION = "addition"
    DELETION = "deletion"
    MODIFICATION = "modification"
    UNCHANGED = "unchanged"
    RENAMED = "renamed"


class ComparisonLevel(Enum):
    LINE = "line"
    FUNCTION = "function"
    CONTRACT = "contract"
    MODULE = "module"
    FILE = "file"


class ChangeSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class DiffLine:
    line_number_old: Optional[int]
    line_number_new: Optional[int]
    content_old: str
    content_new: str
    diff_type: DiffType
    is_context: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'line_number_old': self.line_number_old,
            'line_number_new': self.line_number_new,
            'content_old': self.content_old,
            'content_new': self.content_new,
            'diff_type': self.diff_type.value,
            'is_context': self.is_context
        }


@dataclass
class FunctionDiff:
    function_name: str
    old_signature: str
    new_signature: str
    old_source: str
    new_source: str
    added_lines: int
    removed_lines: int
    modified_lines: int
    change_severity: ChangeSeverity
    
    def get_change_summary(self) -> str:
        changes = []
        if self.added_lines > 0:
            changes.append(f"+{self.added_lines}")
        if self.removed_lines > 0:
            changes.append(f"-{self.removed_lines}")
        return ", ".join(changes) if changes else "no changes"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'old_signature': self.old_signature,
            'new_signature': self.new_signature,
            'source_changed': self.old_source != self.new_source,
            'added_lines': self.added_lines,
            'removed_lines': self.removed_lines,
            'modified_lines': self.modified_lines,
            'change_severity': self.change_severity.value,
            'change_summary': self.get_change_summary()
        }


@dataclass
class ContractDiff:
    contract_name: str
    old_source: str
    new_source: str
    function_diffs: List[FunctionDiff]
    storage_changes: Dict[str, Any]
    inheritance_changes: List[str]
    modifier_changes: Dict[str, Any]
    event_changes: Dict[str, Any]
    
    def get_total_changes(self) -> int:
        return sum(1 for f in self.function_diffs if f.change_severity != ChangeSeverity.NONE)
    
    def has_critical_changes(self) -> bool:
        return any(f.change_severity == ChangeSeverity.CRITICAL for f in self.function_diffs)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'contract_name': self.contract_name,
            'function_count': len(self.function_diffs),
            'total_changes': self.get_total_changes(),
            'has_critical_changes': self.has_critical_changes(),
            'function_diffs': [f.to_dict() for f in self.function_diffs],
            'storage_changes': self.storage_changes,
            'inheritance_changes': self.inheritance_changes,
            'modifier_changes': self.modifier_changes,
            'event_changes': self.event_changes
        }


@dataclass
class DiffResult:
    old_file: str
    new_file: str
    comparison_level: ComparisonLevel
    lines: List[DiffLine]
    function_diffs: List[FunctionDiff]
    contract_diffs: List[ContractDiff]
    statistics: Dict[str, Any]
    security_implications: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'old_file': self.old_file,
            'new_file': self.new_file,
            'comparison_level': self.comparison_level.value,
            'statistics': self.statistics,
            'security_implications': self.security_implications
        }


class DiffParser:
    def __init__(self):
        self.diff_text: str = ""
        self.lines: List[DiffLine] = []
    
    def parse_unified_diff(self, diff_text: str) -> List[DiffLine]:
        self.diff_text = diff_text
        self.lines = []
        
        current_old_line = 0
        current_new_line = 0
        
        for line in diff_text.split('\n'):
            if line.startswith('@@'):
                match = re.search(r'@@ -(\d+),?\d* \+(\d+),?\d* @@', line)
                if match:
                    current_old_line = int(match.group(1))
                    current_new_line = int(match.group(2))
                continue
            
            if line.startswith('+') and not line.startswith('+++'):
                self.lines.append(DiffLine(
                    line_number_old=None,
                    line_number_new=current_new_line,
                    content_old="",
                    content_new=line[1:],
                    diff_type=DiffType.ADDITION
                ))
                current_new_line += 1
            
            elif line.startswith('-') and not line.startswith('---'):
                self.lines.append(DiffLine(
                    line_number_old=current_old_line,
                    line_number_new=None,
                    content_old=line[1:],
                    content_new="",
                    diff_type=DiffType.DELETION
                ))
                current_old_line += 1
            
            elif line.startswith(' ') or line.startswith('\n') or not line:
                if line.strip():
                    self.lines.append(DiffLine(
                        line_number_old=current_old_line,
                        line_number_new=current_new_line,
                        content_old=line[1:] if line.startswith(' ') else line,
                        content_new=line[1:] if line.startswith(' ') else line,
                        diff_type=DiffType.UNCHANGED,
                        is_context=True
                    ))
                current_old_line += 1
                current_new_line += 1
        
        return self.lines
    
    def get_changed_lines(self) -> List[DiffLine]:
        return [l for l in self.lines if l.diff_type != DiffType.UNCHANGED]
    
    def get_additions(self) -> List[DiffLine]:
        return [l for l in self.lines if l.diff_type == DiffType.ADDITION]
    
    def get_deletions(self) -> List[DiffLine]:
        return [l for l in self.lines if l.diff_type == DiffType.DELETION]


class FunctionExtractor:
    def __init__(self):
        self.functions: Dict[str, Dict[str, str]] = {}
    
    def extract_functions(self, source_code: str) -> Dict[str, Dict[str, str]]:
        self.functions = {}
        
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:.*?)\s*(?:returns\s*\(([^)]*)\))?\s*\{'
        matches = re.finditer(func_pattern, source_code, re.DOTALL)
        
        for match in matches:
            func_name = match.group(1)
            params = match.group(2)
            returns = match.group(3) if match.lastindex >= 3 else ""
            
            start = match.start()
            brace_count = 0
            end = start
            for i, char in enumerate(source_code[start:], start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break
            
            func_source = source_code[start:end]
            
            self.functions[func_name] = {
                'signature': f"function {func_name}({params})" + (f" returns ({returns})" if returns else ""),
                'source': func_source
            }
        
        return self.functions
    
    def extract_signatures(self, source_code: str) -> Dict[str, str]:
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:.*?)(?:returns\s*\(([^)]*)\))?'
        matches = re.finditer(func_pattern, source_code)
        
        return {m.group(1): m.group(0) for m in matches}


class SecurityImpactAnalyzer:
    def __init__(self):
        self.critical_patterns = [
            (r'selfdestruct|suicide', 'Self-destruct capability'),
            (r'delegatecall', 'Delegatecall usage'),
            (r'call\{value:', 'Ether transfer'),
            (r'mint\(|_mint', 'Token minting'),
            (r'burn\(|_burn', 'Token burning'),
            (r'setOwner|transferOwnership', 'Ownership transfer'),
            (r'upgrade|upgradeTo', 'Contract upgrade'),
        ]
        
        self.high_risk_patterns = [
            (r'block\.timestamp', 'Timestamp dependency'),
            (r'block\.hash', 'Block hash usage'),
            (r'keccak256\(abi\.encodePacked\(.*block\.', 'Weak randomness'),
            (r'tx\.origin', 'tx.origin usage'),
            (r'call\(.*\(', 'Dynamic call'),
            (r' assembly ', 'Inline assembly'),
        ]
        
        self.medium_risk_patterns = [
            (r'SafeMath', 'SafeMath usage'),
            (r'require\(|assert\(', 'Error handling'),
            (r'emit', 'Event emission'),
            (r'modifier', 'Custom modifier'),
        ]
    
    def analyze_change(self, old_code: str, new_code: str) -> List[Dict[str, Any]]:
        implications = []
        
        for pattern, description in self.critical_patterns:
            if re.search(pattern, new_code) and not re.search(pattern, old_code):
                implications.append({
                    'severity': 'critical',
                    'type': 'new_critical_feature',
                    'feature': description,
                    'description': f"Critical feature '{description}' added"
                })
        
        for pattern, description in self.high_risk_patterns:
            if re.search(pattern, new_code) and not re.search(pattern, old_code):
                implications.append({
                    'severity': 'high',
                    'type': 'new_risk_pattern',
                    'feature': description,
                    'description': f"High-risk pattern '{description}' detected"
                })
        
        for pattern, description in self.medium_risk_patterns:
            if re.search(pattern, new_code) and not re.search(pattern, old_code):
                implications.append({
                    'severity': 'medium',
                    'type': 'new_feature',
                    'feature': description,
                    'description': f"Feature '{description}' added"
                })
        
        removed_critical = []
        for pattern, description in self.critical_patterns:
            if re.search(pattern, old_code) and not re.search(pattern, new_code):
                removed_critical.append(description)
        
        if removed_critical:
            implications.append({
                'severity': 'high',
                'type': 'removed_feature',
                'features': removed_critical,
                'description': "Security features removed"
            })
        
        return implications
    
    def assess_severity(self, diff: List[DiffLine]) -> ChangeSeverity:
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        combined = ' '.join([l.content_new for l in diff])
        
        for pattern, _ in self.critical_patterns:
            if re.search(pattern, combined):
                critical_count += 1
        
        for pattern, _ in self.high_risk_patterns:
            if re.search(pattern, combined):
                high_count += 1
        
        for pattern, _ in self.medium_risk_patterns:
            if re.search(pattern, combined):
                medium_count += 1
        
        if critical_count > 0:
            return ChangeSeverity.CRITICAL
        elif high_count > 2:
            return ChangeSeverity.HIGH
        elif medium_count > 5:
            return ChangeSeverity.MEDIUM
        else:
            return ChangeSeverity.LOW
    
    def get_gas_impact(self, old_code: str, new_code: str) -> Dict[str, Any]:
        old_lines = len(old_code.split('\n'))
        new_lines = len(new_code.split('\n'))
        
        return {
            'old_line_count': old_lines,
            'new_line_count': new_lines,
            'line_diff': new_lines - old_lines,
            'percentage_change': ((new_lines - old_lines) / old_lines * 100) if old_lines > 0 else 0
        }


class DiffAnalyzer:
    def __init__(self):
        self.parser = DiffParser()
        self.extractor = FunctionExtractor()
        self.security_analyzer = SecurityImpactAnalyzer()
        self.results: List[DiffResult] = []
    
    def analyze_files(self, old_file: str, new_file: str, 
                    comparison_level: ComparisonLevel = ComparisonLevel.LINE) -> DiffResult:
        
        with open(old_file, 'r') as f:
            old_content = f.read()
        
        with open(new_file, 'r') as f:
            new_content = f.read()
        
        return self.analyze_content(old_content, new_content, old_file, new_file, comparison_level)
    
    def analyze_content(self, old_content: str, new_content: str, 
                    old_file: str, new_file: str,
                    comparison_level: ComparisonLevel = ComparisonLevel.LINE) -> DiffResult:
        
        diff = list(difflib.unified_diff(
            old_content.split('\n'),
            new_content.split('\n'),
            lineterm='',
            fromfile=old_file,
            tofile=new_file
        ))
        
        diff_text = '\n'.join(diff)
        lines = self.parser.parse_unified_diff(diff_text)
        changed_lines = self.parser.get_changed_lines()
        
        function_diffs = []
        if comparison_level in [ComparisonLevel.FUNCTION, ComparisonLevel.CONTRACT]:
            old_funcs = self.extractor.extract_functions(old_content)
            new_funcs = self.extractor.extract_functions(new_content)
            
            all_funcs = set(old_funcs.keys()) | set(new_funcs.keys())
            
            for func_name in all_funcs:
                old_source = old_funcs.get(func_name, {}).get('source', '')
                new_source = new_funcs.get(func_name, {}).get('source', '')
                
                if func_name not in old_funcs:
                    diff = FunctionDiff(
                        function_name=func_name,
                        old_signature="",
                        new_signature=new_funcs[func_name]['signature'],
                        old_source="",
                        new_source=new_source,
                        added_lines=len(new_source.split('\n')),
                        removed_lines=0,
                        modified_lines=0,
                        change_severity=ChangeSeverity.LOW
                    )
                elif func_name not in new_funcs:
                    diff = FunctionDiff(
                        function_name=func_name,
                        old_signature=old_funcs[func_name]['signature'],
                        new_signature="",
                        old_source=old_source,
                        new_source="",
                        added_lines=0,
                        removed_lines=len(old_source.split('\n')),
                        modified_lines=0,
                        change_severity=ChangeSeverity.HIGH
                    )
                else:
                    added = len(new_source.split('\n')) - len(old_source.split('\n'))
                    removed = abs(added) if added < 0 else 0
                    modified = abs(added) if added > 0 else 0
                    
                    severity = self.security_analyzer.assess_severity(
                        self.parser.get_changed_lines()
                    )
                    
                    diff = FunctionDiff(
                        function_name=func_name,
                        old_signature=old_funcs[func_name]['signature'],
                        new_signature=new_funcs[func_name]['signature'],
                        old_source=old_source,
                        new_source=new_source,
                        added_lines=added if added > 0 else 0,
                        removed_lines=removed,
                        modified_lines=modified,
                        change_severity=severity
                    )
                
                function_diffs.append(diff)
        
        security_implications = self.security_analyzer.analyze_change(old_content, new_content)
        gas_impact = self.security_analyzer.get_gas_impact(old_content, new_content)
        
        statistics = {
            'additions': len(self.parser.get_additions()),
            'deletions': len(self.parser.get_deletions()),
            'total_changes': len(changed_lines),
            'function_changes': len(function_diffs),
            'security_implications': len(security_implications),
            'gas_impact': gas_impact
        }
        
        return DiffResult(
            old_file=old_file,
            new_file=new_file,
            comparison_level=comparison_level,
            lines=changed_lines,
            function_diffs=function_diffs,
            contract_diffs=[],
            statistics=statistics,
            security_implications=security_implications
        )
    
    def analyze_multiple(self, comparisons: List[Tuple[str, str]]) -> List[DiffResult]:
        results = []
        
        for old_file, new_file in comparisons:
            result = self.analyze_files(old_file, new_file)
            results.append(result)
        
        return results
    
    def generate_report(self, result: DiffResult) -> Dict[str, Any]:
        critical_changes = [s for s in result.security_implications if s.get('severity') == 'critical']
        high_changes = [s for s in result.security_implications if s.get('severity') == 'high']
        
        return {
            'summary': {
                'old_file': result.old_file,
                'new_file': result.new_file,
                'total_changes': result.statistics['total_changes'],
                'additions': result.statistics['additions'],
                'deletions': result.statistics['deletions'],
                'critical_changes': len(critical_changes),
                'high_changes': len(high_changes),
                'function_changes': result.statistics['function_changes']
            },
            'function_diffs': [f.to_dict() for f in result.function_diffs],
            'security_implications': result.security_implications,
            'gas_impact': result.statistics['gas_impact'],
            'recommendations': self._generate_recommendations(result.security_implications)
        }
    
    def _generate_recommendations(self, implications: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        
        severities = [s.get('severity') for s in implications]
        
        if 'critical' in severities:
            recommendations.append("URGENT: Critical security changes detected - review immediately")
            recommendations.append("Consider comprehensive security audit")
        
        if 'high' in severities:
            recommendations.append("Review high-risk changes carefully")
            recommendations.append("Ensure new patterns follow best practices")
        
        return recommendations
    
    def export_json(self, result: DiffResult, filepath: str):
        report = self.generate_report(result)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Diff analysis report saved to {filepath}")
    
    def export_csv(self, result: DiffResult, filepath: str):
        import csv
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Severity', 'Change', 'Description'])
            
            for func_diff in result.function_diffs:
                writer.writerow([
                    'function',
                    func_diff.change_severity.value,
                    func_diff.get_change_summary(),
                    func_diff.function_name
                ])
            
            for impl in result.security_implications:
                writer.writerow([
                    'security',
                    impl.get('severity'),
                    impl.get('type'),
                    impl.get('description')
                ])
        
        logger.info(f"CSV export saved to {filepath}")


class VersionComparator:
    def __init__(self):
        self.versions: List[Dict[str, str]] = []
    
    def add_version(self, version: str, source: str, metadata: Optional[Dict[str, Any]] = None):
        self.versions.append({
            'version': version,
            'source': source,
            'metadata': metadata or {},
            'timestamp': time.time()
        })
    
    def compare_versions(self, version_a: str, version_b: str) -> Optional[Dict[str, Any]]:
        source_a = None
        source_b = None
        
        for v in self.versions:
            if v['version'] == version_a:
                source_a = v['source']
            if v['version'] == version_b:
                source_b = v['source']
        
        if not source_a or not source_b:
            return None
        
        analyzer = DiffAnalyzer()
        result = analyzer.analyze_content(source_a, source_b, version_a, version_b)
        
        return analyzer.generate_report(result)
    
    def get_version_history(self) -> List[Dict[str, Any]]:
        return [
            {
                'version': v['version'],
                'metadata': v['metadata'],
                'timestamp': v['timestamp']
            }
            for v in self.versions
        ]


def analyze_diff(old_content: str, new_content: str, 
               old_file: str = "old", new_file: str = "new") -> Dict[str, Any]:
    analyzer = DiffAnalyzer()
    result = analyzer.analyze_content(old_content, new_content, old_file, new_file)
    return analyzer.generate_report(result)


if __name__ == '__main__':
    old_code = """
pragma solidity ^0.8.0;

contract Storage {
    uint256 public value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
}
    """
    
    new_code = """
pragma solidity ^0.8.0;

contract Storage {
    uint256 public value;
    address public owner;
    
    function setValue(uint256 _value) external {
        require(msg.sender == owner);
        value = _value;
    }
    
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner);
    }
}
    """
    
    result = analyze_diff(old_code, new_code)
    print(json.dumps(result, indent=2))