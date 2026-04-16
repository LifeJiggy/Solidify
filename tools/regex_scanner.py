"""
Regex Pattern Scanner Module for Smart Contract Security

This module provides comprehensive regex-based pattern scanning for detecting
security vulnerabilities and code patterns in smart contracts.

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
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PatternCategory(Enum):
    SECURITY = "security"
    BEST_PRACTICE = "best_practice"
    GAS_OPTIMIZATION = "gas_optimization"
    CODE_QUALITY = "code_quality"
    DOCUMENTATION = "documentation"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PatternMatch:
    pattern_id: str
    pattern_name: str
    category: PatternCategory
    severity: SeverityLevel
    line_number: int
    line_content: str
    matched_text: str
    description: str
    recommendation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern_id': self.pattern_id,
            'pattern_name': self.pattern_name,
            'category': self.category.value,
            'severity': self.severity.value,
            'line_number': self.line_number,
            'line_content': self.line_content[:100],
            'matched_text': self.matched_text[:50],
            'description': self.description,
            'recommendation': self.recommendation
        }


class SecurityPattern:
    def __init__(self):
        self.patterns: Dict[str, Dict[str, Any]] = {
            'SEC-001': {
                'name': 'Self-Destruct Usage',
                'pattern': r'selfdestruct|suicide',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.CRITICAL,
                'description': 'Self-destruct can be used to destroy the contract',
                'recommendation': 'Review and remove self-destruct or add proper access control'
            },
            'SEC-002': {
                'name': 'Delegatecall Usage',
                'pattern': r'delegatecall',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.HIGH,
                'description': 'Delegatecall can lead to storage manipulation',
                'recommendation': 'Validate delegatecall target or avoid usage'
            },
            'SEC-003': {
                'name': 'Unchecked Return Value',
                'pattern': r'\.call\s*\([^)]*\)\s*;(?!\s*require)',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.HIGH,
                'description': 'Return value of low-level call not checked',
                'recommendation': 'Always check return value or use SafeERC20'
            },
            'SEC-004': {
                'name': 'Block Timestamp Dependency',
                'pattern': r'block\.timestamp',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.MEDIUM,
                'description': 'Block timestamp can be manipulated by miners',
                'recommendation': 'Use block.number or external oracle'
            },
            'SEC-005': {
                'name': 'Tx Origin Usage',
                'pattern': r'tx\.origin',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.MEDIUM,
                'description': 'tx.origin vulnerable to phishing',
                'recommendation': 'Use msg.sender instead'
            },
            'SEC-006': {
                'name': 'Weak Randomness',
                'pattern': r'keccak256\s*\(\s*block\.(timestamp|difficulty)',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.HIGH,
                'description': 'Predictable randomness source',
                'recommendation': 'Use Chainlink VRF or commit-reveal'
            },
            'SEC-007': {
                'name': 'Integer Overflow',
                'pattern': r'[+\-*/]\s*\w+\s*;(?!(?:.*SafeMath|.*0\.8))',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.HIGH,
                'description': 'Potential arithmetic overflow',
                'recommendation': 'Use SafeMath or Solidity 0.8+'
            },
            'SEC-008': {
                'name': 'Missing Access Control',
                'pattern': r'function\s+(withdraw|mint|burn|pause)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|modifier))',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.HIGH,
                'description': 'Sensitive function lacks access control',
                'recommendation': 'Add onlyOwner or role-based modifier'
            },
            'SEC-009': {
                'name': 'Ether Transfer Without Checks',
                'pattern': r'(?:call|send)\s*\{.*value:',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.MEDIUM,
                'description': 'Ether transfer may fail silently',
                'recommendation': 'Use pull payment pattern or check result'
            },
            'SEC-010': {
                'name': 'Inline Assembly',
                'pattern': r'assembly\s*\{',
                'category': PatternCategory.SECURITY,
                'severity': SeverityLevel.MEDIUM,
                'description': 'Inline assembly increases complexity',
                'recommendation': 'Review and minimize assembly usage'
            },
            'SEC-011': {
                'name': 'Floating Pragma',
                'pattern': r'pragma\s+solidity\s+\^',
                'category': PatternCategory.BEST_PRACTICE,
                'severity': SeverityLevel.LOW,
                'description': 'Floating pragma can lead to inconsistencies',
                'recommendation': 'Lock pragma version or use consistent versions'
            },
            'SEC-012': {
                'name': 'Unlocked Pragma',
                'pattern': r'pragma\s+solidity\s+>\s*0\.[0-9]+',
                'category': PatternCategory.BEST_PRACTICE,
                'severity': SeverityLevel.MEDIUM,
                'description': 'Unlocked pragma may compile with unreleased versions',
                'recommendation': 'Lock to specific version or minimum version'
            },
            'SEC-013': {
                'name': 'Missing NatSpec',
                'pattern': r'function\s+\w+\s*\([^)]*\)\s*(?:public|external|internal|private)\s*\{(?!\s*/\*\*|\s*///)',
                'category': PatternCategory.DOCUMENTATION,
                'severity': SeverityLevel.INFO,
                'description': 'Function lacks NatSpec documentation',
                'recommendation': 'Add @notice, @param, @return comments'
            },
            'SEC-014': {
                'name': 'Variable Naming',
                'pattern': r'(?:uint|int|address|string|bool|bytes)\s+[A-Z]\w+',
                'category': PatternCategory.CODE_QUALITY,
                'severity': SeverityLevel.INFO,
                'description': 'State variable starts with uppercase',
                'recommendation': 'Use CapWords convention for state variables'
            },
            'SEC-015': {
                'name': 'Magic Numbers',
                'pattern': r'(?:0x[a-fA-F0-9]{40}|(?:[0-9]{4,})',
                'category': PatternCategory.CODE_QUALITY,
                'severity': SeverityLevel.LOW,
                'description': 'Magic numbers in code',
                'recommendation': 'Define as constants with clear names'
            },
            'SEC-016': {
                'name': 'Unbounded Loop',
                'pattern': r'for\s*\([^)]*\.length[^)]*\)',
                'category': PatternCategory.GAS_OPTIMIZATION,
                'severity': SeverityLevel.MEDIUM,
                'description': 'Loop with unbounded iterations',
                'recommendation': 'Limit iterations or use mapping'
            },
            'SEC-017': {
                'name': 'Multiple External Calls',
                'pattern': r'for\s*\(.*\{[^}]*\.call',
                'category': PatternCategory.GAS_OPTIMIZATION,
                'severity': SeverityLevel.MEDIUM,
                'description': 'Multiple external calls in loop',
                'recommendation': 'Batch calls outside loop or use aggregation'
            },
            'SEC-018': {
                'name': 'Redundant Storage Read',
                'pattern': r'require\([^)]*(?:balanceOf|ownerOf)[^)]*(?:==|<|>)',
                'category': PatternCategory.GAS_OPTIMIZATION,
                'severity': SeverityLevel.LOW,
                'description': 'Repeated storage reads',
                'recommendation': 'Cache storage values in memory'
            },
            'SEC-019': {
                'name': 'Missing Event Emission',
                'pattern': r'function\s+(set|transfer|mint|burn)\s*\([^)]*\)(?:.*?)(?!\s*emit)',
                'category': PatternCategory.BEST_PRACTICE,
                'severity': SeverityLevel.LOW,
                'description': 'State-changing function missing event',
                'recommendation': 'Emit event for state changes'
            },
            'SEC-020': {
                'name': 'Custom Error Without Base',
                'pattern': r'revert\s+"[^"]+";(?!(?:.*Error))',
                'category': PatternCategory.BEST_PRACTICE,
                'severity': SeverityLevel.INFO,
                'description': 'Custom error strings instead of custom errors',
                'recommendation': 'Use custom error types (Solidity 0.8.4+)'
            }
        }
    
    def scan(self, source_code: str) -> List[PatternMatch]:
        matches = []
        lines = source_code.split('\n')
        
        for pattern_id, pattern_info in self.patterns.items():
            pattern = pattern_info['pattern']
            
            try:
                regex = re.compile(pattern)
            except re.error:
                continue
            
            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    match = PatternMatch(
                        pattern_id=pattern_id,
                        pattern_name=pattern_info['name'],
                        category=pattern_info['category'],
                        severity=pattern_info['severity'],
                        line_number=line_num,
                        line_content=line.strip(),
                        matched_text=regex.findall(line)[0] if regex.findall(line) else '',
                        description=pattern_info['description'],
                        recommendation=pattern_info['recommendation']
                    )
                    matches.append(match)
        
        return matches
    
    def get_patterns_by_category(self, category: PatternCategory) -> Dict[str, Dict[str, Any]]:
        return {k: v for k, v in self.patterns.items() if v['category'] == category}
    
    def get_patterns_by_severity(self, severity: SeverityLevel) -> Dict[str, Dict[str, Any]]:
        return {k: v for k, v in self.patterns.items() if v['severity'] == severity}


class RegexScanner:
    def __init__(self):
        self.pattern_matcher = SecurityPattern()
        self.scan_results: List[PatternMatch] = []
    
    def scan_code(self, source_code: str, 
                 categories: Optional[List[PatternCategory]] = None,
                 severities: Optional[List[SeverityLevel]] = None) -> List[PatternMatch]:
        
        all_matches = self.pattern_matcher.scan(source_code)
        
        filtered_matches = all_matches
        
        if categories:
            filtered_matches = [m for m in filtered_matches if m.category in categories]
        
        if severities:
            filtered_matches = [m for m in filtered_matches if m.severity in severities]
        
        self.scan_results = filtered_matches
        return filtered_matches
    
    def get_statistics(self) -> Dict[str, Any]:
        severity_counts = Counter()
        category_counts = Counter()
        pattern_counts = Counter()
        
        for match in self.scan_results:
            severity_counts[match.severity.value] += 1
            category_counts[match.category.value] += 1
            pattern_counts[match.pattern_name] += 1
        
        return {
            'total_matches': len(self.scan_results),
            'by_severity': dict(severity_counts),
            'by_category': dict(category_counts),
            'by_pattern': dict(pattern_counts)
        }
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'summary': self.get_statistics(),
            'matches': [m.to_dict() for m in self.scan_results]
        }
    
    def export_json(self, filepath: str):
        report = self.generate_report()
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Scan report saved to {filepath}")
    
    def filter_by_cwe(self, cwe_ids: List[str]) -> List[PatternMatch]:
        cwe_mapping = {
            'CWE-20': ['SEC-001', 'SEC-002'],
            'CWE-22': ['SEC-001'],
            'CWE-78': ['SEC-002'],
            'CWE-94': ['SEC-002', 'SEC-010'],
            'CWE-119': ['SEC-017'],
            'CWE-200': ['SEC-012'],
            'CWE-264': ['SEC-008'],
            'CWE-284': ['SEC-008'],
            'CWE-287': ['SEC-008'],
            'CWE-306': ['SEC-008'],
            'CWE-330': ['SEC-001'],
            'CWE-362': ['SEC-006'],
            'CWE-400': ['SEC-016'],
            'CWE-416': ['SEC-007'],
            'CWE-434': ['SEC-008'],
            'CWE-502': ['SEC-003']
        }
        
        allowed_patterns = set()
        for cwe_id in cwe_ids:
            allowed_patterns.update(cwe_mapping.get(cwe_id, []))
        
        return [m for m in self.scan_results if m.pattern_id in allowed_patterns]


def scan_smart_contract(source_code: str, 
                   include_security: bool = True,
                   include_optimization: bool = True) -> Dict[str, Any]:
    scanner = RegexScanner()
    
    categories = []
    if include_security:
        categories.extend([PatternCategory.SECURITY, PatternCategory.BEST_PRACTICE])
    if include_optimization:
        categories.append(PatternCategory.GAS_OPTIMIZATION)
    
    matches = scanner.scan_code(source_code, categories)
    return scanner.generate_report()


if __name__ == '__main__':
    sample = """
pragma solidity ^0.8.0;

contract Vulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }
    
    function kill() public {
        selfdestruct(msg.sender);
    }
}
    """
    
    result = scan_smart_contract(sample)
    print(json.dumps(result, indent=2))