"""
Smart Contract Pattern Matcher Module

This module provides comprehensive pattern matching capabilities for detecting
security vulnerabilities, code patterns, and anti-patterns in smart contracts.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
import ast
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PatternType(Enum):
    VULNERABILITY = "vulnerability"
    SECURITY_PATTERN = "security_pattern"
    ANTI_PATTERN = "anti_pattern"
    BEST_PRACTICE = "best_practice"
    GAS_OPTIMIZATION = "gas_optimization"
    CODE_SMELL = "code_smell"
    DOCUMENTATION = "documentation"
    ARCHITECTURE = "architecture"


class PatternSeverity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    NONE = 0


class MatchConfidence(Enum):
    CERTAIN = 1.0
    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.5
    SPECULATIVE = 0.3


@dataclass
class PatternDefinition:
    pattern_id: str
    name: str
    pattern_type: PatternType
    severity: PatternSeverity
    description: str
    regex_pattern: str
    false_positive_rate: float
    cwe_ids: List[str]
    references: List[str]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern_id': self.pattern_id,
            'name': self.name,
            'pattern_type': self.pattern_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'cwe_ids': self.cwe_ids,
            'recommendations': self.recommendations
        }


@dataclass
class PatternMatch:
    pattern: PatternDefinition
    line_number: int
    line_content: str
    match_text: str
    confidence: MatchConfidence
    context: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern_id': self.pattern.pattern_id,
            'pattern_name': self.pattern.name,
            'severity': self.pattern.severity.value,
            'line_number': self.line_number,
            'matched_text': self.match_text,
            'confidence': self.confidence.value,
            'context': self.context
        }


class VulnerabilityPatternRegistry:
    def __init__(self):
        self.patterns: Dict[str, PatternDefinition] = {}
        self._register_all_patterns()
    
    def _register_all_patterns(self):
        self.patterns = {
            "SEC-VULN-001": PatternDefinition(
                pattern_id="SEC-VULN-001",
                name="Reentrancy Vulnerability",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.CRITICAL,
                description="Potential reentrancy vulnerability detected",
                regex_pattern=r'\.(call|send|transfer)\s*\{.*\}.*;|call\s*\(\s*[^)]*\s*\)\s*;(?!\s*require)',
                false_positive_rate=0.15,
                cwe_ids=["CWE-362", "CWE-841"],
                references=["SWC-107"],
                recommendations=["Use ReentrancyGuard", "Apply checks-effects-interactions pattern"]
            ),
            "SEC-VULN-002": PatternDefinition(
                pattern_id="SEC-VULN-002",
                name="Missing Access Control",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.CRITICAL,
                description="Function lacks access control modifier",
                regex_pattern=r'function\s+(withdraw|mint|burn|pause|upgrade|set.*Root)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|modifier|requiresAuth))',
                false_positive_rate=0.10,
                cwe_ids=["CWE-284", "CWE-862"],
                references=["SWC-100"],
                recommendations=["Add access control modifier", "Implement role-based access"]
            ),
            "SEC-VULN-003": PatternDefinition(
                pattern_id="SEC-VULN-003",
                name="Unchecked Return Value",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.HIGH,
                description="Return value of low-level call not checked",
                regex_pattern=r'\.(call|send|delegatecall)\s*\([^)]*\)\s*;(?!\s*require|\s*if\s*\()',
                false_positive_rate=0.20,
                cwe_ids=["CWE-252", "CWE-756"],
                references=["SWC-104"],
                recommendations=["Check return value", "Use SafeERC20 library"]
            ),
            "SEC-VULN-004": PatternDefinition(
                pattern_id="SEC-VULN-004",
                name="Integer Overflow/Underflow",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.HIGH,
                description="Potential arithmetic overflow without SafeMath",
                regex_pattern=r'[+\-*/]\s*\w+\s*;(?!\s*0\.8)(?!\s*SafeMath)',
                false_positive_rate=0.25,
                cwe_ids=["CWE-190", "CWE-191"],
                references=["SWC-101"],
                recommendations=["Use Solidity 0.8+", "Use SafeMath library"]
            ),
            "SEC-VULN-005": PatternDefinition(
                pattern_id="SEC-VULN-005",
                name="Weak Randomness",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.HIGH,
                description="Predictable randomness source",
                regex_pattern=r'keccak256\s*\(\s*block\.(timestamp|difficulty|number|coinbase)',
                false_positive_rate=0.20,
                cwe_ids=["CWE-338", "CWE-341"],
                references=["SWC-120"],
                recommendations=["Use Chainlink VRF", "Use commit-reveal scheme"]
            ),
            "SEC-VULN-006": PatternDefinition(
                pattern_id="SEC-VULN-006",
                name="Block Timestamp Dependence",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.MEDIUM,
                description="Critical logic depends on block.timestamp",
                regex_pattern=r'block\.timestamp(?!\s*0\.[0-9])',
                false_positive_rate=0.30,
                cwe_ids=["CWE-829", "CWE-367"],
                references=["SWC-116"],
                recommendations=["Use block.number", "Use external oracle"]
            ),
            "SEC-VULN-007": PatternDefinition(
                pattern_id="SEC-VULN-007",
                name="tx.origin Authentication",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.MEDIUM,
                description="tx.origin used for authentication",
                regex_pattern=r'tx\.origin',
                false_positive_rate=0.10,
                cwe_ids=["CWE-346", "CWE-477"],
                references=["SWC-115"],
                recommendations=["Use msg.sender instead"]
            ),
            "SEC-VULN-008": PatternDefinition(
                pattern_id="SEC-VULN-008",
                name="Delegatecall to Untrusted Contract",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.CRITICAL,
                description="delegatecall to user-controlled address",
                regex_pattern=r'delegatecall\s*\(\s*[^msg\.]',
                false_positive_rate=0.15,
                cwe_ids=["CWE-829", "CWE-494"],
                references=["SWC-112"],
                recommendations=["Validate delegatecall target", "Avoid dynamic delegatecall"]
            ),
            "SEC-VULN-009": PatternDefinition(
                pattern_id="SEC-VULN-009",
                name="Self-destruct Usage",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.CRITICAL,
                description="Contract can self-destruct",
                regex_pattern=r'selfdestruct|suicide',
                false_positive_rate=0.05,
                cwe_ids=["CWE-506"],
                references=["SWC-106"],
                recommendations=["Review self-destruct usage", "Add access control"]
            ),
            "SEC-VULN-010": PatternDefinition(
                pattern_id="SEC-VULN-010",
                name="Unprotected Ether Withdrawal",
                pattern_type=PatternType.VULNERABILITY,
                severity=PatternSeverity.CRITICAL,
                description="Ether can be withdrawn without restrictions",
                regex_pattern=r'payable\([^)]*\)\.send\s*\{*value:|\.transfer\s*\(',
                false_positive_rate=0.15,
                cwe_ids=["CWE-306", "CWE-284"],
                references=["SWC-105"],
                recommendations=["Use pull payment pattern", "Add access control"]
            ),
            "SEC-PAT-001": PatternDefinition(
                pattern_id="SEC-PAT-001",
                name="Pull Payment Pattern",
                pattern_type=PatternType.SECURITY_PATTERN,
                severity=PatternSeverity.INFO,
                description="Implements pull payment pattern",
                regex_pattern=r'withdraw|transfer|sendTo.*address.*call',
                false_positive_rate=0.30,
                cwe_ids=[],
                references=["SWC-112"],
                recommendations=["Continue using pull pattern"]
            ),
            "SEC-PAT-002": PatternDefinition(
                pattern_id="SEC-PAT-002",
                name="Reentrancy Guard",
                pattern_type=PatternType.SECURITY_PATTERN,
                severity=PatternSeverity.INFO,
                description="Uses reentrancy guard",
                regex_pattern=r'nonReentrant|reentrancyGuard|ReentrancyGuard',
                false_positive_rate=0.05,
                cwe_ids=[],
                references=["SWC-107"],
                recommendations=["Continue using guard"]
            ),
            "SEC-PAT-003": PatternDefinition(
                pattern_id="SEC-PAT-003",
                name="Access Control Modifier",
                pattern_type=PatternType.SECURITY_PATTERN,
                severity=PatternSeverity.INFO,
                description="Uses custom access control modifier",
                regex_pattern=r'modifier\s+(onlyOwner|onlyAdmin|auth|requiresAuth)',
                false_positive_rate=0.10,
                cwe_ids=[],
                references=["SWC-100"],
                recommendations=["Continue using access control"]
            ),
            "SEC-OPT-001": PatternDefinition(
                pattern_id="SEC-OPT-001",
                name="Unbounded Loop",
                pattern_type=PatternType.GAS_OPTIMIZATION,
                severity=PatternSeverity.MEDIUM,
                description="Loop may iterate unbounded times",
                regex_pattern=r'for\s*\([^)]*\.length',
                false_positive_rate=0.25,
                cwe_ids=[],
                references=["Gas Optimizations"],
                recommendations=["Cache array length", "Use mappings instead"]
            ),
            "SEC-OPT-002": PatternDefinition(
                pattern_id="SEC-OPT-002",
                name="Multiple Storage Reads",
                pattern_type=PatternType.GAS_OPTIMIZATION,
                severity=PatternSeverity.LOW,
                description="Multiple storage reads in function",
                regex_pattern=r'delete\s+\w+|require\s*\([^)]*balance',
                false_positive_rate=0.40,
                cwe_ids=[],
                references=["Gas Optimizations"],
                recommendations=["Cache storage values in memory"]
            ),
            "SEC-DOC-001": PatternDefinition(
                pattern_id="SEC-DOC-001",
                name="Missing NatSpec",
                pattern_type=PatternType.DOCUMENTATION,
                severity=PatternSeverity.INFO,
                description="Function lacks NatSpec documentation",
                regex_pattern=r'function\s+\w+\s*\([^)]*\)\s*(?:public|external|internal|private)\s*\{(?!\s*/\*\*|\s*///)',
                false_positive_rate=0.35,
                cwe_ids=[],
                references=["NatSpec"],
                recommendations=["Add @notice, @param, @return"]
            ),
            "SEC-ARCH-001": PatternDefinition(
                pattern_id="SEC-ARCH-001",
                name="Proxy Pattern",
                pattern_type=PatternType.ARCHITECTURE,
                severity=PatternSeverity.INFO,
                description="Uses proxy pattern for upgradeability",
                regex_pattern=r'Proxy|Delegate|Implementation|proxyAdmin',
                false_positive_rate=0.20,
                cwe_ids=[],
                references=["EIP-1967"],
                recommendations=["Follow proxy best practices"]
            )
        }
    
    def get_pattern(self, pattern_id: str) -> Optional[PatternDefinition]:
        return self.patterns.get(pattern_id)
    
    def get_patterns_by_type(self, pattern_type: PatternType) -> List[PatternDefinition]:
        return [p for p in self.patterns.values() if p.pattern_type == pattern_type]
    
    def get_patterns_by_severity(self, severity: PatternSeverity) -> List[PatternDefinition]:
        return [p for p in self.patterns.values() if p.severity == severity]


class PatternMatcher:
    def __init__(self):
        self.registry = VulnerabilityPatternRegistry()
        self.matches: List[PatternMatch] = []
    
    def match_source(self, source_code: str, file_name: str = "") -> List[PatternMatch]:
        self.matches = []
        lines = source_code.split('\n')
        
        for pattern_id, pattern in self.registry.patterns.items():
            regex = re.compile(pattern.regex_pattern, re.MULTILINE | re.DOTALL)
            
            for line_num, line in enumerate(lines, 1):
                matches = regex.finditer(line)
                
                for match in matches:
                    match_text = match.group(0)
                    
                    context = {
                        'file': file_name,
                        'before_lines': self._get_context_lines(lines, line_num, 3, True),
                        'after_lines': self._get_context_lines(lines, line_num, 3, False)
                    }
                    
                    confidence = self._calculate_confidence(
                        pattern, 
                        match_text, 
                        line, 
                        context
                    )
                    
                    pattern_match = PatternMatch(
                        pattern=pattern,
                        line_number=line_num,
                        line_content=line.strip(),
                        match_text=match_text,
                        confidence=confidence,
                        context=context
                    )
                    
                    self.matches.append(pattern_match)
        
        return self._deduplicate_matches(self.matches)
    
    def _get_context_lines(self, lines: List[str], line_num: int, 
                     count: int, before: bool) -> str:
        if before:
            start = max(0, line_num - count - 1)
            end = line_num - 1
        else:
            start = line_num
            end = min(len(lines), line_num + count)
        
        return '\n'.join(lines[start:end])
    
    def _calculate_confidence(self, pattern: PatternDefinition, 
                       match_text: str, line: str, 
                       context: Dict[str, Any]) -> MatchConfidence:
        base_confidence = 1.0 - pattern.false_positive_rate
        
        if pattern.pattern_type == PatternType.VULNERABILITY:
            if 'require' in line or 'if' in line:
                base_confidence -= 0.3
        
        if '///' in line or '/**' in context.get('before_lines', ''):
            base_confidence -= 0.2
        
        if base_confidence >= 0.9:
            return MatchConfidence.CERTAIN
        elif base_confidence >= 0.7:
            return MatchConfidence.HIGH
        elif base_confidence >= 0.5:
            return MatchConfidence.MEDIUM
        elif base_confidence >= 0.3:
            return MatchConfidence.LOW
        else:
            return MatchConfidence.SPECULATIVE
    
    def _deduplicate_matches(self, matches: List[PatternMatch]) -> List[PatternMatch]:
        seen = set()
        unique = []
        
        for match in matches:
            key = f"{match.pattern.pattern_id}:{match.line_number}"
            
            if key not in seen:
                seen.add(key)
                unique.append(match)
        
        return unique
    
    def get_statistics(self) -> Dict[str, Any]:
        by_severity = Counter()
        by_type = Counter()
        by_pattern = Counter()
        
        for match in self.matches:
            by_severity[match.pattern.severity.name] += 1
            by_type[match.pattern.pattern_type.name] += 1
            by_pattern[match.pattern.name] += 1
        
        return {
            'total_matches': len(self.matches),
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'by_pattern': dict(by_pattern)
        }
    
    def generate_report(self) -> Dict[str, Any]:
        critical_matches = [m for m in self.matches if m.pattern.severity == PatternSeverity.CRITICAL]
        high_matches = [m for m in self.matches if m.pattern.severity == PatternSeverity.HIGH]
        
        return {
            'summary': self.get_statistics(),
            'critical_count': len(critical_matches),
            'high_count': len(high_matches),
            'matches': [m.to_dict() for m in self.matches],
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        recommendations = set()
        
        for match in self.matches:
            if match.pattern.severity in [PatternSeverity.CRITICAL, PatternSeverity.HIGH]:
                recommendations.update(match.pattern.recommendations)
        
        return list(recommendations)
    
    def export_json(self, filepath: str):
        report = self.generate_report()
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Pattern matching report saved to {filepath}")


class ASTRewriter:
    def __init__(self):
        self.rewrites: List[Dict[str, Any]] = []
    
    def suggest_fixes(self, matches: List[PatternMatch]) -> Dict[str, Any]:
        fixes = []
        
        for match in matches:
            if match.pattern.pattern_id == "SEC-VULN-001":
                fixes.append({
                    'line': match.line_number,
                    'type': 'add_guard',
                    'description': 'Add nonReentrant modifier'
                })
            elif match.pattern.pattern_id == "SEC-VULN-004":
                fixes.append({
                    'line': match.line_number,
                    'type': 'add_safemath',
                    'description': 'Use SafeMath for arithmetic'
                })
        
        return {'suggested_fixes': fixes}


def match_patterns(source_code: str, file_name: str = "") -> Dict[str, Any]:
    matcher = PatternMatcher()
    matcher.match_source(source_code, file_name)
    return matcher.generate_report()


if __name__ == '__main__':
    sample = """
pragma solidity ^0.8.0;

contract VulnerableBank {
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
        require(msg.sender == owner);
        selfdestruct(msg.sender);
    }
}
    """
    
    result = match_patterns(sample, "VulnerableBank.sol")
    print(json.dumps(result['summary'], indent=2))
    print(f"\nCritical: {result['critical_count']}")
    print(f"High: {result['high_count']}")