"""
Reentrancy Security Rules

This module provides comprehensive reentrancy vulnerability detection rules
for Solidity smart contracts in the Solidify framework.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReentrancyType(Enum):
    CLASSIC = "classic"
    CROSS_FUNCTION = "cross_function"
    READ_MODIFY_WRITE = "read_modify_write"
    DELEGATE_BASED = "delegate_based"
    ETH_FLOOD = "eth_flood"


class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class ReentrancyRule:
    rule_id: str
    name: str
    reentrancy_type: ReentrancyType
    severity: SeverityLevel
    pattern: str
    description: str
    impact: str
    cwe_id: str
    swc_id: str
    remediation: str
    code_examples: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.15
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'reentrancy_type': self.reentrancy_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'impact': self.impact,
            'cwe_id': self.cwe_id,
            'swc_id': self.swc_id,
            'remediation': self.remediation
        }


class ReentrancyDetectionEngine:
    def __init__(self):
        self.rules: Dict[str, ReentrancyRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self):
        self.rules = {
            'REENT001': ReentrancyRule(
                rule_id='REENT001',
                name='Classic Reentrancy - External Call Before State Change',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.CRITICAL,
                pattern=r'(call|send|transfer)\s*\{[^}]*\}\s*(?!.*require|.*if|.*_update|.*balance)',
                description='External call executed before state variable update',
                impact='Attacker can re-enter and drain funds',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Use checks-effects-interactions pattern or ReentrancyGuard',
                code_examples=[
                    'msg.sender.call{value: amount}(""); balances[msg.sender] = 0;'
                ],
                false_positive_rate=0.15
            ),
            'REENT002': ReentrancyRule(
                rule_id='REENT002',
                name='Cross-Function Reentrancy',
                reentrancy_type=ReentrancyType.CROSS_FUNCTION,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+\w+\s*\([^)]*\)\s*\{[^}]*call\{[^}]*\}[^}]*function\s+\w+\s*\([^)]*\)\s*\{[^}]*balanceOf\s*\[',
                description='Reentrancy possible across different functions',
                impact='State inconsistency between functions exploited',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Use ReentrancyGuard modifier on all state-changing functions',
                code_examples=[],
                false_positive_rate=0.20
            ),
            'REENT003': ReentrancyRule(
                rule_id='REENT003',
                name='Read-Modify-Write Reentrancy',
                reentrancy_type=ReentrancyType.READ_MODIFY_WRITE,
                severity=SeverityLevel.HIGH,
                pattern=r'balanceOf\s*\[\s*\w+\s*\]\s*[-+]\s*=\s*\w+\s*;.*call\s*\{',
                description='Balance read, external call, then write not atomic',
                impact='Attacker can manipulate balance during reentrancy',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Complete state updates before external calls',
                code_examples=[],
                false_positive_rate=0.25
            ),
            'REENT004': ReentrancyRule(
                rule_id='REENT004',
                name='Delegatecall-Based Reentrancy',
                reentrancy_type=ReentrancyType.DELEGATE_BASED,
                severity=SeverityLevel.CRITICAL,
                pattern=r'delegatecall\s*\([^)]*\)\s*(?!.*require|.*if)',
                description='Delegatecall to untrusted contract',
                impact='Storage manipulation and complete protocol compromise',
                cwe_id='CWE-829',
                swc_id='SWC-112',
                remediation='Validate delegatecall targets, use staticcall when possible',
                code_examples=[],
                false_positive_rate=0.10
            ),
            'REENT005': ReentrancyRule(
                rule_id='REENT005',
                name='Multiple External Calls Without Guard',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.CRITICAL,
                pattern=r'for\s*\([^)]*\)\s*\{[^}]*call\s*\{[^}]*\}[^}]*\}',
                description='Loop with external calls without reentrancy protection',
                impact='Each iteration can be re-entered',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Use ReentrancyGuard or process in batches',
                code_examples=[],
                false_positive_rate=0.20
            ),
            'REENT006': ReentrancyRule(
                rule_id='REENT006',
                name='Call Without Return Value Check',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.HIGH,
                pattern=r'\.(call|send)\s*\{[^}]*\}\s*;(?!\s*require|\s*if\s*\()',
                description='Low-level call without success verification',
                impact='Silent failures can be exploited',
                cwe_id='CWE-252',
                swc_id='SWC-104',
                remediation='Always check return value of low-level calls',
                code_examples=[],
                false_positive_rate=0.15
            ),
            'REENT007': ReentrancyRule(
                rule_id='REENT007',
                name=' ERC-677 Callback Reentrancy',
                reentrancy_type=ReentrancyType.CROSS_FUNCTION,
                severity=SeverityLevel.CRITICAL,
                pattern=r'tokenFallback\s*\(.*\)\s*(?!.*nonReentrant|modifier)',
                description='ERC-677 callback without reentrancy protection',
                impact='Tokens with callbacks can trigger reentrancy',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Implement ReentrancyGuard on callback functions',
                code_examples=[],
                false_positive_rate=0.18
            ),
            'REENT008': ReentrancyRule(
                rule_id='REENT008',
                name='Pull Payment Without Reentrancy',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.MEDIUM,
                pattern=r'function\s+withdraw\s*\([^)]*\)\s*public\s*(?!.*nonReentrant)',
                description='Withdraw function lacks reentrancy protection',
                impact='Potential reentrancy in withdrawals',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Use PullPayment pattern with ReentrancyGuard',
                code_examples=[],
                false_positive_rate=0.25
            ),
            'REENT009': ReentrancyRule(
                rule_id='REENT009',
                name='Unprotected Selfdestruct',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.CRITICAL,
                pattern=r'selfdestruct\s*\(\s*\w+\s*\)\s*;(?!\s*require|\s*if)',
                description='Selfdestruct without access control',
                impact='Anyone can destroy the contract',
                cwe_id='CWE-506',
                swc_id='SWC-106',
                remediation='Add onlyOwner modifier to selfdestruct',
                code_examples=[],
                false_positive_rate=0.05
            ),
            'REENT010': ReentrancyRule(
                rule_id='REENT010',
                name='Return Value Manipulation',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.HIGH,
                pattern=r'\.call\s*\{.*value:\s*\w+\s*\}\s*\(\s*""\s*\)\s*;',
                description='Call with empty data return value not checked',
                impact='Silent failures can lead to inconsistent state',
                cwe_id='CWE-252',
                swc_id='SWC-104',
                remediation='Verify return values or use SafeERC20',
                code_examples=[],
                false_positive_rate=0.20
            ),
            'REENT011': ReentrancyRule(
                rule_id='REENT011',
                name='Vulnerable Callback Pattern',
                reentrancy_type=ReentrancyType.CROSS_FUNCTION,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+onReceive\w*\s*\([^)]*\)\s*external\s*(?!.*nonReentrant)',
                description='Callback function without reentrancy protection',
                impact='Attacker can re-enter through callback',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Add ReentrancyGuard to callback functions',
                code_examples=[],
                false_positive_rate=0.15
            ),
            'REENT012': ReentrancyRule(
                rule_id='REENT012',
                name='Unchecked External Call in Loop',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.HIGH,
                pattern=r'for\s*\([^)]*\.length[^)]*\)\s*\{[^}]*\.call\s*\{[^}]*\}\s*;',
                description='External calls in loop without guard',
                impact='State changes between iterations can be exploited',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Use ReentrancyGuard or accumulate first',
                code_examples=[],
                false_positive_rate=0.22
            ),
            'REENT013': ReentrancyRule(
                rule_id='REENT013',
                name='Cross-Contract Reentrancy',
                reentrancy_type=ReentrancyType.CROSS_FUNCTION,
                severity=SeverityLevel.CRITICAL,
                pattern=r'\.call\s*\{[^}]*\}\s*\(\s*\w+\s*,\s*""\s*,\s*""\s*\)\s*;.*balanceOf',
                description='External call to untrusted contract with state read after',
                impact='Attacker contract can callback into vulnerable contract',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Follow CEI pattern, update state before external call',
                code_examples=[],
                false_positive_rate=0.18
            ),
            'REENT014': ReentrancyRule(
                rule_id='REENT014',
                name='Reentrancy Through Mock Contract',
                reentrancy_type=ReentrancyType.CROSS_FUNCTION,
                severity=SeverityLevel.CRITICAL,
                pattern=r'interface\s+\w+\s*\{[^}]*function\s+\w+\s*\([^)]*\)\s*external',
                description='Interface with external function called before state update',
                impact='Mock contracts can exploit reentrancy',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Validate called contracts, use CEI pattern',
                code_examples=[],
                false_positive_rate=0.25
            ),
            'REENT015': ReentrancyRule(
                rule_id='REENT015',
                name='Missing ReentrancyGuard on Withdrawal',
                reentrancy_type=ReentrancyType.CLASSIC,
                severity=SeverityLevel.HIGH,
                pattern=r'function\s+(withdraw|claim|harvest)\s*\([^)]*\)\s*public\s*(?!.*nonReentrant)',
                description='Critical withdrawal function without ReentrancyGuard',
                impact='Reentrancy attack possible',
                cwe_id='CWE-362',
                swc_id='SWC-107',
                remediation='Add nonReentrant modifier to withdraw functions',
                code_examples=[],
                false_positive_rate=0.20
            )
        }
    
    def get_rule(self, rule_id: str) -> Optional[ReentrancyRule]:
        return self.rules.get(rule_id)
    
    def get_rules_by_severity(self, severity: SeverityLevel) -> List[ReentrancyRule]:
        return [r for r in self.rules.values() if r.severity == severity]
    
    def get_rules_by_type(self, reent_type: ReentrancyType) -> List[ReentrancyRule]:
        return [r for r in self.rules.values() if r.reentrancy_type == reent_type]
    
    def detect_reentrancy(self, source_code: str) -> List[Dict[str, Any]]:
        findings = []
        
        for rule in self.rules.values():
            try:
                pattern = re.compile(rule.pattern, re.MULTILINE | re.DOTALL)
            except re.error:
                continue
            
            matches = list(pattern.finditer(source_code))
            
            for match in matches:
                line_number = source_code[:match.start()].count('\n') + 1
                line_content = source_code.split('\n')[line_number - 1].strip()
                
                finding = {
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'severity': rule.severity.name,
                    'type': rule.reentrancy_type.value,
                    'line_number': line_number,
                    'code_snippet': line_content[:100],
                    'description': rule.description,
                    'impact': rule.impact,
                    'cwe_id': rule.cwe_id,
                    'swc_id': rule.swc_id,
                    'remediation': rule.remediation
                }
                
                findings.append(finding)
        
        return findings
    
    def scan_contract(self, source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
        findings = self.detect_reentrancy(source_code)
        
        severity_counts = Counter()
        type_counts = Counter()
        
        for f in findings:
            severity_counts[f['severity']] += 1
            type_counts[f['type']] += 1
        
        return {
            'contract_name': contract_name,
            'total_findings': len(findings),
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0),
            'medium_count': severity_counts.get('MEDIUM', 0),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'findings': findings,
            'recommendations': self._generate_recommendations(findings)
        }
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        recommendations = []
        
        if any(f['severity'] == 'CRITICAL' for f in findings):
            recommendations.append('URGENT: Implement ReentrancyGuard on all state-changing functions')
            recommendations.append('Apply checks-effects-interactions pattern')
        
        if any(f['type'] == 'cross_function' for f in findings):
            recommendations.append('Add ReentrancyGuard to callback functions')
        
        recommendations.append('Use PullPayment pattern for withdrawals')
        recommendations.append('Verify return values of all low-level calls')
        
        return list(set(recommendations))


class ReentrancyComplianceChecker:
    def __init__(self):
        self.engine = ReentrancyDetectionEngine()
    
    def check_compliance(self, source_code: str) -> Dict[str, Any]:
        findings = self.engine.detect_reentrancy(source_code)
        
        critical = [f for f in findings if f['severity'] == 'CRITICAL']
        
        compliant = len(critical) == 0
        
        return {
            'compliant': compliant,
            'total_issues': len(findings),
            'critical_count': len(critical),
            'requires_immediate_action': not compliant
        }


def check_reentrancy_rules(source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
    engine = ReentrancyDetectionEngine()
    return engine.scan_contract(source_code, contract_name)


if __name__ == '__main__':
    sample = """
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}
    """
    
    result = check_reentrancy_rules(sample, "VulnerableBank")
    print(json.dumps(result, indent=2))