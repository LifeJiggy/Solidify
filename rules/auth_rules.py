"""
Authentication and Authorization Security Rules

This module provides comprehensive authentication and authorization security rules
for smart contract vulnerability detection in the Solidify framework.

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


class AuthRuleType(Enum):
    ACCESS_CONTROL = "access_control"
    OWNERSHIP = "ownership"
    ROLE_BASED = "role_based"
    MULTISIG = "multisig"
    TIMELOCK = "timelock"
    PROXY = "proxy"
    PAUSABLE = "pausable"


class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class AuthRule:
    rule_id: str
    name: str
    rule_type: AuthRuleType
    severity: SeverityLevel
    pattern: str
    description: str
    cwe_ids: List[str]
    recommendation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'rule_type': self.rule_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'cwe_ids': self.cwe_ids,
            'recommendation': self.recommendation
        }


class AuthRuleEngine:
    def __init__(self):
        self.rules: Dict[str, AuthRule] = {}
        self._register_all_rules()
    
    def _register_all_rules(self):
        self.rules = {
            'AUTH001': AuthRule(
                rule_id='AUTH001',
                name='Missing Access Control',
                rule_type=AuthRuleType.ACCESS_CONTROL,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+(withdraw|mint|burn|pause|upgrade)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|modifier|auth))',
                description='Critical function lacks access control modifier',
                cwe_ids=['CWE-284', 'CWE-862'],
                recommendation='Add onlyOwner or role-based access control modifier'
            ),
            'AUTH002': AuthRule(
                rule_id='AUTH002',
                name='Missing Ownership Check',
                rule_type=AuthRuleType.OWNERSHIP,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+\w+\s*\([^)]*\)\s+public\s*(?:returns)?\s*(?:\([^)]*\))?\s*\{(?!\s*require\s*\(\s*msg\.sender\s*==)',
                description='Function without ownership verification',
                cwe_ids=['CWE-284'],
                recommendation='Add msg.sender == owner check'
            ),
            'AUTH003': AuthRule(
                rule_id='AUTH003',
                name='Weak Access Control',
                rule_type=AuthRuleType.ACCESS_CONTROL,
                severity=SeverityLevel.HIGH,
                pattern=r'function\s+.*set.*Owner\s*\([^)]*\)\s+public',
                description='SetOwner function publicly accessible',
                cwe_ids=['CWE-284'],
                recommendation='Restrict to current owner only'
            ),
            'AUTH004': AuthRule(
                rule_id='AUTH004',
                name='Missing Role Verification',
                rule_type=AuthRuleType.ROLE_BASED,
                severity=SeverityLevel.HIGH,
                pattern=r'function\s+\w+\s*\([^)]*\)\s+public(?!\s*(?:hasRole|onlyRole|requiresAuth))',
                description='Function missing role verification',
                cwe_ids=['CWE-284', 'CWE-862'],
                recommendation='Add role-based access control'
            ),
            'AUTH005': AuthRule(
                rule_id='AUTH005',
                name='Anyone Can Mint',
                rule_type=AuthRuleType.ROLE_BASED,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+mint\s*\([^)]*\)\s*public(?!\s*(?:onlyMinter|hasRole|modifier))',
                description='Minting function publicly accessible',
                cwe_ids=['CWE-284'],
                recommendation='Add minting role restriction'
            ),
            'AUTH006': AuthRule(
                rule_id='AUTH006',
                name='Anyone Can Pause',
                rule_type=AuthRuleType.PAUSABLE,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+pause\s*\([^)]*\)\s*public',
                description='Pause function without restriction',
                cwe_ids=['CWE-284'],
                recommendation='Add pauser role or onlyOwner'
            ),
            'AUTH007': AuthRule(
                rule_id='AUTH007',
                name='Unverified Proxy Admin',
                rule_type=AuthRuleType.PROXY,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+.*upgradeTo\s*\([^)]*\)\s*public',
                description='Proxy upgrade publicly accessible',
                cwe_ids=['CWE-284', 'CWE-494'],
                recommendation='Restrict to proxy admin only'
            ),
            'AUTH008': AuthRule(
                rule_id='AUTH008',
                name='Missing Timelock',
                rule_type=AuthRuleType.TIMELOCK,
                severity=SeverityLevel.HIGH,
                pattern=r'function\s+.*execute\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:after|delay|timelock))',
                description='Execution without timelock delay',
                cwe_ids=['CWE-293'],
                recommendation='Add timelock for critical functions'
            ),
            'AUTH009': AuthRule(
                rule_id='AUTH009',
                name='Multisig Threshold Too Low',
                rule_type=AuthRuleType.MULTISIG,
                severity=SeverityLevel.MEDIUM,
                pattern=r'uint256\s+public\s+threshold\s*=\s*1',
                description='Multisig threshold set to 1',
                cwe_ids=['CWE-284'],
                recommendation='Increase threshold to at least 2'
            ),
            'AUTH010': AuthRule(
                rule_id='AUTH010',
                name='Missing Access Control in Init',
                rule_type=AuthRuleType.OWNERSHIP,
                severity=SeverityLevel.CRITICAL,
                pattern=r'function\s+initialize\s*\([^)]*\)\s*public(?!\s*onlyOwner)',
                description='Initializer without owner check',
                cwe_ids=['CWE-284', 'CWE-494'],
                recommendation='Add onlyOwner to initializer'
            )
        }
    
    def get_rule(self, rule_id: str) -> Optional[AuthRule]:
        return self.rules.get(rule_id)
    
    def get_rules_by_severity(self, severity: SeverityLevel) -> List[AuthRule]:
        return [r for r in self.rules.values() if r.severity == severity]
    
    def get_rules_by_type(self, rule_type: AuthRuleType) -> List[AuthRule]:
        return [r for r in self.rules.values() if r.rule_type == rule_type]
    
    def detect_violations(self, source_code: str) -> List[Dict[str, Any]]:
        violations = []
        
        for rule in self.rules.values():
            matches = list(re.finditer(rule.pattern, source_code, re.MULTILINE | re.DOTALL))
            
            for match in matches:
                line_number = source_code[:match.start()].count('\n') + 1
                
                violations.append({
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'severity': rule.severity.value,
                    'line_number': line_number,
                    'description': rule.description,
                    'cwe_ids': rule.cwe_ids,
                    'recommendation': rule.recommendation
                })
        
        return violations
    
    def scan_and_report(self, source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
        violations = self.detect_violations(source_code)
        
        severity_counts = Counter()
        type_counts = Counter()
        
        for v in violations:
            severity_counts[v['severity']] += 1
            type_counts[v.get('rule_type', 'unknown')] += 1
        
        return {
            'contract_name': contract_name,
            'total_violations': len(violations),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'violations': violations,
            'recommendations': [v['recommendation'] for v in violations]
        }
    
    def export_rules(self, filepath: str) -> bool:
        try:
            rules_data = {rule_id: rule.to_dict() for rule_id, rule in self.rules.items()}
            
            with open(filepath, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            logger.info(f"Rules exported to: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


class AuthComplianceChecker:
    def __init__(self):
        self.engine = AuthRuleEngine()
    
    def check_compliance(self, source_code: str) -> Dict[str, Any]:
        violations = self.engine.detect_violations(source_code)
        
        critical = [v for v in violations if v['severity'] == SeverityLevel.CRITICAL.value]
        high = [v for v in violations if v['severity'] == SeverityLevel.HIGH.value]
        
        compliant = len(critical) == 0 and len(high) == 0
        
        return {
            'compliant': compliant,
            'total_issues': len(violations),
            'critical_count': len(critical),
            'high_count': len(high),
            'requires_audit': not compliant
        }


def check_auth_rules(source_code: str, contract_name: str = "Unknown") -> Dict[str, Any]:
    engine = AuthRuleEngine()
    return engine.scan_and_report(source_code, contract_name)


if __name__ == '__main__':
    sample_code = """
pragma solidity ^0.8.0;

contract TestToken {
    address public owner;
    
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
    
    function withdraw() public {
        msg.sender.transfer(address(this).balance);
    }
    
    function pause() public {
        _pause();
    }
}
    """
    
    result = check_auth_rules(sample_code, "TestToken")
    print(json.dumps(result, indent=2))