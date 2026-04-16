"""
IDOR Security Rules

This module provides comprehensive Insecure Direct Object Reference (IDOR)
security rules for vulnerability detection.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IDORRuleType(Enum):
    USER_ID_ACCESS = "user_id_access"
    PARAMETER_TAMPERING = "parameter_tampering"
    INSECURE_REFERENCE = "insecure_reference"
    MISSING_AUTHORIZATION = "missing_authorization"


@dataclass
class IDORRule:
    rule_id: str
    name: str
    rule_type: IDORRuleType
    severity: str
    pattern: str
    description: str
    cwe_id: str
    recommendation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


class IDORRuleEngine:
    def __init__(self):
        self.rules = self._register_rules()
    
    def _register_rules(self) -> Dict[str, IDORRule]:
        return {
            'IDOR001': IDORRule(
                rule_id='IDOR001',
                name='User ID in URL Param',
                rule_type=IDORRuleType.USER_ID_ACCESS,
                severity='high',
                pattern=r'/users/\{userId\}|/api/user/\d+',
                description='User ID exposed in URL parameter',
                cwe_id='CWE-639',
                recommendation='Use authenticated user session context'
            ),
            'IDOR002': IDORRule(
                rule_id='IDOR002',
                name='Object ID Enumeration',
                rule_type=IDORRuleType.PARAMETER_TAMPERING,
                severity='high',
                pattern=r'id=\d+|objectId=\d+|resource_id=\d+',
                description='Sequential object IDs allow enumeration',
                cwe_id='CWE-639',
                recommendation='Use non-sequential identifiers'
            ),
            'IDOR003': IDORRule(
                rule_id='IDOR003',
                name='Missing Owner Check',
                rule_type=IDORRuleType.MISSING_AUTHORIZATION,
                severity='critical',
                pattern=r'function\s+getUser\w*\s*\(\s*uint256\s+\w+\s*\)',
                description='Function retrieves user data without ownership verification',
                cwe_id='CWE-639',
                recommendation='Verify resource ownership before access'
            ),
            'IDOR004': IDORRule(
                rule_id='IDOR004',
                name='Unverified File Access',
                rule_type=IDORRuleType.USER_ID_ACCESS,
                severity='high',
                pattern=r'/files/\{fileId\}|download\?file=\w+',
                description='File access without authorization check',
                cwe_id='CWE-639',
                recommendation='Verify file ownership before download'
            )
        }
    
    def detect(self, source_code: str) -> List[Dict[str, Any]]:
        results = []
        for rule in self.rules.values():
            if re.search(rule.pattern, source_code):
                results.append(rule.to_dict())
        return results


def check_idor_rules(source_code: str) -> Dict[str, Any]:
    engine = IDORRuleEngine()
    issues = engine.detect(source_code)
    return {'total': len(issues), 'issues': issues}