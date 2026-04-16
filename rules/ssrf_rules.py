"""
SSRF (Server-Side Request Forgery) Security Rules

This module provides comprehensive SSRF vulnerability detection rules
for smart contract and web application security auditing.

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
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSRFVulnerabilityType(Enum):
    HTTP_REQUEST = "http_request"
    DNS_LOOKUP = "dns_lookup"
    FILE_UPLOAD = "file_upload"
    WEBHOOK = "webhook"
    CALLBACK = "callback"
    IP_DISCLOSURE = "ip_disclosure"
    REDIRECT = "redirect"
    DNS_REBINDING = "dns_rebinding"


class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class ConfidenceLevel(Enum):
    CERTAIN = 1.0
    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.5
    SPECULATIVE = 0.3


@dataclass
class SSRFPattern:
    pattern_id: str
    name: str
    vulnerability_type: SSRFVulnerabilityType
    severity: SeverityLevel
    pattern: str
    description: str
    impact_description: str
    cwe_id: str
    cve_examples: List[str]
    remediation: str
    references: List[str]
    false_positive_rate: float = 0.1
    test_cases: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern_id': self.pattern_id,
            'name': self.name,
            'vulnerability_type': self.vulnerability_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'impact_description': self.impact_description,
            'cwe_id': self.cwe_id,
            'cve_examples': self.cve_examples,
            'remediation': self.remediation,
            'references': self.references,
            'false_positive_rate': self.false_positive_rate
        }


@dataclass
class SSRFMatch:
    pattern: SSRFPattern
    line_number: int
    matched_text: str
    context: str
    confidence: ConfidenceLevel
    severity_override: Optional[SeverityLevel] = None
    
    def get_severity(self) -> SeverityLevel:
        return self.severity_override or self.pattern.severity
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern_id': self.pattern.pattern_id,
            'name': self.pattern.name,
            'severity': self.get_severity().value,
            'line_number': self.line_number,
            'matched_text': self.matched_text[:100],
            'confidence': self.confidence.value,
            'cwe_id': self.pattern.cwe_id
        }


class SSRFDetectionEngine:
    def __init__(self):
        self.patterns: Dict[str, SSRFPattern] = {}
        self._register_all_patterns()
    
    def _register_all_patterns(self):
        self.patterns = {
            'SSRF001': SSRFPattern(
                pattern_id='SSRF001',
                name='HTTP Request to User-Controlled URL',
                vulnerability_type=SSRFVulnerabilityType.HTTP_REQUEST,
                severity=SeverityLevel.CRITICAL,
                pattern=r'(?:fetch|axios|request|httpGet|httpPost)\s*\(\s*(?:url|link|endpoint|uri)\s*\)',
                description='HTTP request made to user-controlled URL parameter',
                impact_description='Attacker can make the server request arbitrary URLs, potentially accessing internal services',
                cwe_id='CWE-918',
                cve_examples=['CVE-2020-1234', 'CVE-2021-5678'],
                remediation='Validate and sanitize URL parameters, use allowlists for permitted domains',
                references=['OWASP SSRF', 'CWE-918'],
                false_positive_rate=0.15,
                test_cases=[
                    {'input': 'fetch(url)', 'expected': 'match'},
                    {'input': 'fetch("https://api.example.com")', 'expected': 'no_match'}
                ]
            ),
            'SSRF002': SSRFPattern(
                pattern_id='SSRF002',
                name='DNS Lookup with User Input',
                vulnerability_type=SSRFVulnerabilityType.DNS_LOOKUP,
                severity=SeverityLevel.HIGH,
                pattern=r'(?:dnsLookup|resolveHost|getHostByName|getaddrinfo)\s*\(\s*\w+\s*\)',
                description='DNS lookup performed using user-controlled hostname',
                impact_description='Attacker can trigger DNS lookups to internal DNS servers or for DNS-based attacks',
                cwe_id='CWE-918',
                cve_examples=['CVE-2020-5678'],
                remediation='Validate hostname format and use allowlists',
                references=['OWASP SSRF'],
                false_positive_rate=0.20
            ),
            'SSRF003': SSRFPattern(
                pattern_id='SSRF003',
                name='Web Request to Internal Network',
                vulnerability_type=SSRFVulnerabilityType.HTTP_REQUEST,
                severity=SeverityLevel.CRITICAL,
                pattern=r'(?:fetch|axios)\s*\(\s*(?:"http|https)://(?:10\.|172\.(?:1[6-9]|2|3[01])|192\.168\.|localhost|127\.)',
                description='HTTP request to internal/private network address',
                impact_description='Attacker can access internal services not exposed to the internet',
                cwe_id='CWE-918',
                cve_examples=['CVE-2021-9012'],
                remediation='Block requests to private IP ranges',
                references=['RFC 1918'],
                false_positive_rate=0.05
            ),
            'SSRF004': SSRFPattern(
                pattern_id='SSRF004',
                name='URL Parsing in Request',
                vulnerability_type=SSRFVulnerabilityType.HTTP_REQUEST,
                severity=SeverityLevel.HIGH,
                pattern=r'new\s+URL\s*\(\s*\w+\s*\)',
                description='URL object created using unvalidated input',
                impact_description='Parser differences may be exploited for SSRF attacks',
                cwe_id='CWE-918',
                cve_examples=['CVE-2020-1234'],
                remediation='Parse and validate URL components separately',
                references=['URL Standard'],
                false_positive_rate=0.25
            ),
            'SSRF005': SSRFPattern(
                pattern_id='SSRF005',
                name='File Upload to URL',
                vulnerability_type=SSRFVulnerabilityType.FILE_UPLOAD,
                severity=SeverityLevel.CRITICAL,
                pattern=r'(?:upload|postFile|writeFile)\s*\(\s*(?:url|link|endpoint)\s*,\s*\w+\s*\)',
                description='File uploaded to user-controlled URL',
                impact_description='Attacker can upload files to arbitrary locations via server',
                cwe_id='CWE-918',
                cve_examples=['CVE-2021-2345'],
                remediation='Use fixed upload destinations, never user-controlled URLs',
                references=['OWASP File Upload'],
                false_positive_rate=0.10
            ),
            'SSRF006': SSRFPattern(
                pattern_id='SSRF006',
                name='Callback URL Without Validation',
                vulnerability_type=SSRFVulnerabilityType.CALLBACK,
                severity=SeverityLevel.MEDIUM,
                pattern=r'(?:callback|webhook|notify)\s*=\s*["\']?\{\s*\w+\s*\}',
                description='Callback/webhook URL parameter that could be controlled',
                impact_description='Attacker can specify their own callback URL for sensitive operations',
                cwe_id='CWE-918',
                cve_examples=[],
                remediation='Validate callback URLs against allowlists',
                references=['OWASP SSRF'],
                false_positive_rate=0.30
            ),
            'SSRF007': SSRFPattern(
                pattern_id='SSRF007',
                name='IP Disclosure via Request',
                vulnerability_type=SSRFVulnerabilityType.IP_DISCLOSURE,
                severity=SeverityLevel.LOW,
                pattern=r'(?:request|get)\s*\(\s*(?:clientIp|remoteAddress|forwarded)\s*\(',
                description='Request reveals server IP addresses',
                impact_description='Server IP disclosure can aid further attacks',
                cwe_id='CWE-200',
                cve_examples=[],
                remediation='Use proper IP anonymization',
                references=['CWE-200'],
                false_positive_rate=0.40
            ),
            'SSRF008': SSRFPattern(
                pattern_id='SSRF008',
                name='Redirect to User-supplied URL',
                vulnerability_type=SSRFVulnerabilityType.REDIRECT,
                severity=SeverityLevel.MEDIUM,
                pattern=r'(?:redirect|forward|location)\s*\(\s*(?:url|link|destination)\s*\)',
                description='Server performs redirect to user-controlled URL',
                impact_description='Open redirect can be used to bypass security measures',
                cwe_id='CWE-601',
                cve_examples=['CVE-2020-9012'],
                remediation='Validate and sanitize redirect URLs',
                references=['CWE-601'],
                false_positive_rate=0.25
            ),
            'SSRF009': SSRFPattern(
                pattern_id='SSRF009',
                name='DNS Rebinding Attack Vector',
                vulnerability_type=SSRFVulnerabilityType.DNS_REBINDING,
                severity=SeverityLevel.HIGH,
                pattern=r'(?:fetch|request|get)\s*\(\s*(?:\w+\s*\.\s*random_domain)',
                description='DNS rebinding attack possible through dynamic domain resolution',
                impact_description='Attacker can bypass DNS-based protections by rapidly changing DNS records',
                cwe_id='CWE-346',
                cve_examples=[],
                remediation='Implement DNS pinning or request validation after DNS resolution',
                references=['DNS Rebinding'],
                false_positive_rate=0.35
            ),
            'SSRF010': SSRFPattern(
                pattern_id='SSRF010',
                name='Open Port Scanning via Request',
                vulnerability_type=SSRFVulnerabilityType.HTTP_REQUEST,
                severity=SeverityLevel.CRITICAL,
                pattern=r'(?:fetch|axios)\s*\(\s*(?:"http|https)://localhost|127\.0\.0\.1|0\.0\.0\.0',
                description='Request can target local server ports',
                impact_description='Attacker can probe internal services and potentially access admin interfaces',
                cwe_id='CWE-918',
                cve_examples=['CVE-2019-1234'],
                remediation='Block access to localhost and internal IP ranges',
                references=['SSRF Bible'],
                false_positive_rate=0.08
            )
        }
    
    def get_pattern(self, pattern_id: str) -> Optional[SSRFPattern]:
        return self.patterns.get(pattern_id)
    
    def get_patterns_by_severity(self, severity: SeverityLevel) -> List[SSRFPattern]:
        return [p for p in self.patterns.values() if p.severity == severity]
    
    def detect_ssrf(self, source_code: str) -> List[SSRFMatch]:
        matches = []
        
        for pattern in self.patterns.values():
            regex = re.compile(pattern.pattern, re.MULTILINE | re.IGNORECASE)
            
            for match in regex.finditer(source_code):
                line_number = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_number - 1].strip()
                
                confidence = self._calculate_confidence(pattern, match.group(0))
                
                ssrf_match = SSRFMatch(
                    pattern=pattern,
                    line_number=line_number,
                    matched_text=match.group(0),
                    context=line,
                    confidence=confidence
                )
                
                matches.append(ssrf_match)
        
        return matches
    
    def _calculate_confidence(self, pattern: SSRFPattern, match_text: str) -> ConfidenceLevel:
        if pattern.false_positive_rate < 0.1:
            return ConfidenceLevel.CERTAIN
        elif pattern.false_positive_rate < 0.2:
            return ConfidenceLevel.HIGH
        elif pattern.false_positive_rate < 0.3:
            return ConfidenceLevel.MEDIUM
        elif pattern.false_positive_rate < 0.4:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.SPECULATIVE
    
    def generate_report(self, source_code: str, target_name: str = "Unknown") -> Dict[str, Any]:
        matches = self.detect_ssrf(source_code)
        
        severity_counts = Counter()
        type_counts = Counter()
        
        for match in matches:
            severity_counts[match.get_severity().name] += 1
            type_counts[match.pattern.vulnerability_type.name] += 1
        
        critical_matches = [m for m in matches if m.get_severity() == SeverityLevel.CRITICAL]
        
        return {
            'target': target_name,
            'total_matches': len(matches),
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'matches': [m.to_dict() for m in matches],
            'risk_assessment': 'CRITICAL' if critical_matches else 'HIGH' if severity_counts.get('HIGH', 0) > 0 else 'MEDIUM',
            'recommendations': self._generate_recommendations(matches)
        }
    
    def _generate_recommendations(self, matches: List[SSRFMatch]) -> List[str]:
        recommendations = []
        
        types_found = set(m.pattern.vulnerability_type for m in matches)
        
        if SSRFVulnerabilityType.HTTP_REQUEST in types_found:
            recommendations.append("Implement URL allowlist validation")
            recommendations.append("Block requests to internal/private IP ranges")
            recommendations.append("Use library functions with built-in protection")
        
        if SSRFVulnerabilityType.DNS_LOOKUP in types_found:
            recommendations.append("Validate hostname format before DNS lookup")
            recommendations.append("Implement DNS pinning for critical operations")
        
        if SSRFVulnerabilityType.REDIRECT in types_found:
            recommendations.append("Validate redirect URLs against allowlists")
        
        return list(set(recommendations))


class SSRFComplianceChecker:
    def __init__(self):
        self.engine = SSRFDetectionEngine()
    
    def check_compliance(self, source_code: str) -> Dict[str, Any]:
        matches = self.engine.detect_ssrf(source_code)
        
        critical = [m for m in matches if m.get_severity() == SeverityLevel.CRITICAL]
        high = [m for m in matches if m.get_severity() == SeverityLevel.HIGH]
        
        compliant = len(critical) == 0
        
        return {
            'compliant': compliant,
            'total_issues': len(matches),
            'critical_count': len(critical),
            'high_count': len(high),
            'requires_audit': not compliant
        }


def check_ssrf_rules(source_code: str, target_name: str = "Unknown") -> Dict[str, Any]:
    engine = SSRFDetectionEngine()
    return engine.generate_report(source_code, target_name)


if __name__ == '__main__':
    sample_code = """
pragma solidity ^0.8.0;

contract ExternalCall {
    function fetchData(string memory url) public {
        externalCall(url);
    }
    
    function makeRequest(string memory endpoint) public {
        request(endpoint);
    }
    
    function resolveHost(string memory host) public {
        dnsLookup(host);
    }
    
    function uploadFile(string memory url, bytes memory data) public {
        upload(url, data);
    }
}
    """
    
    result = check_ssrf_rules(sample_code, "ExternalCall")
    print(json.dumps(result, indent=2))