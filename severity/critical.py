"""
Critical Severity Module for Smart Contract Security Analysis

This module provides comprehensive critical severity vulnerability detection,
classification, and risk assessment for Ethereum smart contracts. It implements
the highest severity tier in the Solidify security auditing framework.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CriticalVulnerabilityType(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC_OVERFLOW = "arithmetic_overflow"
    UNCHECKED_CALLS = "unchecked_calls"
    FRONT_RUNNING = "front_running"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    DOS_ATTACK = "denial_of_service"
    SELF_DESTRUCT = "self_destruct"
    PRIVILEGED_ESCALATION = "privileged_escalation"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ROUTING_VULNERABILITY = "routing_vulnerability"
    STORAGE_MANIPULATION = "storage_manipulation"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    CENTRALIZATION_RISK = "centralization_risk"


class ExploitabilityLevel(Enum):
    IMMEDIATE = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    THEORETICAL = 1


class ImpactAssessment(Enum):
    TOTAL_LOSS = 5
    MAJOR_LOSS = 4
    SIGNIFICANT_LOSS = 3
    MODERATE_LOSS = 2
    MINIMAL_LOSS = 1


@dataclass
class CriticalFinding:
    vulnerability_type: CriticalVulnerabilityType
    severity_score: float
    exploitability: ExploitabilityLevel
    impact: ImpactAssessment
    contract_address: Optional[str]
    function_name: Optional[str]
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    cvss_vector: str
    affected_contracts: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    gas_estimate: Optional[int] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamps: Dict[str, float] = field(default_factory=dict)
    false_positive_rate: float = 0.0
    confirmed: bool = False
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    
    def __post_init__(self):
        self.timestamps['discovered'] = time.time()
        self.severity_score = self._calculate_severity()
    
    def _calculate_severity(self) -> float:
        base_score = (
            self.exploitability.value * 0.4 +
            self.impact.value * 0.4 +
            (1 - self.false_positive_rate) * 0.2
        ) * 20
        return min(base_score, 10.0)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'severity_score': self.severity_score,
            'exploitability': self.exploitability.value,
            'impact': self.impact.value,
            'contract_address': self.contract_address,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'recommendation': self.recommendation,
            'cvss_vector': self.cvss_vector,
            'affected_contracts': self.affected_contracts,
            'dependencies': self.dependencies,
            'gas_estimate': self.gas_estimate,
            'evidence': self.evidence,
            'confirmed': self.confirmed,
            'cwe_id': self.cwe_id,
            'cve_id': self.cve_id
        }


class CriticalPatternDetector(ABC):
    @abstractmethod
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        pass
    
    @abstractmethod
    def get_pattern_id(self) -> str:
        pass


class ReentrancyDetector(CriticalPatternDetector):
    def __init__(self):
        self.state_modifying_patterns = [
            r'\btransfer\s*\(',
            r'\bsend\s*\(',
            r'\bcall\s*\{.*\}\s*;',
            r'\bcall\.value\s*\(',
            r'\brawCall\s*\(',
        ]
        self.external_call_patterns = [
            r'\b(?:call|delegatecall|callcode)\s*\{',
            r'\b(?:transfer|send)\s*\(',
            r'\bAddress\.sendValue\s*\(',
            r'\bAddress\.functionCallWithValue\s*\(',
        ]
        self.state_update_patterns = [
            r'\bbalanceOf\s*\[',
            r'\b_balances\s*\[',
            r'\b_balances\.set\s*\(',
            r'\b_storedEther\s*=',
            r'\b_supply\s*=',
        ]
    
    def get_pattern_id(self) -> str:
        return "CRITICAL_REENTRANCY_001"
    
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        findings = []
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines):
            has_external_call = any(re.search(p, line) for p in self.external_call_patterns)
            has_state_modification = any(re.search(p, line) for p in self.state_modifying_patterns)
            
            if has_external_call:
                forward_context = '\n'.join(lines[i:min(i+10, len(lines))])
                if any(re.search(p, forward_context) for p in self.state_update_patterns):
                    finding = CriticalFinding(
                        vulnerability_type=CriticalVulnerabilityType.REENTRANCY,
                        severity_score=9.8,
                        exploitability=ExploitabilityLevel.IMMEDIATE,
                        impact=ImpactAssessment.TOTAL_LOSS,
                        contract_address=None,
                        function_name=self._extract_function_name(line),
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description="Potential reentrancy vulnerability detected. External call occurs before state updates.",
                        recommendation="Use checks-effects-interactions pattern, reentrancy guard, or PullPayment pattern.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-362"
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class AccessControlDetector(CriticalPatternDetector):
    def __init__(self):
        self.privileged_functions = [
            r'function\s+.*\s+onlyOwner',
            r'function\s+.*\s+onlyAdmin',
            r'function\s+.*\s+onlyMinter',
            r'function\s+.*\s+onlyPauser',
            r'function\s+.*\s+onlyGovernance',
        ]
        self.missing_modifier_patterns = [
            r'function\s+(withdraw|transfer|mint|burn|pause|unpause|upgrade|initialize)\s*\(',
        ]
        self.public_exec_patterns = [
            r'function\s+(execute|run|start|stop|kill|selfdestruct)\s*\([^)]*\)\s+public',
        ]
    
    def get_pattern_id(self) -> str:
        return "CRITICAL_ACCESS_CONTROL_001"
    
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        findings = []
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in self.missing_modifier_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_protection = any(re.search(p, '\n'.join(lines[max(0,i-5):i+5])) 
                                        for p in self.privileged_functions)
                    if not has_protection:
                        finding = CriticalFinding(
                            vulnerability_type=CriticalVulnerabilityType.ACCESS_CONTROL,
                            severity_score=9.5,
                            exploitability=ExploitabilityLevel.HIGH,
                            impact=ImpactAssessment.MAJOR_LOSS,
                            contract_address=None,
                            function_name=self._extract_function_name(line),
                            line_number=i + 1,
                            code_snippet=line.strip(),
                            description="Critical function lacks access control modifiers.",
                            recommendation="Add appropriate access control (onlyOwner, custom role, etc.)",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            cwe_id="CWE-284"
                        )
                        findings.append(finding)
        
        return findings
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class ArithmeticOverflowDetector(CriticalPatternDetector):
    def __init__(self):
        self.unsafe_math_patterns = [
            r'\+\s*\w+\s*;',
            r'-\s*\w+\s*;',
            r'\*\s*\w+\s*;',
            r'/\s*\w+\s*;',
        ]
        self.checked_math_imports = [
            r'import.*SafeMath',
            r'import.*SafeMath.*from',
        ]
    
    def get_pattern_id(self) -> str:
        return "CRITICAL_ARITHMETIC_OVERFLOW_001"
    
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        findings = []
        
        has_safemath = any(re.search(p, source_code) for p in self.checked_math_imports)
        
        if not has_safemath:
            lines = source_code.split('\n')
            for i, line in enumerate(lines):
                if any(re.search(p, line) for p in self.unsafe_math_patterns):
                    if '{' not in line and '}' not in line:
                        finding = CriticalFinding(
                            vulnerability_type=CriticalVulnerabilityType.ARITHMETIC_OVERFLOW,
                            severity_score=9.2,
                            exploitability=ExploitabilityLevel.HIGH,
                            impact=ImpactAssessment.SIGNIFICANT_LOSS,
                            contract_address=None,
                            function_name=self._extract_function_name(line),
                            line_number=i + 1,
                            code_snippet=line.strip(),
                            description="Potential arithmetic overflow/underflow without SafeMath.",
                            recommendation="Use SafeMath library or Solidity 0.8+ checked arithmetic.",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                            cwe_id="CWE-190"
                        )
                        findings.append(finding)
        
        return findings
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class UncheckedCallDetector(CriticalPatternDetector):
    def __init__(self):
        self.unchecked_patterns = [
            r'\.call\s*\([^)]*\)\s*;',
            r'\.send\s*\([^)]*\)\s*;',
            r'\.delegatecall\s*\([^)]*\)\s*;',
            r'Address\.functionCall\s*\(',
            r'Address\.functionCallWithValue\s*\(',
        ]
        self.checked_patterns = [
            r'require\s*\(\s*\w+\.call\s*\(',
            r'require\s*\(\s*\w+\.send\s*\(',
            r'\.call\s*\{.*value:\s*[^}]+\}\s*\(',
            r'if\s*\(\s*!\s*\w+\.call\s*\(',
        ]
    
    def get_pattern_id(self) -> str:
        return "CRITICAL_UNCHECKED_CALLS_001"
    
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        findings = []
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines):
            has_unchecked = any(re.search(p, line) for p in self.unchecked_patterns)
            has_check = any(re.search(p, '\n'.join(lines[max(0,i-3):i+2])) 
                           for p in self.checked_patterns)
            
            if has_unchecked and not has_check:
                finding = CriticalFinding(
                    vulnerability_type=CriticalVulnerabilityType.UNCHECKED_CALLS,
                    severity_score=8.9,
                    exploitability=ExploitabilityLevel.HIGH,
                    impact=ImpactAssessment.SIGNIFICANT_LOSS,
                    contract_address=None,
                    function_name=self._extract_function_name(line),
                    line_number=i + 1,
                    code_snippet=line.strip(),
                    description="Return value of low-level call is not checked.",
                    recommendation="Always check return value or use SafeERC20 wrapper.",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    cwe_id="CWE-252"
                )
                findings.append(finding)
        
        return findings
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class FrontRunningDetector(CriticalPatternDetector):
    def __init__(self):
        self.mempool_patterns = [
            r'function\s+.*set.*Price',
            r'function\s+.*swap.*exact.*tokens',
            r'function\s+.*trade.*exact',
            r'function\s+.*market.*order',
            r'function\s+.*submit.*bid',
            r'function\s+.*auction',
        ]
        self.price_dependent_patterns = [
            r'getReserves\s*\(\)',
            r'getAmountOut\s*\(',
            r'getAmountIn\s*\(',
            r'price\s*\(',
            r'quote\s*\(',
            r'latestAnswer\s*\(',
        ]
    
    def get_pattern_id(self) -> str:
        return "CRITICAL_FRONT_RUNNING_001"
    
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        findings = []
        
        has_price_oracle = any(re.search(p, source_code) for p in self.price_dependent_patterns)
        
        if has_price_oracle:
            lines = source_code.split('\n')
            for i, line in enumerate(lines):
                if any(re.search(p, line, re.IGNORECASE) for p in self.mempool_patterns):
                    finding = CriticalFinding(
                        vulnerability_type=CriticalVulnerabilityType.FRONT_RUNNING,
                        severity_score=8.5,
                        exploitability=ExploitabilityLevel.MEDIUM,
                        impact=ImpactAssessment.SIGNIFICANT_LOSS,
                        contract_address=None,
                        function_name=self._extract_function_name(line),
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description="Function vulnerable to front-running attacks due to MEV extraction.",
                        recommendation="Use commit-reveal scheme, private transactions, or batched operations.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        cwe_id="CWE-377"
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class FlashLoanAttackDetector(CriticalPatternDetector):
    def __init__(self):
        self.flash_loan_patterns = [
            r'IFlashLoanReceiver',
            r'flashLoan\s*\(',
            r'flash\s*\(',
            r'onFlashLoan\s*\(',
            r'IAaveFlashLoan',
            r'IBankruptcy',
        ]
        self.price_manipulation_patterns = [
            r'\.swap\s*\(',
            r'\.exchange\s*\(',
            r'\.trade\s*\(',
            r'getReserves\s*\(\)',
            r'balanceOf\s*\[.*\]',
        ]
    
    def get_pattern_id(self) -> str:
        return "CRITICAL_FLASH_LOAN_001"
    
    def detect(self, source_code: str, ast: Any) -> List[CriticalFinding]:
        findings = []
        
        has_flash_loan = any(re.search(p, source_code, re.IGNORECASE) for p in self.flash_loan_patterns)
        has_price_interaction = any(re.search(p, source_code) for p in self.price_manipulation_patterns)
        
        if has_flash_loan and has_price_interaction:
            lines = source_code.split('\n')
            for i, line in enumerate(lines):
                if 'function' in line.lower() and any(re.search(p, line) for p in self.flash_loan_patterns):
                    finding = CriticalFinding(
                        vulnerability_type=CriticalVulnerabilityType.FLASH_LOAN_ATTACK,
                        severity_score=9.7,
                        exploitability=ExploitabilityLevel.IMMEDIATE,
                        impact=ImpactAssessment.TOTAL_LOSS,
                        contract_address=None,
                        function_name=self._extract_function_name(line),
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description="Contract interacts with flash loans and external prices - vulnerable to flash loan attacks.",
                        recommendation="Use TWAP oracle, time-weighted averages, or decentralized price feeds.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-841"
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_function_name(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class CriticalSeverityEngine:
    def __init__(self):
        self.detectors: List[CriticalPatternDetector] = [
            ReentrancyDetector(),
            AccessControlDetector(),
            ArithmeticOverflowDetector(),
            UncheckedCallDetector(),
            FrontRunningDetector(),
            FlashLoanAttackDetector(),
        ]
        self.findings: List[CriticalFinding] = []
        self.statistics = {
            'total_scans': 0,
            'total_findings': 0,
            'by_type': Counter(),
            'by_severity': Counter(),
        }
    
    def register_detector(self, detector: CriticalPatternDetector):
        self.detectors.append(detector)
        logger.info(f"Registered detector: {detector.get_pattern_id()}")
    
    def scan_contract(self, source_code: str, ast: Optional[Any] = None) -> List[CriticalFinding]:
        self.findings.clear()
        
        for detector in self.detectors:
            try:
                findings = detector.detect(source_code, ast)
                self.findings.extend(findings)
                logger.info(f"Detector {detector.get_pattern_id()} found {len(findings)} issues")
            except Exception as e:
                logger.error(f"Error in detector {detector.get_pattern_id()}: {e}")
        
        self._update_statistics()
        return self.findings
    
    def _update_statistics(self):
        self.statistics['total_scans'] += 1
        self.statistics['total_findings'] += len(self.findings)
        
        for finding in self.findings:
            self.statistics['by_type'][finding.vulnerability_type.value] += 1
            self.statistics['by_severity'][finding.severity_score] += 1
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'summary': {
                'total_findings': len(self.findings),
                'critical_count': sum(1 for f in self.findings if f.severity_score >= 9.0),
                'high_count': sum(1 for f in self.findings if 7.0 <= f.severity_score < 9.0),
            },
            'findings': [f.to_dict() for f in self.findings],
            'statistics': dict(self.statistics),
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        recommendations = []
        
        for finding in self.findings:
            if finding.vulnerability_type == CriticalVulnerabilityType.REENTRANCY:
                recommendations.append("Implement ReentrancyGuard or use PullPayment pattern")
            elif finding.vulnerability_type == CriticalVulnerabilityType.ACCESS_CONTROL:
                recommendations.append("Review and implement proper access control mechanisms")
            elif finding.vulnerability_type == CriticalVulnerabilityType.ARITHMETIC_OVERFLOW:
                recommendations.append("Use Solidity 0.8+ or SafeMath library")
            elif finding.vulnerability_type == CriticalVulnerabilityType.UNCHECKED_CALLS:
                recommendations.append("Always verify return values of low-level calls")
            elif finding.vulnerability_type == CriticalVulnerabilityType.FRONT_RUNNING:
                recommendations.append("Implement commit-reveal or use MEV protection")
            elif finding.vulnerability_type == CriticalVulnerabilityType.FLASH_LOAN_ATTACK:
                recommendations.append("Use time-weighted price oracles (TWAP)")
        
        return list(set(recommendations))
    
    def export_json(self, filepath: str):
        report = self.generate_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report exported to {filepath}")
    
    def export_csv(self, filepath: str):
        import csv
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Severity', 'Line', 'Description', 'Recommendation'])
            
            for finding in self.findings:
                writer.writerow([
                    finding.vulnerability_type.value,
                    finding.severity_score,
                    finding.line_number,
                    finding.description,
                    finding.recommendation
                ])
        
        logger.info(f"CSV exported to {filepath}")


class CriticalSeverityClassifier:
    def __init__(self):
        self.thresholds = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
        }
    
    def classify(self, severity_score: float) -> str:
        if severity_score >= self.thresholds['critical']:
            return 'CRITICAL'
        elif severity_score >= self.thresholds['high']:
            return 'HIGH'
        elif severity_score >= self.thresholds['medium']:
            return 'MEDIUM'
        elif severity_score >= self.thresholds['low']:
            return 'LOW'
        else:
            return 'INFO'
    
    def get_color(self, severity_score: float) -> str:
        classification = self.classify(severity_score)
        colors = {
            'CRITICAL': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[94m',
            'LOW': '\033[92m',
            'INFO': '\033[0m',
        }
        return colors.get(classification, '\033[0m')


def analyze_contract(source_code: str) -> Dict[str, Any]:
    engine = CriticalSeverityEngine()
    findings = engine.scan_contract(source_code)
    return engine.generate_report()


def scan_directory(directory_path: str) -> Dict[str, Any]:
    import os
    
    results = {
        'contracts': {},
        'summary': {
            'total_contracts': 0,
            'total_findings': 0,
            'critical_contracts': 0
        }
    }
    
    for filename in os.listdir(directory_path):
        if filename.endswith('.sol'):
            filepath = os.path.join(directory_path, filename)
            with open(filepath, 'r') as f:
                source_code = f.read()
            
            report = analyze_contract(source_code)
            results['contracts'][filename] = report
            
            results['summary']['total_contracts'] += 1
            results['summary']['total_findings'] += report['summary']['total_findings']
            
            if report['summary']['critical_count'] > 0:
                results['summary']['critical_contracts'] += 1
    
    return results


if __name__ == '__main__':
    sample_code = """
    pragma solidity ^0.8.0;
    
    contract VulnerableBank {
        mapping(address => uint256) public balances;
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
        
        function withdraw() public {
            (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
            require(success);
            balances[msg.sender] = 0;
        }
    }
    """
    
    report = analyze_contract(sample_code)
    print(json.dumps(report, indent=2))
