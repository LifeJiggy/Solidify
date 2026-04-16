"""
High Severity Vulnerability Detection Module

This module implements sophisticated detection algorithms for high-severity
vulnerabilities in Ethereum smart contracts. It provides comprehensive analysis
for vulnerabilities that can lead to significant financial losses but may require
specific conditions or additional prerequisites to exploit.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple, Any, Set, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HighSeverityVulnerabilityType(Enum):
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    BLOCK_NUMBER_DEPENDENCE = "block_number_dependence"
    RANDOMNESS_VULNERABILITY = "randomness_vulnerability"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGED_OPERATIONS = "privileged_operations"
    DELEGATE_CALL_RISK = "delegatecall_risk"
    TXORIGIN_USAGE = "tx_origin_usage"
    STORAGE_COLLISION = "storage_collision"
    IMPERSONATION = "impersonation"
    UPGRADEABILITY_RISK = "upgradeability_risk"
    PROXY_PATTERN_RISK = "proxy_pattern_risk"


class ComplexityLevel(Enum):
    TRIVIAL = 5
    SIMPLE = 4
    MODERATE = 3
    COMPLEX = 2
    VERY_COMPLEX = 1


class AttackSurfaceLevel(Enum):
    MINIMAL = 1
    LIMITED = 2
    MODERATE = 3
    EXTENSIVE = 4
    MAXIMUM = 5


@dataclass
class HighSeverityFinding:
    vulnerability_type: HighSeverityVulnerabilityType
    severity_score: float
    complexity: ComplexityLevel
    attack_surface: AttackSurfaceLevel
    contract_address: Optional[str]
    contract_name: str
    function_name: Optional[str]
    line_number: int
    code_snippet: str
    description: str
    impact_description: str
    recommendation: str
    cvss_vector: str
    affected_functions: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    gas_optimization: Optional[int] = None
    confidence_score: float = 0.85
    false_positive_likelihood: float = 0.1
    related_cwe: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        self.severity_score = self._calculate_adjusted_score()
    
    def _calculate_adjusted_score(self) -> float:
        base = 7.0
        complexity_factor = (5 - self.complexity.value) * 0.15
        surface_factor = self.attack_surface.value * 0.1
        confidence_factor = self.confidence_score * 0.2
        fp_penalty = self.false_positive_likelihood * 0.1
        
        adjusted = base + complexity_factor + surface_factor + confidence_factor - fp_penalty
        return min(max(adjusted, 7.0), 8.9)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'severity_score': round(self.severity_score, 2),
            'complexity': self.complexity.value,
            'attack_surface': self.attack_surface.value,
            'contract_address': self.contract_address,
            'contract_name': self.contract_name,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet[:200],
            'description': self.description,
            'impact_description': self.impact_description,
            'recommendation': self.recommendation,
            'cvss_vector': self.cvss_vector,
            'affected_functions': self.affected_functions,
            'prerequisites': self.prerequisites,
            'mitigation_steps': self.mitigation_steps,
            'references': self.references,
            'confidence_score': self.confidence_score,
            'related_cwe': self.related_cwe
        }


class HighSeverityDetectorBase(ABC):
    @abstractmethod
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        pass
    
    @abstractmethod
    def get_detector_id(self) -> str:
        pass
    
    def _extract_function_names(self, source_code: str) -> List[str]:
        pattern = r'function\s+(\w+)\s*\('
        return re.findall(pattern, source_code)
    
    def _extract_modifiers(self, source_code: str) -> Dict[str, List[str]]:
        modifiers = {}
        func_pattern = r'function\s+(\w+)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        matches = re.finditer(func_pattern, source_code, re.DOTALL)
        
        for match in matches:
            func_name = match.group(1)
            func_body = match.group(2)
            mod_pattern = r'modifier\s+(\w+)'
            modifiers[func_name] = re.findall(mod_pattern, func_body)
        
        return modifiers


class TimestampDependenceDetector(HighSeverityDetectorBase):
    def __init__(self):
        self.timestamp_patterns = [
            r'\bblock\.timestamp\b',
            r'\bnow\b',
            r'\btimestamp\s*=',
        ]
        self.critical_operations = [
            r'random',
            r'winner',
            r'draw',
            r'lottery',
            r'voting',
            r'price',
            r'rate',
            r'exchange',
        ]
    
    def get_detector_id(self) -> str:
        return "HIGH_TIMESTAMP_001"
    
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        findings = []
        
        for pattern in self.timestamp_patterns:
            matches = list(re.finditer(pattern, source_code))
            
            for match in matches:
                line_number = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_number - 1].strip()
                
                is_critical = any(op in line.lower() for op in self.critical_operations)
                
                if is_critical:
                    finding = HighSeverityFinding(
                        vulnerability_type=HighSeverityVulnerabilityType.TIMESTAMP_DEPENDENCE,
                        severity_score=7.5,
                        complexity=ComplexityLevel.MODERATE,
                        attack_surface=AttackSurfaceLevel.MODERATE,
                        contract_address=None,
                        contract_name=contract_name,
                        function_name=self._extract_function(line),
                        line_number=line_number,
                        code_snippet=line,
                        description="Contract depends on block.timestamp for critical operations.",
                        impact_description="Miners can manipulate timestamp within certain limits to influence outcome.",
                        recommendation="Avoid using block.timestamp for critical decisions. Use block.number or external oracle.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        prerequisites=["Miner collusion"],
                        mitigation_steps=[
                            "Use block.number for time-based calculations",
                            "Implement commit-reveal scheme",
                            "Use external verifiable random function"
                        ],
                        references=["SWC-116"],
                        related_cwe=["CWE-829", "CWE-367"]
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_function(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class RandomnessVulnerabilityDetector(HighSeverityDetectorBase):
    def __init__(self):
        self.weak_random_patterns = [
            r'block\.hash\s*\(\s*block\.number',
            r'blockhash\s*\(\s*block\.number',
            r'keccak256\s*\(\s*block\.timestamp',
            r'keccak256\s*\(\s*now',
            r'keccak256\s*\(\s*block\.difficulty',
            r'keccak256\s*\(\s*msg\.sender',
            r'abi\.encodePacked\s*\(\s*block\.timestamp',
            r'uint256\s*\(\s*keccak256\s*\(\s*block\.timestamp',
        ]
        self.gambling_patterns = [
            r'lottery',
            r'gamble',
            r'bet',
            r'raffle',
            r'random',
            r'game',
            r'casino',
        ]
    
    def get_detector_id(self) -> str:
        return "HIGH_RANDOMNESS_001"
    
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        findings = []
        source_lower = source_code.lower()
        
        has_gambling = any(p in source_lower for p in self.gambling_patterns)
        
        for pattern in self.weak_random_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            
            for match in matches:
                line_number = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_number - 1].strip()
                
                complexity = ComplexityLevel.TRIVIAL if has_gambling else ComplexityLevel.SIMPLE
                
                finding = HighSeverityFinding(
                    vulnerability_type=HighSeverityVulnerabilityType.RANDOMNESS_VULNERABILITY,
                    severity_score=7.8,
                    complexity=complexity,
                    attack_surface=AttackSurfaceLevel.EXTENSIVE,
                    contract_address=None,
                    contract_name=contract_name,
                    function_name=self._extract_function(line),
                    line_number=line_number,
                    code_snippet=line,
                    description="Weak randomness source detected - predictable by miners/attackers.",
                    impact_description="Attackers can predict and manipulate outcomes of random operations.",
                    recommendation="Use Chainlink VRF, commit-reveal with beacon chain randomness, or verifiable delay functions.",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    prerequisites=["Predictable block variables"],
                    mitigation_steps=[
                        "Integrate Chainlink VRF for provably fair randomness",
                        "Use beacon chain randomness (RANDAO)",
                        "Implement commit-reveal scheme"
                    ],
                    references=["SWC-120", "CVE-2018-12454"],
                    related_cwe=["CWE-338", "CWE-341"]
                )
                findings.append(finding)
        
        return findings
    
    def _extract_function(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class DelegateCallRiskDetector(HighSeverityDetectorBase):
    def __init__(self):
        self.delegatecall_patterns = [
            r'\.delegatecall\s*\(',
            r'delegatecall\s*\(',
            r'\.library\s*\(',
        ]
        self.proxy_patterns = [
            r'Proxy',
            r'Upgradeable',
            r'Initializable',
            r'Upgradable',
        ]
        self.storage_collision_patterns = [
            r'storage\s+layout',
            r'struct\s+\w+\s*\{[^}]*uint256',
        ]
    
    def get_detector_id(self) -> str:
        return "HIGH_DELEGATECALL_001"
    
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        findings = []
        
        for pattern in self.delegatecall_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            
            for match in matches:
                line_number = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_number - 1].strip()
                
                is_proxy = any(p in source_code for p in self.proxy_patterns)
                
                finding = HighSeverityFinding(
                    vulnerability_type=HighSeverityVulnerabilityType.DELEGATE_CALL_RISK,
                    severity_score=7.6,
                    complexity=ComplexityLevel.COMPLEX,
                    attack_surface=AttackSurfaceLevel.MODERATE,
                    contract_address=None,
                    contract_name=contract_name,
                    function_name=self._extract_function(line),
                    line_number=line_number,
                    code_snippet=line,
                    description="Usage of delegatecall in untrusted context.",
                    impact_description="Storage collisions, malicious library code execution, complete compromise.",
                    recommendation="Validate delegatecall target, use proxy patterns carefully, ensure storage layout compatibility.",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    prerequisites=["Malicious or buggy library"],
                    mitigation_steps=[
                        "Use OpenZeppelin proxy patterns",
                        "Validate delegatecall target address",
                        "Document and audit storage layouts"
                    ],
                    references=["SWC-112"],
                    related_cwe=["CWE-829", "CWE-494"]
                )
                findings.append(finding)
        
        return findings
    
    def _extract_function(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class TxOriginVulnerabilityDetector(HighSeverityDetectorBase):
    def __init__(self):
        self.txorigin_patterns = [
            r'\btx\.origin\b',
            r'tx\.origin\s*=',
        ]
        self.authentication_patterns = [
            r'require\s*\(\s*tx\.origin\s*==',
            r'if\s*\(\s*tx\.origin\s*!=',
            r'require\s*\(\s*msg\.sender\s*==\s*tx\.origin',
        ]
    
    def get_detector_id(self) -> str:
        return "HIGH_TXORIGIN_001"
    
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        findings = []
        
        for pattern in self.txorigin_patterns:
            matches = list(re.finditer(pattern, source_code))
            
            for match in matches:
                line_number = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_number - 1].strip()
                
                is_auth = any(re.search(p, line) for p in self.authentication_patterns)
                
                if is_auth:
                    finding = HighSeverityFinding(
                        vulnerability_type=HighSeverityVulnerabilityType.TXORIGIN_USAGE,
                        severity_score=7.2,
                        complexity=ComplexityLevel.SIMPLE,
                        attack_surface=AttackSurfaceLevel.LIMITED,
                        contract_address=None,
                        contract_name=contract_name,
                        function_name=self._extract_function(line),
                        line_number=line_number,
                        code_snippet=line,
                        description="tx.origin used for authentication - vulnerable to phishing attacks.",
                        impact_description="Attackers can trick users into calling contracts that authenticate via tx.origin.",
                        recommendation="Use msg.sender instead of tx.origin for authorization.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                        prerequisites=["User interaction with malicious contract"],
                        mitigation_steps=[
                            "Replace tx.origin with msg.sender",
                            "Implement proper authentication flow"
                        ],
                        references=["SWC-115"],
                        related_cwe=["CWE-346", "CWE-477"]
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_function(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class IntegerOverflowDetector(HighSeverityDetectorBase):
    def __init__(self):
        self.arithmetic_patterns = [
            r'\+\s*\w+\s*;',
            r'-\s*\w+\s*;',
            r'\*\s*\w+\s*;',
            r'/\s*\w+\s*;',
            r'%\s*\w+\s*;',
            r'\+\+',
            r'--',
        ]
        self.safe_math_imports = [
            r'SafeMath',
            r'using\s+\w+\s+for',
            r'0\.[0-9]+\.0',
        ]
        self.unchecked_patterns = [
            r'\/\/\s*unchecked',
            r'\/\*[\s*]unchecked[\s*]\*\/',
        ]
    
    def get_detector_id(self) -> str:
        return "HIGH_INTEGER_001"
    
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        findings = []
        
        has_safemath = any(re.search(p, source_code) for p in self.safe_math_imports)
        has_unchecked = any(re.search(p, source_code) for p in self.unchecked_patterns)
        
        if not has_safemath and not has_unchecked:
            lines = source_code.split('\n')
            
            for i, line in enumerate(lines):
                if any(re.search(p, line) for p in self.arithmetic_patterns):
                    if '{' in line or '}' in line:
                        continue
                    
                    finding = HighSeverityFinding(
                        vulnerability_type=HighSeverityVulnerabilityType.INTEGER_OVERFLOW,
                        severity_score=7.4,
                        complexity=ComplexityLevel.SIMPLE,
                        attack_surface=AttackSurfaceLevel.MODERATE,
                        contract_address=None,
                        contract_name=contract_name,
                        function_name=self._extract_function(line),
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description="Potential integer overflow without SafeMath.",
                        impact_description="Arithmetic operations can wrap around leading to unexpected values.",
                        recommendation="Use Solidity 0.8+ with checked arithmetic or SafeMath library.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        mitigation_steps=[
                            "Use Solidity 0.8+ checked arithmetic",
                            "Import and use SafeMath library",
                            "Add explicit overflow checks"
                        ],
                        references=["SWC-101"],
                        related_cwe=["CWE-190", "CWE-191"]
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_function(self, line: str) -> Optional[str]:
        match = re.search(r'function\s+(\w+)', line)
        return match.group(1) if match else None


class UnauthorizedAccessDetector(HighSeverityDetectorBase):
    def __init__(self):
        self.sensitive_operations = [
            r'withdraw',
            r'mint',
            r'burn',
            r'mintTo',
            r'burnFrom',
            r'pause',
            r'unpause',
            r'setPrice',
            r'setRate',
            r'setOwner',
            r'upgrade',
            r'transferOwnership',
            r'addMinter',
            r'revokeMinter',
        ]
        self.modifier_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'onlyMinter',
            r'onlyPauser',
            r'onlyGovernance',
            r'requiresAuth',
            r'auth',
        ]
    
    def get_detector_id(self) -> str:
        return "HIGH_UNAUTHORIZED_001"
    
    def detect(self, source_code: str, ast: Any, contract_name: str) -> List[HighSeverityFinding]:
        findings = []
        
        sensitive_funcs = []
        for pattern in self.sensitive_operations:
            matches = re.finditer(rf'function\s+(\w+)[^{{]*\b{pattern}\b', source_code, re.IGNORECASE)
            sensitive_funcs.extend([m.group(1) for m in matches])
        
        for func in sensitive_funcs:
            func_pattern = rf'function\s+{func}\s*\([^)]*\)(?:.*?)(?={{|(?:modifier|$))'
            func_match = re.search(func_pattern, source_code, re.DOTALL | re.IGNORECASE)
            
            if func_match:
                func_block = func_match.group(0)
                has_modifier = any(re.search(m, func_block) for m in self.modifier_patterns)
                
                if not has_modifier:
                    line_number = source_code[:func_match.start()].count('\n') + 1
                    line = source_code.split('\n')[line_number - 1].strip()
                    
                    finding = HighSeverityFinding(
                        vulnerability_type=HighSeverityVulnerabilityType.UNAUTHORIZED_ACCESS,
                        severity_score=7.9,
                        complexity=ComplexityLevel.SIMPLE,
                        attack_surface=AttackSurfaceLevel.EXTENSIVE,
                        contract_address=None,
                        contract_name=contract_name,
                        function_name=func,
                        line_number=line_number,
                        code_snippet=line,
                        description=f"Sensitive function '{func}' lacks access control.",
                        impact_description="Anyone can execute sensitive operations leading to fund loss or contract compromise.",
                        recommendation=f"Add appropriate access control modifier to {func}.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        mitigation_steps=[
                            "Add onlyOwner or role-based modifier",
                            "Implement proper access control",
                            "Review and audit permissions"
                        ],
                        references=["SWC-100"],
                        related_cwe=["CWE-284", "CWE-862"]
                    )
                    findings.append(finding)
        
        return findings


class HighSeverityEngine:
    def __init__(self):
        self.detectors: List[HighSeverityDetectorBase] = [
            TimestampDependenceDetector(),
            RandomnessVulnerabilityDetector(),
            DelegateCallRiskDetector(),
            TxOriginVulnerabilityDetector(),
            IntegerOverflowDetector(),
            UnauthorizedAccessDetector(),
        ]
        self.findings: List[HighSeverityFinding] = []
        self.scan_history: List[Dict[str, Any]] = []
    
    def register_detector(self, detector: HighSeverityDetectorBase):
        self.detectors.append(detector)
        logger.info(f"Registered high severity detector: {detector.get_detector_id()}")
    
    def scan_contract(self, source_code: str, contract_name: str = "Unknown") -> List[HighSeverityFinding]:
        self.findings.clear()
        
        for detector in self.detectors:
            try:
                findings = detector.detect(source_code, None, contract_name)
                self.findings.extend(findings)
            except Exception as e:
                logger.error(f"Error in detector {detector.get_detector_id()}: {e}")
        
        self._record_scan(contract_name, len(self.findings))
        return self.findings
    
    def _record_scan(self, contract_name: str, finding_count: int):
        self.scan_history.append({
            'timestamp': time.time(),
            'contract': contract_name,
            'findings': finding_count
        })
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            'total_scans': len(self.scan_history),
            'total_findings': sum(s['findings'] for s in self.scan_history),
            'by_type': Counter(f.vulnerability_type.value for f in self.findings),
            'by_contract': Counter(s['contract'] for s in self.scan_history)
        }
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'summary': {
                'total_findings': len(self.findings),
                'high_count': sum(1 for f in self.findings if f.severity_score >= 7.5),
                'medium_high_count': sum(1 for f in self.findings if 7.0 <= f.severity_score < 7.5),
            },
            'findings': [f.to_dict() for f in self.findings],
            'statistics': self.get_statistics()
        }
    
    def export_json(self, filepath: str):
        report = self.generate_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)


def analyze_high_severity(source_code: str, contract_name: str = "Contract") -> Dict[str, Any]:
    engine = HighSeverityEngine()
    engine.scan_contract(source_code, contract_name)
    return engine.generate_report()


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract VulnerableGame {
        function play() public {
            uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
            require(random > 100, "You lose");
        }
        
        function withdraw() public {
            msg.sender.transfer(address(this).balance);
        }
    }
    """
    
    report = analyze_high_severity(sample, "VulnerableGame")
    print(json.dumps(report, indent=2))
