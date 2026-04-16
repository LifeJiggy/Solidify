"""
Medium Severity Vulnerability Detection Module

This module provides comprehensive detection for medium-severity vulnerabilities
in Ethereum smart contracts. These vulnerabilities typically have limited impact
or require specific conditions to exploit but should still be addressed.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MediumSeverityVulnerabilityType(Enum):
    GAS_LIMIT_ISSUES = "gas_limit_issues"
    UNUSED_STATE_VARIABLE = "unused_state_variable"
    UNREACHABLE_CODE = "unreachable_code"
    DIVISION_ROUNDING = "division_rounding"
    BLOCK_GAS_LIMIT = "block_gas_limit"
    OUT_OF_GAS_DOS = "out_of_gas_dos"
    ARRAY_LENGTH_MANIPULATION = "array_length_manipulation"
    ENUM_ITERATION = "enum_iteration"
    MISSING_EVENT_EMIT = "missing_event_emission"
    INCORRECT_INHERITANCE = "incorrect_inheritance"
    SHADOWING_VARIABLES = "shadowing_variables"
    IMMUTABLE_VARIABLE = "immutable_variable"
    CONSTANT_VARIABLE = "constant_variable"


class SeverityLevel(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ExploitLikelihood(Enum):
    IMPROBABLE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    CERTAIN = 5


@dataclass
class MediumSeverityFinding:
    vulnerability_type: MediumSeverityVulnerabilityType
    severity_score: float
    likelihood: ExploitLikelihood
    contract_name: str
    function_name: Optional[str]
    line_number: int
    code_snippet: str
    description: str
    impact: str
    recommendation: str
    remediation_effort: str
    external_references: List[str] = field(default_factory=list)
    related_contracts: List[str] = field(default_factory=list)
    gas_impact: Optional[int] = None
    code_quality_impact: str = "Medium"
    automated_fix_available: bool = False
    
    def __post_init__(self):
        self.severity_score = min(max(self.likelihood.value * 1.4, 4.0), 6.9)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'severity_score': round(self.severity_score, 2),
            'likelihood': self.likelihood.name,
            'contract_name': self.contract_name,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet[:150],
            'description': self.description,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'remediation_effort': self.remediation_effort,
            'external_references': self.external_references,
            'gas_impact': self.gas_impact,
            'code_quality_impact': self.code_quality_impact,
            'automated_fix': self.automated_fix_available
        }


class MediumDetectorBase(ABC):
    @abstractmethod
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        pass
    
    @abstractmethod
    def get_detector_id(self) -> str:
        pass
    
    def _get_lines(self, source_code: str) -> List[str]:
        return source_code.split('\n')
    
    def _extract_function_at_line(self, lines: List[str], line_num: int) -> Optional[str]:
        for i in range(line_num - 1, -1, -1):
            if 'function' in lines[i] and '(' in lines[i]:
                match = re.search(r'function\s+(\w+)', lines[i])
                return match.group(1) if match else None
        return None


class GasLimitDetector(MediumDetectorBase):
    def __init__(self):
        self.loop_patterns = [
            r'for\s*\(',
            r'while\s*\(',
            r'do\s*\{',
        ]
        self.unbounded_patterns = [
            r'for\s*\([^)]*\+[^)]*\+[^)]*\)',
            r'for\s*\([^)]*\.length[^)]*\)',
            r'\.push\s*\(',
            r'\.send\s*\(',
        ]
        self.gas_intensive_ops = [
            r'SHA3',
            r'keccak256',
            r'ecrecover',
            r'modexp',
            r'threshold',
        ]
    
    def get_detector_id(self) -> str:
        return "MEDIUM_GAS_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        findings = []
        lines = self._get_lines(source_code)
        
        for i, line in enumerate(lines):
            for pattern in self.loop_patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-2):i+10])
                    
                    has_unbounded = any(re.search(p, context) for p in self.unbounded_patterns)
                    has_gas_ops = any(re.search(p, context, re.IGNORECASE) for p in self.gas_intensive_ops)
                    
                    if has_unbounded or has_gas_ops:
                        likelihood = ExploitLikelihood.LIKELY if has_unbounded else ExploitLikelihood.POSSIBLE
                        
                        finding = MediumSeverityFinding(
                            vulnerability_type=MediumSeverityVulnerabilityType.GAS_LIMIT_ISSUES,
                            severity_score=5.5,
                            likelihood=likelihood,
                            contract_name=contract_name,
                            function_name=self._extract_function_at_line(lines, i + 1),
                            line_number=i + 1,
                            code_snippet=line.strip(),
                            description="Potential gas limit issues in loop - may cause out-of-gas revert.",
                            impact="Transaction may fail due to block gas limit, causing DOS for users.",
                            recommendation="Implement pagination, use mappings instead of arrays, limit loop iterations.",
                            remediation_effort="Medium",
                            gas_impact=50000,
                            external_references=["SWC-128"],
                            automated_fix_available=False
                        )
                        findings.append(finding)
        
        return findings


class UnusedVariableDetector(MediumDetectorBase):
    def __init__(self):
        self.state_var_pattern = r'(uint|int|address|bool|bytes|string|struct|mapping)[^\[]*(\w+)\s*;'
        self.function_pattern = r'function\s+\w+\s*\([^)]*\)\s*(?:.*?)(?:returns\s*\([^)]*\))?\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    
    def get_detector_id(self) -> str:
        return "MEDIUM_UNUSED_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        findings = []
        
        state_vars = re.findall(self.state_var_pattern, source_code)
        used_vars = set()
        
        func_matches = re.finditer(self.function_pattern, source_code, re.DOTALL)
        for match in func_matches:
            func_body = match.group(2)
            for var in state_vars:
                var_name = var[1] if isinstance(var, tuple) else var
                if var_name in func_body:
                    used_vars.add(var_name)
        
        for var in state_vars:
            var_name = var[1] if isinstance(var, tuple) else var
            if var_name not in used_vars and not var_name.startswith('_'):
                finding = MediumSeverityFinding(
                    vulnerability_type=MediumSeverityVulnerabilityType.UNUSED_STATE_VARIABLE,
                    severity_score=4.2,
                    likelihood=ExploitLikelihood.UNLIKELY,
                    contract_name=contract_name,
                    function_name=None,
                    line_number=1,
                    code_snippet=f"State variable '{var_name}' may be unused",
                    description=f"State variable '{var_name}' appears to be unused.",
                    impact="Wastes storage space and increases gas costs.",
                    recommendation=f"Remove unused variable '{var_name}' or use it appropriately.",
                    remediation_effort="Low",
                    code_quality_impact="Low",
                    automated_fix_available=True
                )
                findings.append(finding)
        
        return findings


class MissingEventDetector(MediumDetectorBase):
    def __init__(self):
        self.state_changing_functions = [
            r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)?\s*(?:payable)?\s*\{',
        ]
        self.event_patterns = [
            r'event\s+\w+\s*\(',
            r'emit\s+\w+\s*\(',
        ]
        self.critical_functions = [
            r'transfer',
            r'mint',
            r'burn',
            r'withdraw',
            r'deposit',
            r'set',
            r'pause',
        ]
    
    def get_detector_id(self) -> str:
        return "MEDIUM_EVENT_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        findings = []
        
        has_events = bool(re.search(r'event\s+\w+', source_code))
        
        if has_events:
            func_matches = re.finditer(r'function\s+(\w+)\s*\([^)]*\)(?:.*?)(?:returns\s*\([^)]*\))?\{', source_code, re.DOTALL)
            
            for match in func_matches:
                func_name = match.group(1)
                is_critical = any(cf in func_name.lower() for cf in self.critical_functions)
                
                if is_critical:
                    func_start = match.end()
                    func_body = source_code[func_start:func_start+500]
                    has_emit = 'emit' in func_body
                    
                    if not has_emit:
                        line_number = source_code[:match.start()].count('\n') + 1
                        
                        finding = MediumSeverityFinding(
                            vulnerability_type=MediumSeverityVulnerabilityType.MISSING_EVENT_EMIT,
                            severity_score=4.8,
                            likelihood=ExploitLikelihood.POSSIBLE,
                            contract_name=contract_name,
                            function_name=func_name,
                            line_number=line_number,
                            code_snippet=f"function {func_name}(...)",
                            description=f"Critical function '{func_name}' lacks event emission.",
                            impact="Makes it difficult to track important state changes off-chain.",
                            recommendation=f"Add emit statement for {func_name} with relevant parameters.",
                            remediation_effort="Low",
                            code_quality_impact="Medium",
                            automated_fix_available=False
                        )
                        findings.append(finding)
        
        return findings


class ShadowingDetector(MediumDetectorBase):
    def __init__(self):
        self.state_var_pattern = r'(uint|int|address|bool|bytes|string|struct|mapping)[^\[]*\s+(\w+)\s*[;=]'
        self.param_pattern = r'function\s+\w+\s*\(([^)]*)\)'
        self.local_var_pattern = r'(uint|int|address|bool|bytes|string)\s+(\w+)\s*[;=]'
    
    def get_detector_id(self) -> str:
        return "MEDIUM_SHADOW_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        findings = []
        
        state_vars = set(re.findall(self.state_var_pattern, source_code))
        
        func_matches = re.finditer(r'function\s+(\w+)\s*\(([^)]*)\)(?:.*?)\{', source_code, re.DOTALL)
        
        for match in func_matches:
            func_name = match.group(1)
            params = match.group(2)
            func_body_start = match.end()
            func_body = source_code[func_body_start:func_body_start+1000]
            
            for sv in state_vars:
                if isinstance(sv, tuple):
                    sv_name = sv[1]
                else:
                    sv_name = sv
                
                if sv_name in params or sv_name in func_body:
                    param_match = re.search(rf'\b{sv_name}\b', params)
                    if param_match:
                        line_number = source_code[:match.start()].count('\n') + 1
                        
                        finding = MediumSeverityFinding(
                            vulnerability_type=MediumSeverityVulnerabilityType.SHADOWING_VARIABLES,
                            severity_score=5.0,
                            likelihood=ExploitLikelihood.POSSIBLE,
                            contract_name=contract_name,
                            function_name=func_name,
                            line_number=line_number,
                            code_snippet=f"Parameter '{sv_name}' shadows state variable",
                            description=f"Local variable/parameter '{sv_name}' shadows state variable.",
                            impact="Can lead to confusion and potential bugs in contract logic.",
                            recommendation=f"Rename parameter or local variable to avoid shadowing.",
                            remediation_effort="Low",
                            code_quality_impact="Medium",
                            automated_fix_available=True
                        )
                        findings.append(finding)
        
        return findings


class ArrayLengthManipulationDetector(MediumDetectorBase):
    def __init__(self):
        self.dynamic_array_patterns = [
            r'\.length\s*=',
            r'\.push\s*\(',
            r'\.pop\s*\(',
        ]
        self.loop_with_array = [
            r'for\s*\([^)]*\.length[^)]*\)',
            r'for\s*\([^)]*\.push[^)]*\)',
        ]
    
    def get_detector_id(self) -> str:
        return "MEDIUM_ARRAY_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        findings = []
        
        has_dynamic = any(re.search(p, source_code) for p in self.dynamic_array_patterns)
        
        if has_dynamic:
            lines = source_code.split('\n')
            
            for i, line in enumerate(lines):
                if '.length' in line and '=' in line:
                    finding = MediumSeverityFinding(
                        vulnerability_type=MediumSeverityVulnerabilityType.ARRAY_LENGTH_MANIPULATION,
                        severity_score=5.2,
                        likelihood=ExploitLikelihood.UNLIKELY,
                        contract_name=contract_name,
                        function_name=self._extract_function_at_line(lines, i + 1),
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        description="Direct array length manipulation detected.",
                        impact="Can lead to out-of-bounds access or gas limit issues.",
                        recommendation="Use push/pop for dynamic arrays instead of direct length manipulation.",
                        remediation_effort="Medium",
                        code_quality_impact="Medium"
                    )
                    findings.append(finding)
        
        return findings


class DivisionRoundingDetector(MediumDetectorBase):
    def __init__(self):
        self.division_patterns = [
            r'\/\s*\w+',
            r'\/\s*\d+',
        ]
    
    def get_detector_id(self) -> str:
        return "MEDIUM_DIVISION_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[MediumSeverityFinding]:
        findings = []
        
        has_safemath = 'SafeMath' in source_code or '0.8' in source_code
        
        if not has_safemath:
            lines = source_code.split('\n')
            
            for i, line in enumerate(lines):
                if re.search(r'\/\s*[^/]', line) and '/' in line:
                    if 'require' not in line.lower() and 'if' not in line.lower():
                        finding = MediumSeverityFinding(
                            vulnerability_type=MediumSeverityVulnerabilityType.DIVISION_ROUNDING,
                            severity_score=4.5,
                            likelihood=ExploitLikelihood.POSSIBLE,
                            contract_name=contract_name,
                            function_name=self._extract_function_at_line(lines, i + 1),
                            line_number=i + 1,
                            code_snippet=line.strip(),
                            description="Division operation may result in truncation.",
                            impact="Integer division truncates result, potentially causing precision loss.",
                            recommendation="Consider using multiplication before division or SafeMath.",
                            remediation_effort="Low",
                            code_quality_impact="Medium"
                        )
                        findings.append(finding)
        
        return findings


class MediumSeverityEngine:
    def __init__(self):
        self.detectors: List[MediumDetectorBase] = [
            GasLimitDetector(),
            UnusedVariableDetector(),
            MissingEventDetector(),
            ShadowingDetector(),
            ArrayLengthManipulationDetector(),
            DivisionRoundingDetector(),
        ]
        self.findings: List[MediumSeverityFinding] = []
    
    def register_detector(self, detector: MediumDetectorBase):
        self.detectors.append(detector)
    
    def scan_contract(self, source_code: str, contract_name: str = "Contract") -> List[MediumSeverityFinding]:
        self.findings.clear()
        
        for detector in self.detectors:
            try:
                findings = detector.detect(source_code, contract_name)
                self.findings.extend(findings)
            except Exception as e:
                logger.error(f"Error in {detector.get_detector_id()}: {e}")
        
        return self.findings
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'summary': {
                'total_findings': len(self.findings),
                'severity_breakdown': {
                    'medium': sum(1 for f in self.findings if 5.0 <= f.severity_score < 7.0),
                    'low_medium': sum(1 for f in self.findings if 4.0 <= f.severity_score < 5.0),
                }
            },
            'findings': [f.to_dict() for f in self.findings]
        }


def analyze_medium_severity(source_code: str, contract_name: str = "Contract") -> Dict[str, Any]:
    engine = MediumSeverityEngine()
    engine.scan_contract(source_code, contract_name)
    return engine.generate_report()


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract Example {
        uint256 public totalSupply;
        mapping(address => uint256) balances;
        
        function processAll(address[] calldata users) public {
            for (uint i = 0; i < users.length; i++) {
                balances[users[i]] = balances[users[i]] + 10;
            }
        }
        
        function mint(address to, uint256 amount) public {
            balances[to] += amount;
        }
    }
    """
    
    report = analyze_medium_severity(sample, "Example")
    print(json.dumps(report, indent=2))
