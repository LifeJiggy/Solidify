"""
Low Severity Vulnerability Detection Module

This module provides detection for low-severity issues, code smells, and best practice
violations in Ethereum smart contracts. These typically don't pose immediate security risks
but should be addressed for code quality and gas optimization.

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


class LowSeverityIssueType(Enum):
    CODE_SMELL = "code_smell"
    GAS_OPTIMIZATION = "gas_optimization"
    CODE_READABILITY = "code_readability"
    BEST_PRACTICE = "best_practice"
    COMPILER_WARNING = "compiler_warning"
    DEPRECATED_USAGE = "deprecated_usage"
    UNOPTIMIZED_STORAGE = "unoptimized_storage"
    INEFFICIENT_ALGORITHM = "inefficient_algorithm"
    HARDCODED_VALUES = "hardcoded_values"
    MISSING_DOCS = "missing_documentation"


class IssuePriority(Enum):
    TRIVIAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4


@dataclass
class LowSeverityIssue:
    issue_type: LowSeverityIssueType
    severity_score: float
    priority: IssuePriority
    contract_name: str
    function_name: Optional[str]
    line_number: int
    code_snippet: str
    title: str
    description: str
    suggestion: str
    gas_savings: Optional[int] = None
    refactoring_effort: str = "Minimal"
    
    def __post_init__(self):
        self.severity_score = min(max(self.priority.value * 0.8, 0.5), 3.9)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'issue_type': self.issue_type.value,
            'severity_score': round(self.severity_score, 2),
            'priority': self.priority.name,
            'contract_name': self.contract_name,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet[:100],
            'title': self.title,
            'description': self.description,
            'suggestion': self.suggestion,
            'gas_savings': self.gas_savings,
            'refactoring_effort': self.refactoring_effort
        }


class LowDetectorBase(ABC):
    @abstractmethod
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        pass
    
    @abstractmethod
    def get_detector_id(self) -> str:
        pass


class GasOptimizationDetector(LowDetectorBase):
    def __init__(self):
        self.inefficient_patterns = [
            (r'bytes\(\w+\).length', 'Use bytes32 instead of dynamic bytes for fixed-size data'),
            (r'variable\s*\+\s*0\b', 'Adding zero is wasteful'),
            (r'variable\s*\*\s*1\b', 'Multiplying by one is redundant'),
            (r'string\(abi\.encodePacked\(', 'Use bytes32 for short strings'),
            (r'uint256\(address\(', 'Unnecessary type conversion'),
        ]
        self.optimizations = {
            'cache_array_length': ('cache array length in loop', 1000),
            'short_circuit_evaluation': ('short-circuit boolean operations', 500),
            'unchecked_i_inc': ('use ++i instead of i++ when no assignment', 200),
        }
    
    def get_detector_id(self) -> str:
        return "LOW_GAS_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        issues = []
        
        for pattern, message in self.inefficient_patterns:
            matches = list(re.finditer(pattern, source_code))
            for match in matches:
                line_num = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_num - 1].strip()
                
                issue = LowSeverityIssue(
                    issue_type=LowSeverityIssueType.GAS_OPTIMIZATION,
                    severity_score=2.5,
                    priority=IssuePriority.LOW,
                    contract_name=contract_name,
                    function_name=self._get_function(source_code, line_num),
                    line_number=line_num,
                    code_snippet=line,
                    title="Gas Optimization Opportunity",
                    description=message,
                    suggestion=f"Optimize: {message}",
                    gas_savings=500,
                    refactoring_effort="Low"
                )
                issues.append(issue)
        
        return issues
    
    def _get_function(self, source_code: str, line_num: int) -> Optional[str]:
        lines = source_code.split('\n')[:line_num]
        for line in reversed(lines):
            if 'function' in line:
                match = re.search(r'function\s+(\w+)', line)
                return match.group(1) if match else None
        return None


class DeprecatedUsageDetector(LowDetectorBase):
    def __init__(self):
        self.deprecated_patterns = [
            (r'\.call\.value\(', 'Use {value: x}() syntax instead'),
            (r'\s+throw\b', 'Use require/revert instead of throw'),
            (r'address\(this\)', 'Use address(this)'),
            (r'\.sha3\(', 'Use keccak256 instead of sha3'),
            (r'selfdestruct\(', 'Use selfdestruct (lowercase)'),
        ]
    
    def get_detector_id(self) -> str:
        return "LOW_DEPRECATED_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        issues = []
        
        for pattern, suggestion in self.deprecated_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            for match in matches:
                line_num = source_code[:match.start()].count('\n') + 1
                line = source_code.split('\n')[line_num - 1].strip()
                
                issue = LowSeverityIssue(
                    issue_type=LowSeverityIssueType.DEPRECATED_USAGE,
                    severity_score=2.0,
                    priority=IssuePriority.TRIVIAL,
                    contract_name=contract_name,
                    function_name=self._get_function(source_code, line_num),
                    line_number=line_num,
                    code_snippet=line,
                    title="Deprecated Usage",
                    description=f"Using deprecated pattern: {line[:30]}",
                    suggestion=suggestion,
                    refactoring_effort="Low"
                )
                issues.append(issue)
        
        return issues
    
    def _get_function(self, source_code: str, line_num: int) -> Optional[str]:
        lines = source_code.split('\n')[:line_num]
        for line in reversed(lines):
            if 'function' in line:
                match = re.search(r'function\s+(\w+)', line)
                return match.group(1) if match else None
        return None


class MissingDocumentationDetector(LowDetectorBase):
    def __init__(self):
        self.functions_without_docs = [
            r'function\s+(\w+)\s*\([^)]*\)\s*public[^/]*\{',
        ]
        self.natspec_pattern = r'/\*\*|@title|@author|@notice'
    
    def get_detector_id(self) -> str:
        return "LOW_DOCS_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        issues = []
        
        has_natspec = bool(re.search(self.natspec_pattern, source_code))
        
        if not has_natspec:
            func_matches = re.finditer(r'function\s+(\w+)', source_code)
            for match in func_matches:
                line_num = source_code[:match.start()].count('\n') + 1
                func_name = match.group(1)
                
                issue = LowSeverityIssue(
                    issue_type=LowSeverityIssueType.MISSING_DOCS,
                    severity_score=1.5,
                    priority=IssuePriority.TRIVIAL,
                    contract_name=contract_name,
                    function_name=func_name,
                    line_number=line_num,
                    code_snippet=f"function {func_name}(...)",
                    title="Missing Documentation",
                    description=f"Function {func_name} lacks NatSpec documentation.",
                    suggestion="Add @title, @author, @notice, and @dev comments.",
                    refactoring_effort="Low"
                )
                issues.append(issue)
        
        return issues


class HardcodedValuesDetector(LowDetectorBase):
    def __init__(self):
        self.hardcoded_patterns = [
            r'uint256\s+\(\s*\d+\s*\)',
            r'address\(\s*0x[0-9a-fA-F]{40}\s*\)',
            r'"\w+"',
        ]
    
    def get_detector_id(self) -> str:
        return "LOW_HARDCODED_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        issues = []
        
        matches = list(re.finditer(r'0x[0-9a-fA-F]{40}', source_code))
        for match in matches:
            line_num = source_code[:match.start()].count('\n') + 1
            line = source_code.split('\n')[line_num - 1].strip()
            
            issue = LowSeverityIssue(
                issue_type=LowSeverityIssueType.HARDCODED_VALUES,
                severity_score=1.8,
                priority=IssuePriority.TRIVIAL,
                contract_name=contract_name,
                function_name=self._get_function(source_code, line_num),
                line_number=line_num,
                code_snippet=line[:50],
                title="Hardcoded Address",
                description="Contract address is hardcoded - consider using parameters.",
                suggestion="Use constructor parameters or configuration contract.",
                refactoring_effort="Medium"
            )
            issues.append(issue)
        
        return issues
    
    def _get_function(self, source_code: str, line_num: int) -> Optional[str]:
        lines = source_code.split('\n')[:line_num]
        for line in reversed(lines):
            if 'function' in line:
                match = re.search(r'function\s+(\w+)', line)
                return match.group(1) if match else None
        return None


class UnusedModifierDetector(LowDetectorBase):
    def __init__(self):
        self.modifier_pattern = r'modifier\s+(\w+)'
        self.used_modifier_pattern = r'\\b\1\s*('
    
    def get_detector_id(self) -> str:
        return "LOW_MODIFIER_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        issues = []
        
        modifiers = re.findall(self.modifier_pattern, source_code)
        
        for mod in modifiers:
            if mod == 'nonReentrant':
                continue
            used = len(re.findall(rf'\b{mod}\b', source_code)) > 1
            if not used:
                issue = LowSeverityIssue(
                    issue_type=LowSeverityIssueType.CODE_SMELL,
                    severity_score=1.2,
                    priority=IssuePriority.TRIVIAL,
                    contract_name=contract_name,
                    function_name=None,
                    line_number=1,
                    code_snippet=f"modifier {mod}",
                    title="Unused Modifier",
                    description=f"Modifier '{mod}' is defined but never used.",
                    suggestion=f"Remove unused modifier '{mod}' or use it properly.",
                    refactoring_effort="Low"
                )
                issues.append(issue)
        
        return issues


class ContractNamingDetector(LowDetectorBase):
    def __init__(self):
        self.naming_patterns = [
            (r'contract\s+[a-z][A-Z]', 'Mixed case contract name'),
            (r'contract\s+[A-Z][a-z]', 'Inconsistent contract naming'),
            (r'contract\s+\w+\d+$', 'Contract name ends with number'),
        ]
    
    def get_detector_id(self) -> str:
        return "LOW_NAMING_001"
    
    def detect(self, source_code: str, contract_name: str) -> List[LowSeverityIssue]:
        issues = []
        
        if not contract_name[0].isupper():
            issue = LowSeverityIssue(
                issue_type=LowSeverityIssueType.CODE_READABILITY,
                severity_score=1.0,
                priority=IssuePriority.TRIVIAL,
                contract_name=contract_name,
                function_name=None,
                line_number=1,
                code_snippet=f"contract {contract_name}",
                title="Non-Standard Naming",
                description="Contract should use CapWords naming convention.",
                suggestion="Use CapWords (e.g., MyContract, Not myContract)",
                refactoring_effort="Low"
            )
            issues.append(issue)
        
        return issues


class LowSeverityEngine:
    def __init__(self):
        self.detectors: List[LowDetectorBase] = [
            GasOptimizationDetector(),
            DeprecatedUsageDetector(),
            MissingDocumentationDetector(),
            HardcodedValuesDetector(),
            UnusedModifierDetector(),
            ContractNamingDetector(),
        ]
        self.issues: List[LowSeverityIssue] = []
    
    def register_detector(self, detector: LowDetectorBase):
        self.detectors.append(detector)
    
    def scan_contract(self, source_code: str, contract_name: str = "Contract") -> List[LowSeverityIssue]:
        self.issues.clear()
        
        for detector in self.detectors:
            try:
                issues = detector.detect(source_code, contract_name)
                self.issues.extend(issues)
            except Exception as e:
                logger.error(f"Error in {detector.get_detector_id()}: {e}")
        
        return self.issues
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'summary': {
                'total_issues': len(self.issues),
                'gas_savings_potential': sum(i.gas_savings or 0 for i in self.issues),
            },
            'issues': [i.to_dict() for i in self.issues]
        }


def analyze_low_severity(source_code: str, contract_name: str = "Contract") -> Dict[str, Any]:
    engine = LowSeverityEngine()
    engine.scan_contract(source_code, contract_name)
    return engine.generate_report()


if __name__ == '__main__':
    sample = """
    pragma solidity ^0.8.0;
    
    contract example {
        uint256 public totalSupply = 1000000;
        
        function test() public {
            uint256 x = 10 * 1;
        }
    }
    """
    
    report = analyze_low_severity(sample, "example")
    print(json.dumps(report, indent=2))