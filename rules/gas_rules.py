"""
SoliGuard Gas Rules
Gas optimization rules for smart contracts

Author: Peace Stephen (Tech Lead)
Description: Gas optimization rules and best practices
"""

import re
import logging
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class GasImprovement(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class GasPattern(Enum):
    STORAGE_READ = "storage_read"
    STORAGE_WRITE = "storage_write"
    EXTERNAL_CALL = "external_call"
    INTERNAL_CALL = "internal_call"
    LOOP = "loop"
    EVENT = "event"
    STRING = "string"


@dataclass
class GasRule:
    rule_id: str
    name: str
    description: str
    pattern: str
    improvement: GasImprovement
    gas_saved: int
    recommendation: str
    severity: str = "medium"


@dataclass
class GasCheck:
    rule: GasRule
    found: bool
    line_number: int = 0
    code_snippet: str = ""
    estimated_savings: int = 0


GAS_RULES = [
    GasRule(
        rule_id="GAS001",
        name="Cache Storage Reads",
        description="Storage variables read multiple times should be cached in memory",
        pattern=r"(\w+)\s*=\s*\w+\[.*\].*?\{.*?\1\s*=\s*\w+\[",
        improvement=GasImprovement.HIGH,
        gas_saved=5000,
        recommendation="Cache storage value in memory variable"
    ),
    GasRule(
        rule_id="GAS002",
        name="Short Circuit Evaluation",
        description="Use short-circuit evaluation in require",
        pattern=r"require\s*\(\s*\w+\s*&&\s*\w+",
        improvement=GasImprovement.MEDIUM,
        gas_saved=100,
        recommendation="Order conditions by likelihood of failure"
    ),
    GasRule(
        rule_id="GAS003",
        name="Unchecked Loop Index",
        description="Loop index should be uint256 for overflow protection",
        pattern=r"for\s*\(\s*uint\d*\s+\w+",
        improvement=GasImprovement.LOW,
        gas_saved=50,
        recommendation="Use uint256 for loop counters"
    ),
    GasRule(
        rule_id="GAS004",
        name="Event Indexing",
        description="Index event parameters to reduce gas costs",
        pattern=r"event\s+\w+\s*\(\s*(?!\w+\s+indexed)",
        improvement=GasImprovement.LOW,
        gas_saved=500,
        recommendation="Add indexed to event parameters"
    ),
    GasRule(
        rule_id="GAS005",
        name="Constant State Variables",
        description="Use constant for immutable values",
        pattern=r"(?:\w+\s*=\s*\d+[^;]{0,30})(?!.*constant)",
        improvement=GasImprovement.HIGH,
        gas_saved=20000,
        recommendation="Mark as constant"
    ),
    GasRule(
        rule_id="GAS006",
        name="Immutable Variables",
        description="Use immutable for constructor-set values",
        pattern=r"immutable\s+(?!\w+)",
        improvement=GasImprovement.MEDIUM,
        gas_saved=15000,
        recommendation="Mark constructor-set values as immutable"
    ),
    GasRule(
        rule_id="GAS007",
        name="Calldata Usage",
        description="Use calldata instead of memory for external functions",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*public\s+memory",
        improvement=GasImprovement.MEDIUM,
        gas_saved=1000,
        recommendation="Use calldata for function parameters"
    ),
    GasRule(
        rule_id="GAS008",
        name="Custom Errors",
        description="Use custom errors instead of require strings",
        pattern=r'require\s*\(\s*[^,]+,\s*"',
        improvement=GasImprovement.MEDIUM,
        gas_saved=3000,
        recommendation="Use custom errors (revert CustomError())"
    ),
    GasRule(
        rule_id="GAS009",
        name="Bit Shifting",
        description="Use bit shifting instead of multiplication",
        pattern=r"\*\s*2\s*\)|\*\s*4\b|\*\s*8\b|\*\s*16\b|\*\s*32\b",
        improvement=GasImprovement.LOW,
        gas_saved=100,
        recommendation="Use bit shifting for powers of 2"
    ),
    GasRule(
        rule_id="GAS010",
        name="External Function Visibility",
        description="Use external instead of public for gas optimization",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*public(?!\s+returns)",
        improvement=GasImprovement.MEDIUM,
        gas_saved=200,
        recommendation="Use external for functions only called externally"
    ),
    GasRule(
        rule_id="GAS011",
        name="Empty Fallback",
        description="Use receive() function for ETH deposits",
        pattern=r"function\s+\\(\s*\)\s*external\s+\{[^}]*\}(?!\s*receive)",
        improvement=GasImprovement.LOW,
        gas_saved=2000,
        recommendation="Use receive() function"
    ),
    GasRule(
        rule_id="GAS012",
        name="Unchecked Math",
        description="Use unchecked for safe math operations",
        pattern=r"\+\s*\w+\s*\+.*\+\s*\w+",
        improvement=GasImprovement.MEDIUM,
        gas_saved=200,
        recommendation="Use unchecked for proven safe operations"
    ),
    GasRule(
        rule_id="GAS013",
        name="Struct Packing",
        description="Pack struct members efficiently",
        pattern=r"(?!\s*(?:uint128|uint128))struct\s+\w+\s*\{",
        improvement=GasImprovement.MEDIUM,
        gas_saved=5000,
        recommendation="Order members by size for storage packing"
    ),
    GasRule(
        rule_id="GAS014",
        name="Mappings vs Arrays",
        description="Use mappings instead of arrays when possible",
        pattern=r"mapping\s*\(\s*address.*",
        improvement=GasImprovement.HIGH,
        gas_saved=10000,
        recommendation="Use mappings for key-value lookups"
    ),
    GasRule(
        rule_id="GAS015",
        name="Delete vs Assign Zero",
        description="Use delete instead of assigning zero",
        pattern=r"\w+\s*=\s*0\s*;",
        improvement=GasImprovement.LOW,
        gas_saved=100,
        recommendation="Use delete keyword"
    ),
    GasRule(
        rule_id="GAS016",
        name="Library Usage",
        description="Use libraries for repeated code",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{(?=.*\w+\s*\([^)]*\);[^}]*function\s+\w+\s*\([^)]*)",
        improvement=GasImprovement.HIGH,
        gas_saved=5000,
        recommendation="Extract to library"
    ),
    GasRule(
        rule_id="GAS017",
        name="Fixed-Size Array",
        description="Use fixed-size arrays when size is known",
        pattern=r"new\s+uint\[\s*\]",
        improvement=GasImprovement.MEDIUM,
        gas_saved=500,
        recommendation="Use fixed-size array if size known"
    ),
    GasRule(
        rule_id="GAS018",
        name="Batch Transfers",
        description="Batch multiple transfers",
        pattern=r"for\s*\([^)]*\.length[^)]*\)[^{]*transfer",
        improvement=GasImprovement.HIGH,
        gas_saved=10000,
        recommendation="Batch transfers in single transaction"
    ),
    GasRule(
        rule_id="GAS019",
        name="Emit After State Change",
        description="Emit events after state changes",
        pattern=r"emit[^{]*\{[^}]*mapping",
        improvement=GasImprovement.LOW,
        gas_saved=100,
        recommendation="Emit events after state updates"
    ),
    GasRule(
        rule_id="GAS020",
        name="View Functions",
        description="Mark view functions as view",
        pattern=r"function\s+\w+\s*\([^)]*\)\s*public\s+returns(?!\s+view)",
        improvement=GasImprovement.MEDIUM,
        gas_saved=1,
        recommendation="Mark functions that don't modify state as view"
    ),
]


class GasRuleEngine:
    def __init__(self):
        self.rules: Dict[str, GasRule] = {}
        self.checks: List[GasCheck] = []
        
    def register_rule(self, rule: GasRule) -> None:
        self.rules[rule.rule_id] = rule
        
    def check(self, source_code: str) -> List[GasCheck]:
        results = []
        
        for rule_id, rule in self.rules.items():
            pattern = re.compile(rule.pattern)
            
            for match in pattern.finditer(source_code):
                line_number = source_code[:match.start()].count('\n') + 1
                
                check = GasCheck(
                    rule=rule,
                    found=True,
                    line_number=line_number,
                    code_snippet=source_code.split('\n')[line_number - 1],
                    estimated_savings=rule.gas_saved
                )
                results.append(check)
                
        self.checks.extend(results)
        return results
    
    def get_total_savings(self) -> int:
        return sum(check.estimated_savings for check in self.checks)
    
    def get_gas_warnings(self) -> Dict[str, List[str]]:
        warnings = defaultdict(list)
        
        for check in self.checks:
            if check.rule.improvement == GasImprovement.CRITICAL:
                warnings["critical"].append(check.rule.name)
            elif check.rule.improvement == GasImprovement.HIGH:
                warnings["high"].append(check.rule.name)
            elif check.rule.improvement == GasImprovement.MEDIUM:
                warnings["medium"].append(check.rule.name)
            elif check.rule.improvement == GasImprovement.LOW:
                warnings["low"].append(check.rule.name)
                
        return dict(warnings)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self.rules),
            "total_checks": len(self.checks),
            "total_savings": self.get_total_savings(),
            "warnings": self.get_gas_warnings()
        }


def initialize_gas_rules() -> GasRuleEngine:
    engine = GasRuleEngine()
    
    for rule in GAS_RULES:
        engine.register_rule(rule)
        
    return engine


def check_gas(source_code: str) -> List[GasCheck]:
    engine = initialize_gas_rules()
    return engine.check(source_code)


def get_gas_stats() -> Dict[str, Any]:
    return initialize_gas_rules().get_stats()


_default_gas_engine: Optional[GasRuleEngine] = None


def get_gas_engine() -> GasRuleEngine:
    global _default_gas_engine
    
    if _default_gas_engine is None:
        _default_gas_engine = initialize_gas_rules()
        
    return _default_gas_engine