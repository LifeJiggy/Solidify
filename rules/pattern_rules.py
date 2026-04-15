"""
SoliGuard Pattern Rules
Pattern matching rules for smart contract analysis

Author: Peace Stephen (Tech Lead)
Description: Pattern matching rules for vulnerability detection
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


class PatternType(Enum):
    VULNERABILITY = "vulnerability"
    CODE_SMELL = "code_smell"
    ANTI_PATTERN = "anti_pattern"
    BEST_PRACTICE = "best_practice"
    OPTIMIZATION = "optimization"


class PatternSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PatternRule:
    rule_id: str
    name: str
    description: str
    pattern_type: PatternType
    pattern: str
    severity: PatternSeverity
    examples: List[str] = field(default_factory=list)
    mitigation: str = ""


PATTERN_RULES = [
    PatternRule(
        rule_id="PAT001",
        name="Reentrancy Pattern",
        description="Detects potential reentrancy vulnerability pattern",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"(?:mapping|uint)\s+\w+\s*\[\s*\w+\s*\].*?(?:=>\s*)?(?:uint|mapping).*?\{.*?\.call\s*\(\s*[\s\S]*?\)\s*\.value",
        severity=PatternSeverity.CRITICAL,
        examples=["function withdraw() public { (bool sent,) = msg.sender.call{value: balance}("); balanceOf[msg.sender] = 0; }"],
        mitigation="Use Checks-Effects-Interactions pattern or reentrancy guard"
    ),
    PatternRule(
        rule_id="PAT002",
        name="Unchecked Call Return",
        description="Detects unchecked return value from external call",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"addr\.call\s*\([^)]*\)\s*;(?!\s*require)",
        severity=PatternSeverity.HIGH,
        examples=["addr.call(data);"],
        mitigation="Always check return value with require()"
    ),
    PatternRule(
        rule_id="PAT003",
        name="Integer Overflow Pattern",
        description="Detects potential integer overflow",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"(?:\w+\s*\+\s*\w+|\w+\s*-\s*\w+|\w+\s*\*\s*\w+)",
        severity=PatternSeverity.HIGH,
        examples=["amount + amount", "balance - fee"],
        mitigation="Use SafeMath library or Solidity 0.8+ checked arithmetic"
    ),
    PatternRule(
        rule_id="PAT004",
        name="Tx Origin Pattern",
        description="Detects tx.origin usage for authorization",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"tx\.origin\s*==",
        severity=PatternSeverity.MEDIUM,
        examples=["require(tx.origin == owner);"],
        mitigation="Use msg.sender instead of tx.origin"
    ),
    PatternRule(
        rule_id="PAT005",
        name="Floating Pragma Pattern",
        description="Detects floating pragma version",
        pattern_type=PatternType.CODE_SMELL,
        pattern=r"pragma\s+solidity\s+\^[0-9]+\.[0-9]+(?!\.[0-9])",
        severity=PatternSeverity.LOW,
        examples=["pragma solidity ^0.8.0;"],
        mitigation="Lock pragma version after testing"
    ),
    PatternRule(
        rule_id="PAT006",
        name="Unlimited Approval Pattern",
        description="Detects unlimited token approval",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"approve\s*\(\s*\w+\s*,\s*uint256\(\s*-\s*1\s*\)\s*\)",
        severity=PatternSeverity.MEDIUM,
        examples=["approve(token, type(uint256).max);"],
        mitigation="Set specific approval amount"
    ),
    PatternRule(
        rule_id="PAT007",
        name="Shadowing Pattern",
        description="Detects variable shadowing",
        pattern_type=PatternType.CODE_SMELL,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{[^}]*uint\w+\s+\w+\s*=",
        severity=PatternSeverity.MEDIUM,
        examples=["uint balance = 0; // shadows state variable"],
        mitigation="Use different variable name"
    ),
    PatternRule(
        rule_id="PAT008",
        name="Block Timestamp Dependency",
        description="Detects block.timestamp usage",
        pattern_type=PatternType.ANTI_PATTERN,
        pattern=r"block\.timestamp",
        severity=PatternSeverity.MEDIUM,
        examples=["block.timestamp"],
        mitigation="Use block.number for time-based logic"
    ),
    PatternRule(
        rule_id="PAT009",
        name="Selfdestruct Pattern",
        description="Detects selfdestruct usage",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"selfdestruct\s*\(",
        severity=PatternSeverity.CRITICAL,
        examples=["selfdestruct(payable(msg.sender));"],
        mitigation="Implement proper access control"
    ),
    PatternRule(
        rule_id="PAT010",
        name="Delegatecall Pattern",
        description="Detects delegatecall usage",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"delegatecall\s*\(",
        severity=PatternSeverity.HIGH,
        examples=["target.delegatecall(data);"],
        mitigation="Validate target contract carefully"
    ),
    PatternRule(
        rule_id="PAT011",
        name="Storage Array Loop Pattern",
        description="Detects storage array in loop",
        pattern_type=PatternType.OPTIMIZATION,
        pattern=r"for\s*\([^)]*\.length[^)]*\)\s*\{[^}]*\w+\[",
        severity=PatternSeverity.MEDIUM,
        examples=["for (uint i=0; i < array.length; i++)"],
        mitigation="Cache array length in memory"
    ),
    PatternRule(
        rule_id="PAT012",
        name="Constructor Missing Address Check",
        description="Detects missing zero address check",
        pattern_type=PatternType.BEST_PRACTICE,
        pattern=r"constructor\s*\([^)]*\)\s*\{(?!\s*require\s*\(\s*\w+\s*!=\s*address\(0\))",
        severity=PatternSeverity.MEDIUM,
        examples=["constructor(address _owner) { owner = _owner; }"],
        mitigation="Add require(owner != address(0));"
    ),
    PatternRule(
        rule_id="PAT013",
        name="Public Function Returning Storage",
        description="Detects public function returning storage pointer",
        pattern_type=PatternType.ANTI_PATTERN,
        pattern=r"function\s+\w+\s*\(\s*\)\s*public\s+returns\s*\(\s*(?:uint|mapping)",
        severity=PatternSeverity.MEDIUM,
        examples=["function get() public returns (uint) { return value; }"],
        mitigation="Return copy via memory"
    ),
    PatternRule(
        rule_id="PAT014",
        name="Ether Transfer Without Gas",
        description="Detects .transfer() with limited gas",
        pattern_type=PatternType.VULNERABILITY,
        pattern=r"\.transfer\s*\(",
        severity=PatternSeverity.MEDIUM,
        examples=["msg.sender.transfer(amount);"],
        mitigation="Use .call() with value instead"
    ),
    PatternRule(
        rule_id="PAT015",
        name="Return Value Not Used",
        description="Detects unused return value",
        pattern_type=PatternType.CODE_SMELL,
        pattern=r"[^require].*\.call\s*\([^)]*\)\s*;(?!\s*require)",
        severity=PatternSeverity.LOW,
        examples=["addr.call{value: 1 ether}(");"],
        mitigation="Check return value or use require"
    ),
    PatternRule(
        rule_id="PAT016",
        name="Unbounded Array Length",
        description="Detects dynamic array with unknown length",
        pattern_type=PatternType.ANTI_PATTERN,
        pattern=r"new\s+uint\[\s*\]\s*\(",
        severity=PatternSeverity.MEDIUM,
        examples=["new uint[]()"],
        mitigation="Set maximum array size"
    ),
    PatternRule(
        rule_id="PAT017",
        name="Unsafe Custom Error",
        description="Detects potentially unsafe custom error",
        pattern_type=PatternType.CODE_SMELL,
        pattern=r"error\s+\w+\s*\(",
        severity=PatternSeverity.INFO,
        examples=["error CustomError();"],
        mitigation="Use descriptive error names"
    ),
    PatternRule(
        rule_id="PAT018",
        name="Unused Event Index",
        description="Detects event without indexed parameters",
        pattern_type=PatternType.OPTIMIZATION,
        pattern=r"event\s+\w+\s*\(\s*(?!\w+\s+indexed))",
        severity=PatternSeverity.LOW,
        examples=["event Transfer(address from, address to);"],
        mitigation="Add indexed to parameters"
    ),
    PatternRule(
        rule_id="PAT019",
        name="Magic Number",
        description="Detects magic numbers in code",
        pattern_type=PatternType.CODE_SMELL,
        pattern=r"\b\d{4,}\b(?!\s*/)",
        severity=PatternSeverity.INFO,
        examples=["10000", "3600"],
        mitigation="Use named constants"
    ),
    PatternRule(
        rule_id="PAT020",
        name="Redundant Empty Check",
        description="Detects redundant zero address check",
        pattern_type=PatternType.CODE_SMELL,
        pattern=r"require\s*\(\s*\w+\s*!=\s*address\(0\)\s*\);.*require\s*\(\s*\w+\s*!=",
        severity=PatternSeverity.LOW,
        examples=["require(addr != address(0)); require(addr != address(0));"],
        mitigation="Remove duplicate checks"
    ),
]


class PatternMatchingEngine:
    def __init__(self):
        self.rules: Dict[str, PatternRule] = {}
        self.findings: List[Dict[str, Any]] = []
        
    def register_rule(self, rule: PatternRule) -> None:
        self.rules[rule.rule_id] = rule
        
    def match(self, source_code: str) -> List[Dict[str, Any]]:
        results = []
        
        for rule_id, rule in self.rules.items():
            try:
                pattern = re.compile(rule.pattern, re.MULTILINE | re.DOTALL)
                
                for match in pattern.finditer(source_code):
                    line_number = source_code[:match.start()].count('\n') + 1
                    
                    result = {
                        "rule_id": rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "pattern_type": rule.pattern_type.value,
                        "severity": rule.severity.value,
                        "line_number": line_number,
                        "matched": source_code.split('\n')[line_number - 1] if line_number > 0 else "",
                        "mitigation": rule.mitigation
                    }
                    results.append(result)
                    
            except re.error as e:
                logger.warning(f"Invalid pattern for {rule_id}: {e}")
                
        self.findings.extend(results)
        return results
    
    def get_findings_by_type(self, pattern_type: PatternType) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f.get("pattern_type") == pattern_type.value]
    
    def get_findings_by_severity(self, severity: PatternSeverity) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f.get("severity") == severity.value]
    
    def get_stats(self) -> Dict[str, Any]:
        by_type = {}
        by_severity = {}
        
        for pt in PatternType:
            by_type[pt.value] = len(self.get_findings_by_type(pt))
            
        for sev in PatternSeverity:
            by_severity[sev.value] = len(self.get_findings_by_severity(sev))
            
        return {
            "total_rules": len(self.rules),
            "total_matches": len(self.findings),
            "by_type": by_type,
            "by_severity": by_severity
        }


def initialize_pattern_rules() -> PatternMatchingEngine:
    engine = PatternMatchingEngine()
    
    for rule in PATTERN_RULES:
        engine.register_rule(rule)
        
    return engine


def match_patterns(source_code: str) -> List[Dict[str, Any]]:
    return initialize_pattern_rules().match(source_code)


def get_pattern_stats() -> Dict[str, Any]:
    return initialize_pattern_rules().get_stats()


_default_pattern_engine: Optional[PatternMatchingEngine] = None


def get_pattern_engine() -> PatternMatchingEngine:
    global _default_pattern_engine
    
    if _default_pattern_engine is None:
        _default_pattern_engine = initialize_pattern_rules()
        
    return _default_pattern_engine