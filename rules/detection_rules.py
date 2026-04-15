"""
SoliGuard Detection Rules
Detection rules for smart contract vulnerability identification

Author: Peace Stephen (Tech Lead)
Description: Detection rules for smart contract security analysis
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


class DetectionCategory(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    ORACLE = "oracle"
    FRONT_RUNNING = "front_running"
    CENTRALIZATION = "centralization"
    DENIAL_OF_SERVICE = "denial_of_service"
    OTHER = "other"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    category: DetectionCategory
    severity: Severity
    pattern: str
    cwe_id: str = ""
    cvss_score: float = 0.0
    status: RuleStatus = RuleStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    rule: DetectionRule
    matched: bool
    line_number: int = 0
    code_snippet: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class DetectionRuleEngine:
    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.results: List[DetectionResult] = []
        
    def register_rule(self, rule: DetectionRule) -> None:
        self.rules[rule.rule_id] = rule
        try:
            self.compiled_patterns[rule.rule_id] = re.compile(rule.pattern, re.MULTILINE)
        except re.error:
            logger.warning(f"Invalid pattern for rule {rule.rule_id}")
            
    def detect(self, source_code: str) -> List[DetectionResult]:
        results = []
        
        for rule_id, pattern in self.compiled_patterns.items():
            rule = self.rules.get(rule_id)
            if not rule or rule.status != RuleStatus.ACTIVE:
                continue
                
            for match in pattern.finditer(source_code):
                line_number = source_code[:match.start()].count('\n') + 1
                
                result = DetectionResult(
                    rule=rule,
                    matched=True,
                    line_number=line_number,
                    code_snippet=source_code.split('\n')[line_number - 1] if line_number > 0 else "",
                    confidence=0.9,
                    metadata={"match": match.group(0)}
                )
                results.append(result)
                
        self.results.extend(results)
        return results
    
    def get_rules_by_category(self, category: DetectionCategory) -> List[DetectionRule]:
        return [r for r in self.rules.values() if r.category == category]
    
    def get_rules_by_severity(self, severity: Severity) -> List[DetectionRule]:
        return [r for r in self.rules.values() if r.severity == severity]
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self.rules),
            "active_rules": len([r for r in self.rules.values() if r.status == RuleStatus.ACTIVE]),
            "rules_by_category": {c.value: len(self.get_rules_by_category(c)) for c in DetectionCategory},
            "rules_by_severity": {s.value: len(self.get_rules_by_severity(s)) for s in Severity}
        }


REENTRANCY_RULES = [
    DetectionRule(
        rule_id="R001",
        name="External Call Before State Change",
        description="External call made before state changes, potential reentrancy",
        category=DetectionCategory.REENTRANCY,
        severity=Severity.CRITICAL,
        pattern=r"(?:\.call|\.transfer|\.send)\s*\([^)]*\)\s*;[^}]*?(?!\b(?:balance|mapping|state)",
        cwe_id="CWE-362",
        cvss_score=9.1
    ),
    DetectionRule(
        rule_id="R002",
        name="Recursive Call Pattern",
        description="Function calls itself recursively without proper guards",
        category=DetectionCategory.REENTRANCY,
        severity=Severity.CRITICAL,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*(?:public|external).*\{[^}]*\b\1\s*\(",
        cwe_id="CWE-362",
        cvss_score=8.5
    ),
    DetectionRule(
        rule_id="R003",
        name="Callback Function Without Guard",
        description="Callback function missing reentrancy protection",
        category=DetectionCategory.REENTRANCY,
        severity=Severity.CRITICAL,
        pattern=r"function\s+(?:onTokenReceived|onERC721Received|receive)\s*\([^)]*\).*\{(?!\breentrancy)",
        cwe_id="CWE-362",
        cvss_score=8.0
    ),
    DetectionRule(
        rule_id="R004",
        name="Write After External Call",
        description="State variable written after external call",
        category=DetectionCategory.REENTRANCY,
        severity=Severity.HIGH,
        pattern=r"\.call\s*\([^)]+\)\s*;[^}]*?[a-zA-Z_]\w*\s*\[.*\]\s*=",
        cwe_id="CWE-362",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="R005",
        name="Missing Reentrancy Guard",
        description="No reentrancy guard on withdrawal function",
        category=DetectionCategory.REENTRANCY,
        severity=Severity.HIGH,
        pattern=r"function\s+(?:withdraw|claim|transfer)\s*\([^)]*\).*\{(?!.*nonreentrant)",
        cwe_id="CWE-362",
        cvss_score=7.0
    ),
]


ACCESS_CONTROL_RULES = [
    DetectionRule(
        rule_id="AC001",
        name="Missing Access Control",
        description="Critical function without access control modifier",
        category=DetectionCategory.ACCESS_CONTROL,
        severity=Severity.CRITICAL,
        pattern=r"function\s+(?:setOwner|transferOwnership|upgrade|mint|burn)\s*\([^)]*\)\s*(?:public|external)(?!.*only",
        cwe_id="CWE-862",
        cvss_score=9.0
    ),
    DetectionRule(
        rule_id="AC002",
        name="Tx Origin Authorization",
        description="Using tx.origin for authorization",
        category=DetectionCategory.ACCESS_CONTROL,
        severity=Severity.CRITICAL,
        pattern=r"require\s*\(\s*tx\.origin\s*==\s*",
        cwe_id="CWE-862",
        cvss_score=8.5
    ),
    DetectionRule(
        rule_id="AC003",
        name="Public Burn Function",
        description="Burn function publicly accessible",
        category=DetectionCategory.ACCESS_CONTROL,
        severity=Severity.HIGH,
        pattern=r"function\s+burn\s*\([^)]*\)\s*(?:public|external)(?!.*only)",
        cwe_id="CWE-862",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="AC004",
        name="Unrestricted Selfdestruct",
        description="Selfdestruct without access control",
        category=DetectionCategory.ACCESS_CONTROL,
        severity=Severity.CRITICAL,
        pattern=r"(?:selfdestruct|suicide)\s*\([^)]*\)(?!.*require.*owner)",
        cwe_id="CWE-506",
        cvss_score=9.5
    ),
    DetectionRule(
        rule_id="AC005",
        name="Missing Owner Check",
        description="Critical operation without owner verification",
        category=DetectionCategory.ACCESS_CONTROL,
        severity=Severity.HIGH,
        pattern=r"function\s+\w+\s*\([^)]*\).*\{(?!\brequire\s*\(.*owner)",
        cwe_id="CWE-862",
        cvss_score=7.0
    ),
]


ARITHMETIC_RULES = [
    DetectionRule(
        rule_id="AR001",
        name="Integer Overflow",
        description="Potential integer overflow in addition",
        category=DetectionCategory.ARITHMETIC,
        severity=Severity.CRITICAL,
        pattern=r"\+\s*\w+\s*\[\s*\w+\s*\]\s*\+",
        cwe_id="CWE-190",
        cvss_score=8.5
    ),
    DetectionRule(
        rule_id="AR002",
        name="Integer Underflow",
        description="Potential integer underflow in subtraction",
        category=DetectionCategory.ARITHMETIC,
        severity=Severity.CRITICAL,
        pattern=r"(?:\w+\s*-\s*\w+\s*\[|\-\s*\w+\s*\[\s*\w+\s*\])",
        cwe_id="CWE-191",
        cvss_score=8.5
    ),
    DetectionRule(
        rule_id="AR003",
        name="Unchecked Math",
        description="Arithmetic operation without SafeMath",
        category=DetectionCategory.ARITHMETIC,
        severity=Severity.HIGH,
        pattern=r"\b(?:\+|-\|\*|/|%)\s*\b(?!\bSafeMath)",
        cwe_id="CWE-190",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="AR004",
        name="Division by Zero",
        description="Potential division by zero",
        category=DetectionCategory.ARITHMETIC,
        severity=Severity.HIGH,
        pattern=r"/\s*\w+\s*(?:\.|;|$)",
        cwe_id="CWE-369",
        cvss_score=7.0
    ),
    DetectionRule(
        rule_id="AR005",
        name="Unchecked Return Value",
        description="Return value of arithmetic operation unchecked",
        category=DetectionCategory.ARITHMETIC,
        severity=Severity.MEDIUM,
        pattern=r"\w+\s*\+=\s*\w+[^;]*(?!.*require)",
        cwe_id="CWE-190",
        cvss_score=6.0
    ),
]


ORACLE_RULES = [
    DetectionRule(
        rule_id="OR001",
        name="Single Source Oracle",
        description="Only one oracle source without fallback",
        category=DetectionCategory.ORACLE,
        severity=Severity.HIGH,
        pattern=r"(?:\w*[O|o]racle\w*\s*=\s*[^;]{10,50})(?!.* Aggregator|.*Chainlink)",
        cwe_id="CWE-757",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="OR002",
        name="Stale Price Data",
        description="Oracle without staleness check",
        category=DetectionCategory.ORACLE,
        severity=Severity.MEDIUM,
        pattern=r"latestRoundData\s*\(\s*\)(?!.*updatedAt|.*timestamp)",
        cwe_id="CWE-754",
        cvss_score=6.0
    ),
    DetectionRule(
        rule_id="OR003",
        name="Swap Price Oracle",
        description="Using Uniswap pair for price calculation",
        category=DetectionCategory.ORACLE,
        severity=Severity.HIGH,
        pattern=r"getReserves\s*\(\s*\)[\s\n]+(?:token[01]|reserve)",
        cwe_id="CWE-707",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="OR004",
        name="Block Timestamp Oracle",
        description="Using block timestamp for critical operations",
        category=DetectionCategory.ORACLE,
        severity=Severity.MEDIUM,
        pattern=r"block\.timestamp\s*(?:==|!=|>|<|>=|<=)",
        cwe_id="CWE-386",
        cvss_score=6.5
    ),
    DetectionRule(
        rule_id="OR005",
        name="Block Hash Randomness",
        description="Using block hash for randomness",
        category=DetectionCategory.ORACLE,
        severity=Severity.HIGH,
        pattern=r"block\.blockhash\s*\(\s*block\.number",
        cwe_id="CWE-337",
        cvss_score=7.0
    ),
]


FRONT_RUNNING_RULES = [
    DetectionRule(
        rule_id="FR001",
        name="No Slippage Protection",
        description="Swap without minimum output amount",
        category=DetectionCategory.FRONT_RUNNING,
        severity=Severity.CRITICAL,
        pattern=r"swap(?:Exact|ExactETH|ExactTokens)\w*\s*\([^)]*(?:(?!\bminOutput|\bminAmount|\bslippage))",
        cwe_id="CWE-695",
        cvss_score=8.5
    ),
    DetectionRule(
        rule_id="FR002",
        name="Public Batch Transaction",
        description="Public batch transaction vulnerable to front-running",
        category=DetectionCategory.FRONT_RUNNING,
        severity=Severity.HIGH,
        pattern=r"function\s+batch\s*\([^)]*\)\s*public",
        cwe_id="CWE-362",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="FR003",
        name="Public Airdrop Claim",
        description="Public airdrop claim function",
        category=DetectionCategory.FRONT_RUNNING,
        severity=Severity.MEDIUM,
        pattern=r"function\s+claim\s*\([^)]*\)\s*public",
        cwe_id="CWE-770",
        cvss_score=6.5
    ),
    DetectionRule(
        rule_id="FR004",
        name="Visible Transaction Value",
        description="Transaction value visible in mempool",
        category=DetectionCategory.FRONT_RUNNING,
        severity=Severity.MEDIUM,
        pattern=r"(?:amount|value|price)\s*=\s*\w+[\s(]",
        cwe_id="CWE-200",
        cvss_score=5.5
    ),
    DetectionRule(
        rule_id="FR005",
        name="Linear Pricing",
        description="Linear price calculation without TWAP",
        category=DetectionCategory.FRONT_RUNNING,
        severity=Severity.MEDIUM,
        pattern=r"price\s*=\s*(?:\w+\s*\*\s*\d+|\d+\s*\*\s*\w+)",
        cwe_id="CWE-754",
        cvss_score=6.0
    ),
]


CENTRALIZATION_RULES = [
    DetectionRule(
        rule_id="CE001",
        name="Single Owner",
        description="Single owner with full control",
        category=DetectionCategory.CENTRALIZATION,
        severity=Severity.HIGH,
        pattern=r"address\s+public\s+owner",
        cwe_id="CWE-862",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="CE002",
        name="Upgradeable Without Timelock",
        description="Upgradeable contract without timelock",
        category=DetectionCategory.CENTRALIZATION,
        severity=Severity.HIGH,
        pattern=r"upgradeTo\s*\([^)]*\)(?!.*timelock|.*delay)",
        cwe_id="CWE-754",
        cvss_score=8.0
    ),
    DetectionRule(
        rule_id="CE003",
        name="Admin Pausability",
        description="Contract can be paused by admin",
        category=DetectionCategory.CENTRALIZATION,
        severity=Severity.MEDIUM,
        pattern=r"function\s+(?:pause|unpause)\s*\([^)]*\).*onlyOwner",
        cwe_id="CWE-862",
        cvss_score=6.5
    ),
    DetectionRule(
        rule_id="CE004",
        name="Unlimited Minting",
        description="Unlimited token minting capability",
        category=DetectionCategory.CENTRALIZATION,
        severity=Severity.CRITICAL,
        pattern=r"function\s+mint\s*\([^)]*\)\s*(?:public|external)(?!.*onlyOwner)",
        cwe_id="CWE-770",
        cvss_score=9.0
    ),
    DetectionRule(
        rule_id="CE005",
        name="Admin Fee Setter",
        description="Admin can set fees arbitrarily",
        category=DetectionCategory.CENTRALIZATION,
        severity=Severity.MEDIUM,
        pattern=r"function\s+setFee\s*\([^)]*\)\s*onlyOwner",
        cwe_id="CWE-754",
        cvss_score=6.5
    ),
]


DENIAL_OF_SERVICE_RULES = [
    DetectionRule(
        rule_id="DOS001",
        name="Unbounded Loop",
        description="Looping over dynamic array without limit",
        category=DetectionCategory.DENIAL_OF_SERVICE,
        severity=Severity.HIGH,
        pattern=r"for\s*\([^)]*(?:\.length|\.balanceOf|length)\s*\)",
        cwe_id="CWE-834",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="DOS002",
        name="Reachable Selfdestruct",
        description="Contract can self-destruct from any address",
        category=DetectionCategory.DENIAL_OF_SERVICE,
        severity=Severity.CRITICAL,
        pattern=r"selfdestruct\s*\(\s*(?:msg\.sender|owner)",
        cwe_id="CWE-506",
        cvss_score=9.0
    ),
    DetectionRule(
        rule_id="DOS003",
        name="Unlimited Gas Consumption",
        description="Function without gas limit",
        category=DetectionCategory.DENIAL_OF_SERVICE,
        severity=Severity.MEDIUM,
        pattern=r"\.call\s*\(\s*\"([^\"]*)\"\).*(?!\bgwei|\bgas)",
        cwe_id="CWE-400",
        cvss_score=6.0
    ),
    DetectionRule(
        rule_id="DOS004",
        name="Recursive Call Without Limit",
        description="Recursive call without proper execution limits",
        category=DetectionCategory.DENIAL_OF_SERVICE,
        severity=Severity.HIGH,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{[^}]*\{[^}]*\1\s*\(",
        cwe_id="CWE-834",
        cvss_score=7.5
    ),
    DetectionRule(
        rule_id="DOS005",
        name="Accessing Deleted Array",
        description="Accessing array after deletion",
        category=DetectionCategory.DENIAL_OF_SERVICE,
        severity=Severity.LOW,
        pattern=r"delete\s+\w+\[.*\]\s*;.*\w+\[",
        cwe_id="CWE-369",
        cvss_score=4.0
    ),
]


def initialize_detection_rules() -> DetectionRuleEngine:
    engine = DetectionRuleEngine()
    
    for rule in REENTRANCY_RULES:
        engine.register_rule(rule)
        
    for rule in ACCESS_CONTROL_RULES:
        engine.register_rule(rule)
        
    for rule in ARITHMETIC_RULES:
        engine.register_rule(rule)
        
    for rule in ORACLE_RULES:
        engine.register_rule(rule)
        
    for rule in FRONT_RUNNING_RULES:
        engine.register_rule(rule)
        
    for rule in CENTRALIZATION_RULES:
        engine.register_rule(rule)
        
    for rule in DENIAL_OF_SERVICE_RULES:
        engine.register_rule(rule)
        
    return engine


def detect_vulnerabilities(source_code: str) -> List[DetectionResult]:
    engine = initialize_detection_rules()
    return engine.detect(source_code)


def get_detection_stats() -> Dict[str, Any]:
    engine = initialize_detection_rules()
    return engine.get_stats()


_default_detection_engine: Optional[DetectionRuleEngine] = None


def get_detection_engine() -> DetectionRuleEngine:
    global _default_detection_engine
    
    if _default_detection_engine is None:
        _default_detection_engine = initialize_detection_rules()
        
    return _default_detection_engine