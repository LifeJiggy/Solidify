"""
Solidify Analysis Rules
Analysis rules for smart contract security scanning

Author: Peace Stephen (Tech Lead)
Description: Comprehensive analysis rules for contract scanning
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


class AnalysisType(Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    SYMBOLIC = "symbolic"
    MANUAL = "manual"
    AUTOMATED = "automated"


class FindingType(Enum):
    VULNERABILITY = "vulnerability"
    CODE_QUALITY = "code_quality"
    BEST_PRACTICE = "best_practice"
    INFORMATION = "information"
    WARNING = "warning"


class AnalysisPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class AnalysisRule:
    rule_id: str
    name: str
    description: str
    analysis_type: AnalysisType
    finding_type: FindingType
    priority: AnalysisPriority
    pattern: str
    severity: str
    cwe_id: str = ""
    mitre_id: str = ""


@dataclass
class AnalysisFinding:
    rule: AnalysisRule
    location: str
    line_number: int
    code: str
    message: str
    confidence: float = 0.0


ANALYSIS_RULES = [
    AnalysisRule(
        rule_id="AN001",
        name="Unprotected Selfdestruct",
        description="Function callable by anyone can destroy contract",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.CRITICAL,
        pattern=r"selfdestruct\s*\(",
        severity="critical",
        cwe_id="CWE-506",
        mitre_id="T1486"
    ),
    AnalysisRule(
        rule_id="AN002",
        name="Unlimited Minting",
        description="Minting function lacks proper access control",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.CRITICAL,
        pattern=r"function\s+mint\s*\([^)]*public",
        severity="critical",
        cwe_id="CWE-770",
        mitre_id="T1486"
    ),
    AnalysisRule(
        rule_id="AN003",
        name="Insecure Randomness",
        description="Randomness can be predicted",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.HIGH,
        pattern=r"block\.blockhash\s*\(",
        severity="high",
        cwe_id="CWE-338",
        mitre_id="T1490"
    ),
    AnalysisRule(
        rule_id="AN004",
        name="Dangerous Delegatecall",
        description="Use of delegatecall to untrusted contract",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.HIGH,
        pattern=r"delegatecall\s*\(",
        severity="high",
        cwe_id="CWE-827",
        mitre_id="T1190"
    ),
    AnalysisRule(
        rule_id="AN005",
        name="Integer Overflow",
        description="Potential integer overflow in arithmetic",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.HIGH,
        pattern=r"\+\s*\w+\s*\+\s*\w+",
        severity="high",
        cwe_id="CWE-190",
        mitre_id="T1490"
    ),
    AnalysisRule(
        rule_id="AN006",
        name="Missing Access Control",
        description="Missing access control on privileged function",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.HIGH,
        pattern=r"function\s+(?:set|update|admin)\s*\([^)]*external(?!.*only)",
        severity="high",
        cwe_id="CWE-862",
        mitre_id="T1190"
    ),
    AnalysisRule(
        rule_id="AN007",
        name="Unchecked Return Value",
        description="Return value not checked",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.MEDIUM,
        pattern=r"\.call\s*\([^)]*\)\s*;",
        severity="medium",
        cwe_id="CWE-754",
        mitre_id="T1190"
    ),
    AnalysisRule(
        rule_id="AN008",
        name="Approval Insecurity",
        description="Unlimited token approval",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.MEDIUM,
        pattern=r"approve\s*\(\s*\w+\s*,\s*uint256\(\s*-\s*1",
        severity="medium",
        cwe_id="CWE-770",
        mitre_id="T1486"
    ),
    AnalysisRule(
        rule_id="AN009",
        name="Reentrancy Bug",
        description="Potential reentrancy vulnerability",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.HIGH,
        pattern=r"\.call\s*\([^)]*value\s*\(",
        severity="high",
        cwe_id="CWE-362",
        mitre_id="T1190"
    ),
    AnalysisRule(
        rule_id="AN010",
        name="Weak Ownership",
        description="tx.origin used for authorization",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.MEDIUM,
        pattern=r"tx\.origin\s*==",
        severity="medium",
        cwe_id="CWE-862",
        mitre_id="T1190"
    ),
    AnalysisRule(
        rule_id="AN011",
        name="Floating Pragma",
        description="Using floating pragma version",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.CODE_QUALITY,
        priority=AnalysisPriority.LOW,
        pattern=r"pragma\s+solidity\s+\^",
        severity="low",
        cwe_id="CWE-1104"
    ),
    AnalysisRule(
        rule_id="AN012",
        name="Unused Local Variable",
        description="Declared variable not used",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.CODE_QUALITY,
        priority=AnalysisPriority.INFO,
        pattern=r"uint\d*\s+\w+\s*;(?!\s*//)",
        severity="info"
    ),
    AnalysisRule(
        rule_id="AN013",
        name="Missing NatSpec",
        description="Missing documentation",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.BEST_PRACTICE,
        priority=AnalysisPriority.LOW,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*public(?!\s*/\*\*|\s*///)",
        severity="low"
    ),
    AnalysisRule(
        rule_id="AN014",
        name="Long Function",
        description="Function exceeds recommended length",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.CODE_QUALITY,
        priority=AnalysisPriority.LOW,
        pattern=r"function\s+\w+\s*\([^)]*\)\s*\{[^}]{500,}",
        severity="low"
    ),
    AnalysisRule(
        rule_id="AN015",
        name="Todo Comment",
        description="TODO comment in code",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.INFORMATION,
        priority=AnalysisPriority.INFO,
        pattern=r"//\s*TODO",
        severity="info"
    ),
    AnalysisRule(
        rule_id="AN016",
        name="Ether Balance Check",
        description="Contract checks ether balance",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.VULNERABILITY,
        priority=AnalysisPriority.MEDIUM,
        pattern=r"address\s*\(\s*this\s*\)\s*\.\s*balance",
        severity="medium"
    ),
    AnalysisRule(
        rule_id="AN017",
        name="Deprecated Usage",
        description="Using deprecated features",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.CODE_QUALITY,
        priority=AnalysisPriority.LOW,
        pattern=r"(?:suicide|block\.coinbase|block\.difficulty)",
        severity="low"
    ),
    AnalysisRule(
        rule_id="AN018",
        name="Event Emit Timing",
        description="Event emitted before state change",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.BEST_PRACTICE,
        priority=AnalysisPriority.MEDIUM,
        pattern=r"emit[^{]*\{[^}]*\.call",
        severity="medium"
    ),
    AnalysisRule(
        rule_id="AN019",
        name="Storage Array Length",
        description="Cache array length in loop",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.BEST_PRACTICE,
        priority=AnalysisPriority.MEDIUM,
        pattern=r"for\s*\([^)]*\.\w+\.length[^)]*\{",
        severity="medium"
    ),
    AnalysisRule(
        rule_id="AN020",
        name="Immutable Declaration",
        description="Use immutable for contract variables",
        analysis_type=AnalysisType.STATIC,
        finding_type=FindingType.BEST_PRACTICE,
        priority=AnalysisPriority.LOW,
        pattern=r"immutable\s+(?!\w+)",
        severity="low"
    ),
]


class AnalysisRuleEngine:
    def __init__(self):
        self.rules: Dict[str, AnalysisRule] = {}
        self.findings: List[AnalysisFinding] = []
        
    def register_rule(self, rule: AnalysisRule) -> None:
        self.rules[rule.rule_id] = rule
        
    def analyze(self, source_code: str) -> List[AnalysisFinding]:
        results = []
        
        for rule in self.rules.values():
            pattern = re.compile(rule.pattern, re.MULTILINE)
            
            for match in pattern.finditer(source_code):
                line_number = source_code[:match.start()].count('\n') + 1
                
                finding = AnalysisFinding(
                    rule=rule,
                    location="",
                    line_number=line_number,
                    code=source_code.split('\n')[line_number - 1],
                    message=rule.description,
                    confidence=0.85
                )
                results.append(finding)
                
        self.findings.extend(results)
        return results
    
    def get_findings_by_priority(self, priority: AnalysisPriority) -> List[AnalysisFinding]:
        return [f for f in self.findings if f.rule.priority == priority]
    
    def get_findings_by_type(self, finding_type: FindingType) -> List[AnalysisFinding]:
        return [f for f in self.findings if f.rule.finding_type == finding_type]
    
    def get_stats(self) -> Dict[str, Any]:
        by_priority = {p.name: len(self.get_findings_by_priority(p)) for p in AnalysisPriority}
        by_type = {t.name: len(self.get_findings_by_type(t)) for t in FindingType}
        
        return {
            "total_rules": len(self.rules),
            "total_findings": len(self.findings),
            "by_priority": by_priority,
            "by_type": by_type
        }


def initialize_analysis_rules() -> AnalysisRuleEngine:
    engine = AnalysisRuleEngine()
    
    for rule in ANALYSIS_RULES:
        engine.register_rule(rule)
        
    return engine


def analyze_contract(source_code: str) -> List[AnalysisFinding]:
    engine = initialize_analysis_rules()
    return engine.analyze(source_code)


def get_analysis_stats() -> Dict[str, Any]:
    return initialize_analysis_rules().get_stats()


_default_analysis_engine: Optional[AnalysisRuleEngine] = None


def get_analysis_engine() -> AnalysisRuleEngine:
    global _default_analysis_engine
    
    if _default_analysis_engine is None:
        _default_analysis_engine = initialize_analysis_rules()
        
    return _default_analysis_engine