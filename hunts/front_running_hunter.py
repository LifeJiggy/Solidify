"""
SoliGuard Front-Running Hunter
Hunt for front-running vulnerabilities with comprehensive detection

Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for front-running vulnerabilities in smart contracts
"""

import re
import logging
import json
import hashlib
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class FrontRunningPattern(Enum):
    UNPROTECTED_TX = "unprotected_tx"
    SENSITIVE_FUNCTION = "sensitive_function"
    AMOUNT_DISCLOSURE = "amount_disclosure"
    LINEAR_PRICING = "linear_pricing"
    PUBLIC_MEMPOOL = "public_mempool"
    ORDER_MATCHING = "order_matching"
    BATCH_TRADE = "batch_trade"
    AIRDROP_CLAIM = "airdrop_claim"
    VULNERABLE_SETTER = "vulnerable_setter"
    TIMING_DEPENDENT = "timing_dependent"
    SLIPPAGE_NOT_SET = "slippage_not_set"
    FRONT_RUNABLE = "front_runable"


class FrontRunningSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"
    PENDING = "pending"


@dataclass
class FrontRunningFinding:
    pattern: FrontRunningPattern
    severity: FrontRunningSeverity
    function: str
    description: str
    line_number: int
    exposure_vector: str
    recommendation: str
    code_snippet: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    affected_users: int = 0
    potential_loss: str = "unknown"


@dataclass
class FunctionAnalysis:
    name: str
    external_calls: List[str] = field(default_factory=list)
    has_access_control: bool = False
    is_public: bool = False
    is_external: bool = False
    reads_sensitive_data: bool = False
    modifies_state: bool = False
    has_timing_dependency: bool = False
    has_value_fields: bool = False
    lines: List[str] = field(default_factory=list)


@dataclass 
class ExploitScenario:
    name: str
    description: str
    preconditions: List[str] = field(default_factory=list)
    attack_steps: List[str] = field(default_factory=list)
    expected_impact: str = ""
    complexity: str = "medium"
    PoC_code: str = ""


FRONT_RUNNING_PATTERNS = {
    "sensitive_function_public": {
        "pattern": r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+\b(public|external)\b",
        "severity": "high",
        "description": "Sensitive function exposed as public",
        "cwe": "CWE-862",
        "cvss": 7.5,
        "impact": "Transaction can be frontrun by observing mempool"
    },
    "value_in_public_function": {
        "pattern": r"(amount|value|quantity|price)\s*[=:]",
        "severity": "high",
        "description": "Value parameter visible in mempool",
        "cwe": "CWE-200",
        "cvss": 7.0,
        "impact": "Attackers can see transaction values"
    },
    "no_slippage_protection": {
        "pattern": r"(swap|trade|exchange)\s*\([^)]*\)\s*;[^}]*?(?!slippage|minAmount|minOutput)",
        "severity": "critical",
        "description": "No slippage protection on swaps",
        "cwe": "CWE-695",
        "cvss": 8.5,
        "impact": "Sandwich attacks can extract value"
    },
    "linear_price_calculation": {
        "pattern": r"price\s*[=\\/]\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\*\s*\d+",
        "severity": "medium",
        "description": "Linear pricing vulnerable to manipulation",
        "cwe": "CWE-754",
        "cvss": 6.5,
        "impact": "Price can be manipulated before transaction"
    },
    "public_memorializer": {
        "pattern": r"(emit|event)\s+([A-Z][a-zA-Z0-9]*)",
        "severity": "medium",
        "description": "Public events disclose sensitive data",
        "cwe": "CWE-200",
        "cvss": 5.5,
        "impact": "Transaction details visible on-chain"
    },
    "batch_transaction_vulnerable": {
        "pattern": r"(batch|multi|execute)\s*\(\s*[^)]*amounts)",
        "severity": "high",
        "description": "Batch transactions can be frontrun",
        "cwe": "CWE-362",
        "cvss": 8.0,
        "impact": "Attacker can bundle transactions ahead"
    },
    "setter_without_timelock": {
        "pattern": r"function\s+(set|update|change)[\w]*\s*\([^)]*\)",
        "severity": "high",
        "description": "Critical setter without timelock",
        "cwe": "CWE-362",
        "cvss": 7.5,
        "impact": "Parameters can be front-run"
    },
    "claim_without_delay": {
        "pattern": r"(claim|withdraw|harvest)\s*\([^)]*\)",
        "severity": "medium",
        "description": "Claim function without delay",
        "cwe": "CWE-362",
        "cvss": 6.5,
        "impact": "MEV extractor can steal airdrops"
    },
    "order_execution_visible": {
        "pattern": r"(order|swap|trade)\s*\.\s*fill|execute\(",
        "severity": "high",
        "description": "Order execution visible in mempool",
        "cwe": "CWE-200",
        "cvss": 7.0,
        "impact": "Orders can be frontrun"
    },
    "airdrop_claim_public": {
        "pattern": r"function\s+claim\s*\([^)]*\)\s*public",
        "severity": "critical",
        "description": "Public airdrop claim vulnerable to botting",
        "cwe": "CWE-770",
        "cvss": 8.8,
        "impact": "Bots frontrun legitimate claimers"
    },
    "fee_calculation_external": {
        "pattern": r"(fee|commission|spread)\s*[=:]\s*[^;]+\.(call|staticcall)",
        "severity": "high",
        "description": "External fee calculation can be manipulated",
        "cwe": "CWE-754",
        "cvss": 7.5,
        "impact": "Fee can be manipulated"
    },
    "timestamp_dependency": {
        "pattern": r"(block\.timestamp|now)\s*[=+\-]",
        "severity": "medium",
        "description": "Timestamp dependency in critical logic",
        "cwe": "CWE-386",
        "cvss": 6.0,
        "impact": "Miner can manipulate timestamps"
    },
}


SENSITIVE_FUNCTIONS = [
    "setPrice",
    "updateFee",
    "adjustParameter",
    "changeAdmin",
    "upgrade",
    "_set",
    "setReserveFactor",
    "setCollateralFactor",
    "claim",
    "withdraw",
    "harvest",
    "swap",
    "trade",
    "execute",
    "batch",
]

MEV_EXTRACTABLE_PATTERNS = [
    r"(swapExactETHForTokens|swapExactTokensForETH)",
    r"( Uniswap|V2).*(swap|exchange)",
    r"(balanceOf.*transfer|transfer.*balanceOf)",
    r"(approve.*transferFrom|transferFrom.*balanceOf)",
    r"\.(flashLoan|flashBorrow)",
]

VULNERABLE_SETTERS = [
    r"function\s+set\w*\s*\([^)]*\)\s*public",
    r"function\s+update\w*\s*\([^)]*\)\s*external",
    r"function\s+_\set\w*\s*\([^)]*\)",
    r"function\s+adjust\s*\([^)]*\)",
]


@dataclass
class TransactionAnalysis:
    tx_hash: str = ""
    from_address: str = ""
    to_address: str = ""
    value: int = 0
    gas_price: int = 0
    timestamp: int = 0
    block_number: int = 0
    is_sensitive: bool = False
    has_protection: bool = False


@dataclass
class MEVExtractionVector:
    attack_type: str = ""
    description: str = ""
    required_gas: int = 0
    potential_profit: float = 0.0
    complexity: str = "unknown"


class FrontRunningHunter:
    def __init__(self):
        self.findings: List[FrontRunningFinding] = []
        self.sensitive_functions: Dict[str, FunctionAnalysis] = {}
        self.vulnerable_patterns: Set[str] = set()
        self.mev_analysis: List[MEVExtractionVector] = []
        self.analysis_cache: Dict[str, Any] = {}
        
    def hunt(self, source_code: str, file_name: str = "") -> List[FrontRunningFinding]:
        logger.info(f"Hunting for front-running vulnerabilities in {file_name}")
        
        self.findings.clear()
        self._parse_functions(source_code)
        self._detect_sensitive_functions(source_code)
        self._check_front_running_patterns(source_code)
        self._analyze_mev_extraction(source_code)
        self._check_slippage_protection(source_code)
        
        return self.findings
    
    def _parse_functions(self, source_code: str) -> None:
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            func_match = re.search(
                r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*(public|external|internal|private|view|payable)?",
                line_stripped
            )
            
            if func_match:
                func_name = func_match.group(1)
                visibility = func_match.group(3) or "external"
                
                func_analysis = FunctionAnalysis(
                    name=func_name,
                    is_public=visibility == "public",
                    is_external=visibility == "external",
                    lines=[line]
                )
                
                self.sensitive_functions[func_name] = func_analysis
                
    def _detect_sensitive_functions(self, source_code: str) -> None:
        lines = source_code.split('\n')
        
        for pattern_name, pattern_info in FRONT_RUNNING_PATTERNS.items():
            pattern = pattern_info["pattern"]
            severity_str = pattern_info["severity"]
            description = pattern_info["description"]
            cwe = pattern_info["cwe"]
            cvss = pattern_info["cvss"]
            impact = pattern_info["impact"]
            
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    severity = self._parse_severity(severity_str)
                    
                    func_name = self._extract_function_name(line, lines, line_num)
                    
                    if func_name in self.sensitive_functions:
                        self.sensitive_functions[func_name].has_access_control = True
                        self.sensitive_functions[func_name].reads_sensitive_data = True
                        
                    finding = FrontRunningFinding(
                        pattern=self._get_pattern_type(pattern_name),
                        severity=severity,
                        function=func_name,
                        description=description,
                        line_number=line_num,
                        exposure_vector=impact,
                        recommendation=self._generate_recommendation(pattern_name),
                        code_snippet=line.strip(),
                        cvss_score=cvss,
                        cwe_id=cwe,
                        status=VulnerabilityStatus.CONFIRMED
                    )
                    self.findings.append(finding)
                    
    def _check_front_running_patterns(
        self, source_code: str
    ) -> None:
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            for sensitive_func in SENSITIVE_FUNCTIONS:
                if sensitive_func.lower() in line_stripped.lower():
                    if self._is_public_visible(line, lines, line_num):
                        severity = FrontRunningSeverity.HIGH
                        if sensitive_func in ["claim", "withdraw"]:
                            severity = FrontRunningSeverity.CRITICAL
                            
                        finding = FrontRunningFinding(
                            pattern=FrontRunningPattern.SENSITIVE_FUNCTION,
                            severity=severity,
                            function=sensitive_func,
                            description=f"Sensitive function {sensitive_func} visible in mempool",
                            line_number=line_num,
                            exposure_vector="Transaction can be observed and frontrun",
                            recommendation=f"Consider private transactions or commit-reveal scheme",
                            cvss_score=7.5,
                            cwe_id="CWE-862",
                            status=VulnerabilityStatus.CONFIRMED
                        )
                        self.findings.append(finding)
                        
    def _analyze_mev_extraction(self, source_code: str) -> None:
        mev_patterns = [
            ("Uniswap Swap", r"swapExact\w+\For\w+", "Sandwich attack on swap", 5000),
            ("Token Transfer", r"transfer\([^)]+\)", "Transfer frontrun", 1000),
            ("Flash Loan", r"flashLoan\(", "Flash loan MEV", 10000),
            ("Order Fill", r"fillOrder\(", "Order sniping", 2000),
        ]
        
        for pattern_name, pattern, description, profit in mev_patterns:
            if re.search(pattern, source_code):
                vector = MEVExtractionVector(
                    attack_type=pattern_name,
                    description=description,
                    potential_profit=profit,
                    complexity="medium"
                )
                self.mev_analysis.append(vector)
                
    def _check_slippage_protection(self, source_code: str) -> None:
        swap_related = re.findall(
            r"(swap|exchange|trade)\s*\([^)]+\)", 
            source_code,
            re.IGNORECASE
        )
        
        if not swap_related:
            return
            
        has_slippage = bool(
            re.search(r"(minOutput|minAmount|slippage|minToken)", source_code)
        )
        
        if not has_slippage:
            for match in swap_related:
                line = ""
                for l in source_code.split('\n'):
                    if match in l:
                        line = l
                        break
                        
                finding = FrontRunningFinding(
                    pattern=FrontRunningPattern.NO_SLIPPAGE_PROTECTION,
                    severity=FrontRunningSeverity.CRITICAL,
                    function=match.split('(')[0],
                    description="Swap without slippage protection",
                    line_number=0,
                    exposure_vector="Sandwich attack can extract value",
                    recommendation="Add minOutput amount or slippage tolerance",
                    cvss_score=8.5,
                    cwe_id="CWE-695",
                    status=VulnerabilityStatus.CONFIRMED
                )
                self.findings.append(finding)
                
    def _is_public_visible(
        self, line: str, lines: List[str], line_num: int
    ) -> bool:
        search_start = max(0, line_num - 5)
        search_end = min(len(lines), line_num + 3)
        
        for i in range(search_start, search_end):
            if "public" in lines[i] or "external" in lines[i]:
                return True
                
        return False
        
    def _extract_function_name(
        self, line: str, lines: List[str], line_num: int
    ) -> str:
        search_start = max(0, line_num - 10)
        search_end = min(len(lines), line_num + 5)
        
        for i in range(search_start, search_end):
            func_match = re.search(r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)", lines[i])
            if func_match:
                return func_match.group(1)
                
        return "unknown"
        
    def _parse_severity(self, severity_str: str) -> FrontRunningSeverity:
        mapping = {
            "critical": FrontRunningSeverity.CRITICAL,
            "high": FrontRunningSeverity.HIGH,
            "medium": FrontRunningSeverity.MEDIUM,
            "low": FrontRunningSeverity.LOW,
            "info": FrontRunningSeverity.INFO,
        }
        return mapping.get(severity_str.lower(), FrontRunningSeverity.MEDIUM)
        
    def _get_pattern_type(self, pattern_name: str) -> FrontRunningPattern:
        mapping = {
            "sensitive_function_public": FrontRunningPattern.SENSITIVE_FUNCTION,
            "value_in_public_function": FrontRunningPattern.AMOUNT_DISCLOSURE,
            "no_slippage_protection": FrontRunningPattern.SLIPPAGE_NOT_SET,
            "linear_price_calculation": FrontRunningPattern.LINEAR_PRICING,
            "public_memorializer": FrontRunningPattern.PUBLIC_MEMPOOL,
            "batch_transaction_vulnerable": FrontRunningPattern.BATCH_TRADE,
            "setter_without_timelock": FrontRunningPattern.VULNERABLE_SETTER,
            "claim_without_delay": FrontRunningPattern.AIRDROP_CLAIM,
            "order_execution_visible": FrontRunningPattern.ORDER_MATCHING,
            "airdrop_claim_public": FrontRunningPattern.AIRDROP_CLAIM,
            "fee_calculation_external": FrontRunningPattern.LINEAR_PRICING,
            "timestamp_dependency": FrontRunningPattern.TIMING_DEPENDENT,
        }
        return mapping.get(pattern_name, FrontRunningPattern.FRONT_RUNABLE)
        
    def _generate_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "sensitive_function_public": (
                "Use private functions where possible. "
                "Consider using commit-reveal scheme for sensitive operations."
            ),
            "value_in_public_function": (
                "Hide amount values using cryptographic commitments."
            ),
            "no_slippage_protection": (
                "Implement minimum output amount (minOutput) protection."
            ),
            "linear_price_calculation": (
                "Use TWAP or oracle-based pricing to resist manipulation."
            ),
            "public_memorializer": (
                "Use encrypted events or move sensitive data off-chain."
            ),
            "batch_transaction_vulnerable": (
                "Implement transaction batching with cryptographic ordering."
            ),
            "setter_without_timelock": (
                "Add timelock delay for critical parameter changes."
            ),
            "claim_without_delay": (
                "Implement claim delay or gradual unlocking."
            ),
            "order_execution_visible": (
                "Use batch auctions or random matching to prevent frontrunning."
            ),
            "airdrop_claim_public": (
                "Implement merkle tree claiming or commitment scheme."
            ),
            "fee_calculation_external": (
                "Make fee calculation deterministic and on-chain."
            ),
            "timestamp_dependency": (
                "Use block numbers instead of timestamps for critical timing."
            ),
        }
        return recommendations.get(pattern_name, "Review transaction visibility.")
        
    def generate_report(self) -> Dict[str, Any]:
        severity_counts = Counter(f.severity.value for f in self.findings)
        
        return {
            "hunter": "Front-Running Hunter",
            "total_findings": len(self.findings),
            "severity_breakdown": dict(severity_counts),
            "findings": [
                {
                    "pattern": f.pattern.value,
                    "severity": f.severity.value,
                    "function": f.function,
                    "description": f.description,
                    "line_number": f.line_number,
                    "recommendation": f.recommendation,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                }
                for f in self.findings
            ],
            "mev_vectors": [
                {
                    "attack_type": v.attack_type,
                    "description": v.description,
                    "potential_profit": v.potential_profit,
                    "complexity": v.complexity,
                }
                for v in self.mev_analysis
            ],
            "sensitive_functions": list(self.sensitive_functions.keys()),
        }
        
    def get_critical_findings(self) -> List[FrontRunningFinding]:
        return [f for f in self.findings if f.severity == FrontRunningSeverity.CRITICAL]
        
    def get_high_findings(self) -> List[FrontRunningFinding]:
        return [f for f in self.findings if f.severity == FrontRunningSeverity.HIGH]
        
    def get_mev_analysis(self) -> List[MEVExtractionVector]:
        return self.mev_analysis
        
    def export_findings_json(self, output_path: str) -> None:
        report = self.generate_report()
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"Exported findings to {output_path}")
        
    def export_findings_sarif(self, output_path: str) -> None:
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SoliGuard Front-Running Hunter",
                            "rules": [
                                {
                                    "id": f.cwe_id or f.pattern.value,
                                    "name": f.pattern.value,
                                    "shortDescription": {
                                        "text": f.description
                                    },
                                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe_id.replace('CWE-', '')}.html"
                                }
                                for f in self.findings
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.cwe_id or f.pattern.value,
                            "level": "error" if f.severity == FrontRunningSeverity.CRITICAL else "warning",
                            "message": {
                                "text": f.description
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": f.function
                                        }
                                    }
                                }
                            ]
                        }
                        for f in self.findings
                    ]
                }
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)
            
        logger.info(f"Exported SARIF results to {output_path}")