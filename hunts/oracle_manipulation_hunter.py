"""
SoliGuard Oracle Manipulation Hunter
Hunt for oracle manipulation vulnerabilities with comprehensive detection

Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for oracle manipulation vulnerabilities in smart contracts
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


class OracleType(Enum):
    CHAINLINK = "chainlink"
    UNISWAP = "uniswap"
    BAND = "band"
    COMPOUND = "compound"
    AAVE = "aave"
    CUSTOM = "custom"
    FIXED = "fixed"
    WORDS = "words"
    WITCH = "witch"
    REDSTONE = "redstone"
    PYTH = "pyth"
    TWAP = "twap"


class OracleManipulationPattern(Enum):
    PRICE_ORACLE = "price_oracle"
    LIQUIDITY_CHECK = "liquidity_check"
    TIME_WEIGHTED = "time_weighted"
    SPOT_PRICE = "spot_price"
    AGGREGATION = "aggregation"
    STALE_DATA = "stale_data"
    MANIPULATION_RESISTANT = "manipulation_resistant"
    FLASH_LOAN = "flash_loan"
    SWAP_MANIPULATION = "swap_manipulation"
    TWAP_ORACLE = "twap_oracle"
    LP_TOKEN = "lp_token"
    ORACLE_FEED = "oracle_feed"


class OracleSeverity(Enum):
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
class OracleFinding:
    pattern: OracleManipulationPattern
    severity: OracleSeverity
    oracle_type: OracleType
    function: str
    description: str
    line_number: int
    price_feed: str
    manipulation_vector: str
    recommendation: str
    code_snippet: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING


@dataclass
class OracleAnalysis:
    name: str
    oracle_type: OracleType
    price_feeds: List[str] = field(default_factory=list)
    is_external: bool = False
    has_staleness_check: bool = False
    has_deviation_check: bool = False
    has_aggregation: bool = False
    uses_twap: bool = False
    uses_median: bool = False
    liquidity_threshold: int = 0
    staleness_threshold: int = 0
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


ORACLE_MANIPULATION_PATTERNS = {
    "price_oracle_external": {
        "pattern": r"(\.latestRoundData|getPrice|latestAnswer|latestTimestamp)\s*\(",
        "severity": "critical",
        "description": "External price oracle without staleness check",
        "cwe": "CWE-707",
        "cvss": 8.5,
        "impact": "Attacker can manipulate price feeds to profit from liquidations or arbitrage"
    },
    "swap_price_manipulation": {
        "pattern": r"(getReserves|token0|token1|totalSupply|balanceOf)\s*\.\s*(call|staticcall)",
        "severity": "critical",
        "description": "Swap-based price oracle susceptible to manipulation",
        "cwe": "CWE-707",
        "cvss": 9.0,
        "impact": "Attacker can manipulate token prices through large swaps"
    },
    "twap_no_manipulation_resistance": {
        "pattern": r"(twap|observe|increaseObservationCardinalityNext)\s*\(",
        "severity": "high",
        "description": "TWAP oracle without full manipulation resistance",
        "cwe": "CWE-707",
        "cvss": 7.5,
        "impact": "TWAP can be manipulated if time window is too short"
    },
    "liquidity_check_missing": {
        "pattern": r"(checkLiquidity|verifyLiquidity|sufficientLiquidity)\s*\(",
        "severity": "high",
        "description": "Missing liquidity verification in oracle",
        "cwe": "CWE-703",
        "cvss": 7.0,
        "impact": "Oracle can be manipulated with low liquidity"
    },
    "stale_price_allowed": {
        "pattern": r"(updatedAt|block.timestamp|now)\s*[-+]\s*(\d+|timeout|staleness)",
        "severity": "medium",
        "description": "Stale price data allowed without proper validation",
        "cwe": "CWE-754",
        "cvss": 6.0,
        "impact": "Oracle returns outdated prices"
    },
    "single_source_oracle": {
        "pattern": r"(priceFeeds|priceFeed|aggregator)\s*\[\s*\w+\s*]\s*=\s*[^;]+",
        "severity": "medium",
        "description": "Single source oracle without aggregation",
        "cwe": "CWE-757",
        "cvss": 5.5,
        "impact": "Single point of failure for price data"
    },
    "fixed_price_oracle": {
        "pattern": r"(price|factor|rate)\s*=\s*\d+(\.\d+)?\s*;",
        "severity": "medium",
        "description": "Fixed price oracle without external data",
        "cwe": "CWE-756",
        "cvss": 6.5,
        "impact": "Price does not reflect market conditions"
    },
    "flash_loan_manipulation": {
        "pattern": r"(flash|flashLoan|flashBorrow)\s*\.\s*(execute|callback)",
        "severity": "critical",
        "description": "Flash loan price manipulation vulnerability",
        "cwe": "CWE-707",
        "cvss": 9.2,
        "impact": "Attacker uses flash loans to manipulate oracle prices"
    },
}


CHAINLINK_PATTERNS = [
    r"aggregator\.latestRoundData",
    r" Aggregator\.latestRoundData",
    r"chainlink.*priceFeed",
    r"Chainlink.*Oracle",
    r"priceConverter\.convert",
    r"ETH.*USD.*price",
]

UNISWAP_PATTERNS = [
    r"uniswap.*pair.*getReserves",
    r"PairFor.*getReserves",
    r"token0\(\).*token1\(\)",
    r"balanceOf.*token",
    r"totalSupply.*lpToken",
]

TWAP_PATTERNS = [
    r"Oracle\.consult",
    r"twap.*observation",
    r"observe\(\[{2}",
    r"increaseObservationCardinalityNext",
    r"slot0\(\).*sqrtPriceX96",
]


@dataclass
class LiquidityAnalysis:
    pool_address: str = ""
    reserve0: int = 0
    reserve1: int = 0
    total_lp_tokens: int = 0
    pool_utilization: float = 0.0
    is_stable: bool = False
    manipulation_risk: str = "unknown"


@dataclass
class PriceManipulationVector:
    attack_type: str = ""
    required_capital: float = 0.0
    potential_profit: float = 0.0
    time_window: int = 0
    difficulty: str = "unknown"


class OracleManipulationHunter:
    def __init__(self):
        self.findings: List[OracleFinding] = []
        self.oracle_configs: Dict[str, OracleAnalysis] = {}
        self.price_feeds: Set[str] = set()
        self.oracle_contracts: Set[str] = set()
        self.analysis_cache: Dict[str, Any] = {}
        
    def hunt(self, source_code: str, file_name: str = "") -> List[OracleFinding]:
        logger.info(f"Hunting for oracle manipulation in {file_name}")
        
        self.findings.clear()
        self._parse_oracle_usage(source_code)
        self._detect_price_oracle_patterns(source_code)
        self._check_oracle_resilience(source_code)
        self._analyze_aggregation_strategy(source_code)
        
        return self.findings
    
    def _parse_oracle_usage(self, source_code: str) -> None:
        for line_num, line in enumerate(source_code.split('\n'), 1):
            line_stripped = line.strip()
            
            for pattern in CHAINLINK_PATTERNS:
                if re.search(pattern, line_stripped):
                    self._register_oracle_config(
                        line_stripped, OracleType.CHAINLINK, line_num
                    )
                    
            for pattern in UNISWAP_PATTERNS:
                if re.search(pattern, line_stripped):
                    self._register_oracle_config(
                        line_stripped, OracleType.UNISWAP, line_num
                    )
                    
            for pattern in TWAP_PATTERNS:
                if re.search(pattern, line_stripped):
                    self._register_oracle_config(
                        line_stripped, OracleType.TWAP, line_num
                    )
                    
            if "oracle" in line_stripped.lower():
                self.oracle_contracts.add(line_stripped)
                
    def _register_oracle_config(
        self, line: str, oracle_type: OracleType, line_num: int
    ) -> None:
        match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+)',
                         line)
        if match:
            name = match.group(1)
            self.oracle_configs[name] = OracleAnalysis(
                name=name,
                oracle_type=oracle_type,
                lines=[line]
            )
            
    def _detect_price_oracle_patterns(
        self, source_code: str
    ) -> None:
        lines = source_code.split('\n')
        
        for pattern_name, pattern_info in ORACLE_MANIPULATION_PATTERNS.items():
            pattern = pattern_info["pattern"]
            severity_str = pattern_info["severity"]
            description = pattern_info["description"]
            cwe = pattern_info["cwe"]
            cvss = pattern_info["cvss"]
            impact = pattern_info["impact"]
            
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    severity = self._parse_severity(severity_str)
                    finding = OracleFinding(
                        pattern=self._get_pattern_type(pattern_name),
                        severity=severity,
                        oracle_type=self._identify_oracle_type(line),
                        function=self._extract_function_name(line, lines, line_num),
                        description=description,
                        line_number=line_num,
                        price_feed=self._extract_price_feed(line),
                        manipulation_vector=impact,
                        recommendation=self._generate_recommendation(pattern_name),
                        code_snippet=line.strip(),
                        cvss_score=cvss,
                        cwe_id=cwe,
                        status=VulnerabilityStatus.CONFIRMED
                    )
                    self.findings.append(finding)
                    
    def _check_oracle_resilience(self, source_code: str) -> None:
        has_staleness_check = bool(
            re.search(r"(updatedAt|staleness|timeout|validPeriod)", source_code)
        )
        has_deviation_check = bool(
            re.search(r"(deviation|threshold|minAnswers)", source_code)
        )
        has_multi_source = bool(
            re.search(r"(median|average|multiplied)", source_code, re.IGNORECASE)
        )
        
        if not has_staleness_check:
            for name, config in self.oracle_configs.items():
                if not config.has_staleness_check:
                    finding = OracleFinding(
                        pattern=OracleManipulationPattern.STALE_DATA,
                        severity=OracleSeverity.MEDIUM,
                        oracle_type=config.oracle_type,
                        function=name,
                        description="No staleness check on price oracle",
                        line_number=0,
                        price_feed=name,
                        manipulation_vector="Stale price data can be used",
                        recommendation="Implement staleness check with maximum age validation",
                        cvss_score=5.5,
                        cwe_id="CWE-754",
                        status=VulnerabilityStatus.CONFIRMED
                    )
                    self.findings.append(finding)
                    
        if not has_multi_source:
            for name, config in self.oracle_configs.items():
                if config.oracle_type in [OracleType.CHAINLINK, OracleType.CUSTOM]:
                    finding = OracleFinding(
                        pattern=OracleManipulationPattern.AGGREGATION,
                        severity=OracleSeverity.MEDIUM,
                        oracle_type=config.oracle_type,
                        function=name,
                        description="Single source oracle without aggregation",
                        line_number=0,
                        price_feed=name,
                        manipulation_vector="Single point of failure",
                        recommendation="Use median of multiple oracle sources",
                        cvss_score=5.0,
                        cwe_id="CWE-757",
                        status=VulnerabilityStatus.CONFIRMED
                    )
                    self.findings.append(finding)
                    
    def _analyze_aggregation_strategy(self, source_code: str) -> None:
        if re.search(r"median", source_code, re.IGNORECASE):
            for name, config in self.oracle_configs.items():
                config.uses_median = True
                
        if re.search(r"twap|time.*weighted", source_code, re.IGNORECASE):
            for name, config in self.oracle_configs.items():
                config.uses_twap = True
                
    def _identify_oracle_type(self, line: str) -> OracleType:
        line_lower = line.lower()
        
        if "chainlink" in line_lower:
            return OracleType.CHAINLINK
        elif "uniswap" in line_lower or "pair" in line_lower:
            return OracleType.UNISWAP
        elif "twap" in line_lower:
            return OracleType.TWAP
        elif "band" in line_lower:
            return OracleType.BAND
        elif "pyth" in line_lower:
            return OracleType.PYTH
        elif "redstone" in line_lower:
            return OracleType.REDSTONE
        else:
            return OracleType.CUSTOM
            
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
        
    def _extract_price_feed(self, line: str) -> str:
        patterns = [
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*(price|latestRoundData)',
            r'(priceFeeds?|feed)\s*\[\s*([^\]]+)\s*\]',
            r'( ETH| USD| BTC)?\s*price',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1) if match.lastindex else line.strip()[:30]
                
        return line.strip()[:30]
        
    def _parse_severity(self, severity_str: str) -> OracleSeverity:
        mapping = {
            "critical": OracleSeverity.CRITICAL,
            "high": OracleSeverity.HIGH,
            "medium": OracleSeverity.MEDIUM,
            "low": OracleSeverity.LOW,
            "info": OracleSeverity.INFO,
        }
        return mapping.get(severity_str.lower(), OracleSeverity.MEDIUM)
        
    def _get_pattern_type(self, pattern_name: str) -> OracleManipulationPattern:
        mapping = {
            "price_oracle_external": OracleManipulationPattern.PRICE_ORACLE,
            "swap_price_manipulation": OracleManipulationPattern.SWAP_MANIPULATION,
            "twap_no_manipulation_resistance": OracleManipulationPattern.TWAP_ORACLE,
            "liquidity_check_missing": OracleManipulationPattern.LIQUIDITY_CHECK,
            "stale_price_allowed": OracleManipulationPattern.STALE_DATA,
            "single_source_oracle": OracleManipulationPattern.AGGREGATION,
            "fixed_price_oracle": OracleManipulationPattern.SPOT_PRICE,
            "flash_loan_manipulation": OracleManipulationPattern.FLASH_LOAN,
        }
        return mapping.get(pattern_name, OracleManipulationPattern.PRICE_ORACLE)
        
    def _generate_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "price_oracle_external": (
                "Implement staleness check with maxAge parameter. "
                "Reject prices older than 3 minutes for critical operations."
            ),
            "swap_price_manipulation": (
                "Use TWAP with sufficient granularity. "
                "Implement liquidity checks before using prices."
            ),
            "twap_no_manipulation_resistance": (
                "Use longer observation windows. "
                "Implement liquidity thresholds."
            ),
            "liquidity_check_missing": (
                "Verify liquidity against minimum threshold before price usage."
            ),
            "stale_price_allowed": (
                "Reject prices older than staleness threshold."
            ),
            "single_source_oracle": (
                "Aggregate multiple oracle sources using median or weighted average."
            ),
            "fixed_price_oracle": (
                "Replace with external oracle integration."
            ),
            "flash_loan_manipulation": (
                "Implement time delays between price updates and sensitive operations."
            ),
        }
        return recommendations.get(pattern_name, "Review and secure oracle configuration.")
        
    def generate_report(self) -> Dict[str, Any]:
        severity_counts = Counter(f.severity.value for f in self.findings)
        
        return {
            "hunter": "Oracle Manipulation Hunter",
            "total_findings": len(self.findings),
            "severity_breakdown": dict(severity_counts),
            "findings": [
                {
                    "pattern": f.pattern.value,
                    "severity": f.severity.value,
                    "oracle_type": f.oracle_type.value,
                    "function": f.function,
                    "description": f.description,
                    "line_number": f.line_number,
                    "recommendation": f.recommendation,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                }
                for f in self.findings
            ],
            "oracle_configs": [
                {
                    "name": config.name,
                    "oracle_type": config.oracle_type.value,
                    "uses_twap": config.uses_twap,
                    "uses_median": config.uses_median,
                }
                for config in self.oracle_configs.values()
            ],
        }
        
    def get_critical_findings(self) -> List[OracleFinding]:
        return [f for f in self.findings if f.severity == OracleSeverity.CRITICAL]
        
    def get_high_findings(self) -> List[OracleFinding]:
        return [f for f in self.findings if f.severity == OracleSeverity.HIGH]
        
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
                            "name": "SoliGuard Oracle Manipulation Hunter",
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
                            "level": "error" if f.severity == OracleSeverity.CRITICAL else "warning",
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