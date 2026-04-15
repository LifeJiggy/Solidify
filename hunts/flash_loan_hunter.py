"""
SoliGuard Flash Loan Hunter
Hunt for flash loan attack vectors with comprehensive detection
Author: Peace Stephen (Tech Lead)
Description: Specialized hunter for flash loan vulnerabilities in DeFi protocols
"""

import re
import logging
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, OrderedDict

logger = logging.getLogger(__name__)


class FlashLoanPattern(Enum):
    PRICE_ORACLE = "price_oracle"
    TWAP_MANIPULATION = "twap_manipulation"
    AMM_SWAP = "amm_swap"
    LIQUIDATION = "liquidation"
    YIELD_STEALING = "yield_stealing"
    COLLATERAL_RATIO = "collateral_ratio"
    BORROW_LIMIT = "borrow_limit"
    SWAP_MANIPULATION = "swap_manipulation"
    ORACLE_STALENESS = "oracle_staleness"
    SPOT_PRICE = "spot_price"
    TWAP_WINDOW = "twap_window"
    LIQUIDATION_THRESHOLD = "liquidation_threshold"
    BURNABLE_VAULT = "burnable_vault"


class FlashLoanSeverity(Enum):
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
class FlashLoanFinding:
    pattern: FlashLoanPattern
    severity: FlashLoanSeverity
    function: str
    description: str
    line_number: int
    recommendation: str
    cvss_score: float = 0.0
    cwe_id: str = ""
    protocol_interaction: str = ""
    status: VulnerabilityStatus = VulnerabilityStatus.PENDING
    impact: str = ""
    exploit_complexity: str = "medium"


@dataclass
class OracleAnalysis:
    oracle_type: str
    is_safe: bool
    staleness_check: bool
    heartbeat: Optional[int]
    deviation_threshold: Optional[float]
    price_feed: str = ""
    update_frequency: str = ""
    risk_level: str = "unknown"


@dataclass
class AMMAnalysis:
    amm_type: str
    pool_tokens: List[str] = field(default_factory=list)
    fee_tier: Optional[int]
    uses_twap: bool
    twap_interval: int = 0
    uses_spot_price: bool
    risk_assessment: str = ""


@dataclass
class LiquidationAnalysis:
    has_liquidation: bool
    threshold_check: bool
    bonus_rate: float = 0.0
    gas_estimate: int = 0
    protected_functions: List[str] = field(default_factory=list)
    risk_level: str = ""


FLASH_LOAN_PATTERNS = {
    "uniswap_v2_swap": {
        "pattern": r"(?:IUniswapV2Router|UniswapV2Router02?|UniswapV2Router01).*swap(?:ExactETHForTokens|ExactTokensForETH|ExactTokensForETHSupportingFeeOnTransferTokens)",
        "severity": "high",
        "description": "Uniswap V2 swap without price protection - vulnerable to price manipulation in same transaction",
        "protocol": "Uniswap V2",
        "cvss": 8.5,
        "cwe": "CWE-707",
        "impact": "Flash loan attacker can manipulate pool reserves to force unfavorable swaps",
        "exploit": "Borrow flash loan, swap to manipulate price, swap back, repay flash loan"
    },
    "uniswap_v3_swap": {
        "pattern": r"exactInputSingle\(\)|exactInput\(\)",
        "severity": "high",
        "description": "Uniswap V3 single hop swap vulnerable to price manipulation",
        "protocol": "Uniswap V3",
        "cvss": 8.0,
        "cwe": "CWE-707",
        "impact": "Can manipulate spot price dramatically within one block"
    },
    "chainlink_price": {
        "pattern": r"(latestRoundData|latestAnswer|Consumer|s AggregatorV3Interface).*(?<!stale)",
        "severity": "critical",
        "description": "Using Chainlink price without staleness check - stale prices can be manipulated",
        "protocol": "Chainlink",
        "cvss": 9.1,
        "cwe": "CWE-1275",
        "impact": "Stale oracle data can be used for liquidations or price manipulation"
    },
    "chainlink_no_heartbeat": {
        "pattern": r"latestRoundData.*\)(?!\s*\(.*heartbeat)",
        "severity": "high",
        "description": "Chainlink price without heartbeat check",
        "protocol": "Chainlink",
        "cvss": 8.5,
        "cwe": "CWE-1275",
        "impact": "No validation on price freshness",
        "recommendation": "Add heartbeat check to ensure price was updated recently (e.g., within last hour)"
    },
    "twap_oracle": {
        "pattern": r"Oracle\(|TWAP|price0Cumulative|price1Cumulative|construct",
        "severity": "medium",
        "description": "TWAP oracle with insufficient time window - vulnerable to manipulation",
        "protocol": "Uniswap TWAP",
        "cvss": 6.5,
        "cwe": "CWE-707",
        "impact": "Short TWAP windows can be manipulated flash loans"
    },
    "twap_short_window": {
        "pattern": r"TWAP.*interval.*(<|==)\s*(?:\d+|1[0-9]\d*|1800)",
        "severity": "medium",
        "description": "TWAP interval is too short (less than 30 minutes)",
        "protocol": "Uniswap TWAP",
        "cvss": 5.3,
        "cwe": "CWE-707",
        "impact": "Short intervals are easily manipulated"
    },
    "get_reserves": {
        "pattern": r"getReserves\(\)|_update\(|sync\(",
        "severity": "high",
        "description": "Using spot reserves as oracle - immediately manipulable",
        "protocol": "Uniswap V2",
        "cvss": 8.5,
        "cwe": "CWE-707",
        "impact": "Attacker can manipulate reserves with a flash loan"
    },
    "spot_price": {
        "pattern": r"(tokenA|token0)\(\).*(price|ethPerToken|token1Eth)\(\)?(?!\s*\*|/\s*(?:price0Cumulative|avg)",
        "severity": "high",
        "description": "Using spot price as oracle instead of TWAP",
        "protocol": "AMM",
        "cvss": 8.5,
        "cwe": "CWE-707",
        "impact": "Spot price can be manipulated in single transaction"
    },
    "liquidation": {
        "pattern": r"liquidate\(|seize\(|_liquidate\(",
        "severity": "critical",
        "description": "Liquidation function without full access control or price check",
        "protocol": "Lending",
        "cvss": 9.1,
        "cwe": "CWE-284",
        "impact": "Anyone can liquidate positions with manipulated prices"
    },
    "liquidation_bonus": {
        "pattern": r"(bonus|reward|liquidationFee).*(>[a-z0-9]|[0-9]+(\.[0-9]+)?%",
        "severity": "medium",
        "description": "Liquidation bonus can be manipulated",
        "protocol": "Lending",
        "cvss": 5.3,
        "cwe": "CWE-707",
        "impact": "Incorrect liquidation bonuses due to price manipulation"
    },
    "borrow_limit": {
        "pattern": r"maxBorrow|borrow\(.*\).*(?!\s*<=|\s*<\s*|>=|\s*>\s*max",
        "severity": "medium",
        "description": "Missing maximum borrow limit validation",
        "protocol": "Lending",
        "cvss": 5.3,
        "cwe": "CWE-1289",
        "impact": "Can borrow more than collateral allows"
    },
    "undercollateralized": {
        "pattern": r"collateral.*[><]=.*debt|(accountHealth|healthFactor).*[<>].*1",
        "severity": "high",
        "description": "Under-collateralized positions allowed",
        "protocol": "Lending",
        "cvss": 8.0,
        "cwe": "CWE-1289",
        "impact": "Users can borrow more than worth"
    },
    "flash_loan_receiver": {
        "pattern": r"IFlashLoanReceiver|onFlashLoan\(|executeOperation\(.*\)\s*(?!require|\s*msg\.sender",
        "severity": "low",
        "description": "Flash loan receiver without callback sender validation",
        "protocol": "Aave",
        "cvss": 3.8,
        "cwe": "CWE-346",
        "impact": "Minor - receiver should validate caller"
    },
    "fee_on_transfer": {
        "pattern": r"transferFee|transferFrom\(.*\)(?!\s*-\s*fee)",
        "severity": "medium",
        "description": "Token with fee-on-transfer not accounted in TWAP",
        "protocol": "ERC20",
        "cvss": 5.3,
        "cwe": "CWE-707",
        "impact": "TWAP calculation incorrect for fee tokens"
    },
    "unsupported_hooks": {
        "pattern": r"hook|beforeSwap|afterSwap|beforeMint|afterMint",
        "severity": "low",
        "description": "Custom hooks may introduce vulnerabilities",
        "protocol": "Uniswap V4",
        "cvss": 3.0,
        "cwe": "CWE-506",
        "impact": "Custom logic can be exploitable"
    }
}


ORACLE_PROVIDERS = {
    "chainlink": {
        "patterns": ["latestRoundData", "AggregatorV3Interface", "feed", "chainlink", "staleTime", "heartbeat"],
        "safe_patterns": ["heartbeat >=", "staleTime >=", "updatedAt", "roundID", "getFeed"],
        "safe_timeout": 3600,
        "recommended": True
    },
    "uniswap_v2": {
        "patterns": ["getReserves", "token0", "token1", "pairFor", "factory", "getPair"],
        "safe_patterns": ["price0Cumulative", "price1Cumulative", "twap"],
        "safe_timeout": 1800,
        "recommended": False
    },
    "uniswap_v3": {
        "patterns": ["Oracle", "slot0", "twapInterval", "observe", "uniswapv3", "tick"],
        "safe_patterns": ["observe", "tickCumulative", "secondsInside"],
        "safe_timeout": 1800,
        "recommended": True
    },
    "band": {
        "patterns": ["getPriceData", "ReferenceData", "getLastPrice", "BandAdapter"],
        "safe_patterns": ["rate", "resolveTime", "requestEVM"],
        "safe_timeout": 300,
        "recommended": True
    },
    "linear": {
        "patterns": ["getCurrentRate", "LinearRate", "getRate"],
        "safe_patterns": ["lastUpdate", "rate", "updateRate"],
        "safe_timeout": 3600,
        "recommended": False
    },
    "借���协���": {
        "patterns": ["liquidate", "seize", "liquidatable", "healthFactor"],
        "safe_patterns": ["healthFactor >", "closeFactor", "liquidationThreshold"],
        "safe_timeout": 0,
        "recommended": False
    }
}


AMM_PROVIDERS = {
    "uniswap_v2": {
        "factory": "UniswapV2Factory",
        "router": "UniswapV2Router",
        "pair": "UniswapV2Pair",
        "fee": 0.003,
        "supports_twap": True,
        "recommended_twap_window": 1800
    },
    "uniswap_v3": {
        "factory": "UniswapV3Factory",
        "router": "UniswapV3Router",
        "pool": "UniswapV3Pool",
        "fees": [500, 3000, 10000],
        "supports_twap": True,
        "recommended_twap_window": 1800
    },
    "sushiswap": {
        "factory": "FactoryV2",
        "router": "RouterV2",
        "pair": "Pair",
        "fee": 0.003,
        "supports_twap": True,
        "recommended_twap_window": 1800
    },
    "pancakeswap": {
        "factory": "PancakeFactory",
        "router": "PancakeRouter",
        "pair": "Pair",
        "fee": 0.0025,
        "supports_twap": True,
        "recommended_twap_window": 1800
    },
    "balancer": {
        "factory": "Vault",
        "router": "BalancerQueries",
        "pool": "WeightedPool2Votes",
        "fee": "dynamic",
        "supports_twap": True,
        "recommended_twap_window": 3600
    }
}


class FlashLoanDetector:
    """Detect flash loan vulnerability patterns"""
    
    def __init__(self):
        self.patterns = FLASH_LOAN_PATTERNS
        self._findings: List[FlashLoanFinding] = []
    
    def detect(self, code: str) -> List[FlashLoanFinding]:
        self._findings.clear()
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for name, info in self.patterns.items():
                if re.search(info["pattern"], line, re.IGNORECASE):
                    finding = self._create_finding(name, info, line, i)
                    if finding:
                        self._findings.append(finding)
        
        return self._findings
    
    def _create_finding(self, name: str, info: Dict, line: str, line_num: int) -> Optional[FlashLoanFinding]:
        severity = FlashLoanSeverity[info["severity"].upper()]
        
        return FlashLoanFinding(
            pattern=FlashLoanPattern[name.upper()],
            severity=severity,
            function=self._extract_function(line),
            description=info["description"],
            line_number=line_num,
            recommendation=self._get_recommendation(name),
            cvss_score=info.get("cvss", 0.0),
            cwe_id=info.get("cwe", ""),
            protocol_interaction=info.get("protocol", ""),
            status=VulnerabilityStatus.CONFIRMED,
            impact=info.get("impact", ""),
            exploit_complexity=info.get("exploit", "moderate")
        )
    
    def _extract_function(self, line: str) -> str:
        match = re.search(r"function\s+(\w+)", line)
        return match.group(1) if match else "unknown"
    
    def _get_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            "uniswap_v2_swap": "Use Uniswap V3 TWAP oracle for price with minimum 30-minute interval",
            "uniswap_v3_swap": "Use TWAP with sufficient observation period",
            "chainlink_price": "Add staleness check: require(price.updatedAt > block.timestamp - heartbeat)",
            "chainlink_no_heartbeat": "Implement heartbeat check for price freshness",
            "twap_oracle": "Use longer TWAP interval (minimum 30 minutes)",
            "twap_short_window": "Increase TWAP interval to at least 30 minutes (1800 seconds)",
            "get_reserves": "Never use spot reserves as oracle - use TWAP instead",
            "spot_price": "Use TWAP or Chainlink oracle instead of spot price",
            "liquidation": "Add access control to liquidation, check price from oracle",
            "liquidation_bonus": "Calculate bonus from oracle, not fixed value",
            "borrow_limit": "Add maximum borrow limit check based on collateral value",
            "undercollateralized": "Enforce proper collateralization ratios",
            "flash_loan_receiver": "Validate msg.sender is the flash loan pool",
            "fee_on_transfer": "Account for transfer fees in TWAP calculations",
            "unsupported_hooks": "Audit custom hook implementations thoroughly"
        }
        return recommendations.get(pattern_name, "Review and fix the vulnerability")


class PriceOracleChecker:
    """Check price oracle implementations"""
    
    def __init__(self):
        self.oracles = ORACLE_PROVIDERS
        self._found_oracles: Dict[str, OracleAnalysis] = {}
    
    def check(self, code: str) -> Dict[str, Any]:
        found_oracles = {}
        
        for oracle_name, oracle_info in self.oracles.items():
            analysis = self._analyze_oracle(oracle_name, oracle_info, code)
            if analysis:
                found_oracles[oracle_name] = {
                    "oracle_type": analysis.oracle_type,
                    "is_safe": analysis.is_safe,
                    "staleness_check": analysis.staleness_check,
                    "heartbeat": analysis.heartbeat,
                    "risk_level": self._assess_risk(analysis).value
                }
        
        return {
            "oracles": found_oracles,
            "overall_risk": self._calculate_overall_risk(found_oracles)
        }
    
    def _analyze_oracle(self, name: str, info: Dict, code: str) -> Optional[OracleAnalysis]:
        for pattern in info.get("patterns", []):
            if pattern.lower() in code.lower():
                has_staleness = self._check_staleness(code, info.get("safe_patterns", []))
                heartbeat = self._find_heartbeat(code)
                
                return OracleAnalysis(
                    oracle_type=name,
                    is_safe=has_staleness,
                    staleness_check=has_staleness,
                    heartbeat=heartbeat,
                    deviation_threshold=info.get("deviation"),
                    risk_level=self._assess_risk_from_oracle(name, has_staleness, heartbeat).value
                )
        
        return None
    
    def _check_staleness(self, code: str, safe_patterns: List[str]) -> bool:
        staleness_indicators = ["staleTime", "heartbeat", "updatedAt", "roundID", "> block.timestamp -"]
        
        for indicator in staleness_indicators:
            if indicator.lower() in code.lower():
                return True
        
        return any(pattern.lower() in code.lower() for pattern in safe_patterns)
    
    def _find_heartbeat(self, code: str) -> Optional[int]:
        patterns = [
            r"heartbeat\s*[=!<>]*\s*(\d+)",
            r"staleTime\s*[=!<>]*\s*(\d+)",
            r"MAX_AGE\s*[=!<>]*\s*(\d+)",
            r"timeout\s*[=!<>]*\s*(\d+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    pass
        
        return None
    
    def _assess_risk(self, analysis: OracleAnalysis) -> FlashLoanSeverity:
        if analysis.is_safe and analysis.staleness_check:
            return FlashLoanSeverity.LOW
        elif analysis.oracle_type in ["chainlink", "band"]:
            return FlashLoanSeverity.MEDIUM
        else:
            return FlashLoanSeverity.HIGH
    
    def _assess_risk_from_oracle(self, name: str, has_staleness: bool, heartbeat: Optional[int]) -> FlashLoanSeverity:
        if name in ["chainlink", "band"]:
            if has_staleness and heartbeat:
                return FlashLoanSeverity.LOW
            return FlashLoanSeverity.MEDIUM
        
        return FlashLoanSeverity.HIGH
    
    def _calculate_overall_risk(self, oracles: Dict) -> str:
        if not oracles:
            return "unknown"
        
        risks = [o.get("risk_level", "unknown") for o in oracles.values()]
        
        if "critical" in risks:
            return "critical"
        elif "high" in risks:
            return "high"
        elif "medium" in risks:
            return "medium"
        
        return "low"


class AMMAnalyzer:
    """Analyze AMM implementations"""
    
    def __init__(self):
        self.amms = AMM_PROVIDERS
    
    def analyze(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        
        for amm_name, amm_info in self.amms.items():
            if self._detect_amm(amm_info, code):
                analysis = self._analyze_amm(amm_name, amm_info, code)
                findings.append(analysis)
        
        return findings
    
    def _detect_amm(self, amm_info: Dict, code: str) -> bool:
        for pattern in list(amm_info.values())[0:3]:
            if isinstance(pattern, str) and pattern.lower() in code.lower():
                return True
        return False
    
    def _analyze_amm(self, name: str, info: Dict, code: str) -> Dict[str, Any]:
        uses_twap = any(p.lower() in code.lower() for p in ["twap", "price0Cumulative", "observe"])
        spot_used = "getReserves" in code or "slot0" in code
        twap_window = self._find_twap_window(code)
        
        risk = self._assess_amm_risk(name, uses_twap, spot_used, twap_window)
        
        return {
            "name": name,
            "uses_twap": uses_twap,
            "uses_spot_price": spot_used,
            "twap_window": twap_window,
            "fee_tier": info.get("fee"),
            "risk_level": risk,
            "recommendation": self._get_amm_recommendation(name, uses_twap, twap_window)
        }
    
    def _find_twap_window(self, code: str) -> int:
        patterns = [
            r"twap\s*=\s*(\d+)",
            r"interval\s*=\s*(\d+)",
            r"TWAP.*(\d+)\s*(?:seconds|secs)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    pass
        
        return 0
    
    def _assess_amm_risk(self, name: str, uses_twap: bool, spot: bool, twap_window: int) -> str:
        if spot:
            return "critical"
        elif not uses_twap:
            return "high"
        elif twap_window < 1800:
            return "medium"
        
        return "low"
    
    def _get_amm_recommendation(self, name: str, uses_twap: bool, twap_window: int) -> str:
        if not uses_twap:
            return f"Migrate to {name} TWAP oracle"
        elif twap_window < 1800:
            return f"Increase TWAP interval to at least 1800 seconds (30 minutes)"
        
        return "AMM implementation appears secure"


class LiquidationAnalyzer:
    """Analyze liquidation logic"""
    
    def __init__(self):
        self._liquidation_functions = []
    
    def analyze(self, code: str) -> Dict[str, Any]:
        findings = {
            "has_liquidation": False,
            "functions": [],
            "has_bonus": False,
            "bonus_rate": 0.0,
            "has_access_control": False,
            "has_price_check": False,
            "risk_level": "unknown"
        }
        
        findings["has_liquidation"] = "liquidate" in code.lower() or "seize" in code.lower()
        
        if findings["has_liquidation"]:
            findings["functions"] = self._find_liquidation_functions(code)
            findings["has_bonus"] = "bonus" in code.lower() or "reward" in code.lower()
            findings["bonus_rate"] = self._find_bonus_rate(code)
            findings["has_access_control"] = self._check_access_control(code)
            findings["has_price_check"] = self._check_price_check(code)
            findings["risk_level"] = self._assess_risk(findings)
        
        return findings
    
    def _find_liquidation_functions(self, code: str) -> List[str]:
        functions = []
        
        for line in code.split('\n'):
            if re.search(r"function\s+(liquidate|seize|force)", line, re.IGNORECASE):
                match = re.search(r"function\s+(\w+)", line)
                if match:
                    functions.append(match.group(1))
        
        return functions
    
    def _find_bonus_rate(self, code: str) -> float:
        patterns = [
            r"bonus\s*=\s*(\d+(?:\.\d+)?)",
            r"reward\s*=\s*(\d+(?:\.\d+)?)",
            r"liquidationBonus\s*=\s*(\d+(?:\.\d+)?)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                try:
                    return float(match.group(1))
                except (ValueError, IndexError):
                    pass
        
        return 0.0
    
    def _check_access_control(self, code: str) -> bool:
        access_patterns = ["onlyOwner", "onlyKeeper", "onlyLiquidator", "hasRole", "whenNotPaused"]
        
        liquidate_block = False
        for line in code.split('\n'):
            if "liquidate" in line.lower():
                liquidate_block = True
            elif liquidate_block:
                if any(pattern in line for pattern in access_patterns):
                    return True
        
        return False
    
    def _check_price_check(self, code: str) -> bool:
        price_patterns = ["Oracle", "latestAnswer", "getPrice", "feed", "twap", "price0Cumulative"]
        
        return any(pattern.lower() in code.lower() for pattern in price_patterns)
    
    def _assess_risk(self, findings: Dict) -> str:
        if not findings["has_liquidation"]:
            return "low"
        
        if not findings["has_price_check"]:
            return "critical"
        elif not findings["has_access_control"]:
            return "high"
        
        return "medium"


class FlashLoanHunter:
    """Main flash loan vulnerability hunter"""
    
    def __init__(self):
        self.detector = FlashLoanDetector()
        self.oracle_checker = PriceOracleChecker()
        self.amm_analyzer = AMMAnalyzer()
        self.liquidation_analyzer = LiquidationAnalyzer()
        
        logger.info("✅ Flash Loan Hunter initialized")
    
    def hunt(self, code: str) -> Dict[str, Any]:
        findings = self.detector.detect(code)
        oracle_check = self.oracle_checker.check(code)
        amm_analysis = self.amm_analyzer.analyze(code)
        liquidation_analysis = self.liquidation_analyzer.analyze(code)
        
        vulnerabilities = []
        
        for finding in findings:
            vulnerabilities.append({
                "type": "flash_loan",
                "pattern": finding.pattern.value,
                "severity": finding.severity.value,
                "function": finding.function,
                "description": finding.description,
                "line": finding.line_number,
                "recommendation": finding.recommendation,
                "cvss": finding.cvss_score,
                "cwe": finding.cwe_id,
                "protocol": finding.protocol_interaction,
                "status": finding.status.value,
                "impact": finding.impact,
                "exploit_complexity": finding.exploit_complexity
            })
        
        return {
            "vulnerabilities": vulnerabilities,
            "oracles": oracle_check,
            "amm_analysis": amm_analysis,
            "liquidation": liquidation_analysis,
            "total_findings": len(findings),
            "risk_score": self._calculate_risk_score(vulnerabilities, oracle_check)
        }
    
    def _calculate_risk_score(self, vulns: List[Dict], oracle_check: Dict) -> float:
        score = 0.0
        
        for vuln in vulns:
            severity = vuln.get("severity")
            if severity == "critical":
                score += 3.0
            elif severity == "high":
                score += 2.0
            elif severity == "medium":
                score += 1.0
        
        oracles = oracle_check.get("oracles", {})
        for name, data in oracles.items():
            risk = data.get("risk_level", "unknown")
            if risk in ["critical", "high"]:
                score += 1.5
            elif risk == "medium":
                score += 0.5
        
        return min(10.0, score)
    
    def check_oracles(self, code: str) -> Dict[str, Any]:
        return self.oracle_checker.check(code)
    
    def check_amm(self, code: str) -> List[Dict[str, Any]]:
        return self.amm_analyzer.analyze(code)
    
    def check_liquidation(self, code: str) -> Dict[str, Any]:
        return self.liquidation_analyzer.analyze(code)


def hunt_flash_loan(code: str) -> Dict[str, Any]:
    """Entry point for flash loan hunting"""
    hunter = FlashLoanHunter()
    return hunter.hunt(code)


def check_oracles(code: str) -> Dict[str, Any]:
    """Check oracle implementations"""
    hunter = FlashLoanHunter()
    return hunter.check_oracles(code)


def check_amm(code: str) -> List[Dict[str, Any]]:
    """Check AMM implementations"""
    hunter = FlashLoanHunter()
    return hunter.check_amm(code)


def check_liquidation(code: str) -> Dict[str, Any]:
    """Check liquidation logic"""
    hunter = FlashLoanHunter()
    return hunter.check_liquidation(code)