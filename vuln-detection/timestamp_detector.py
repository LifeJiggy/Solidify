"""
Timestamp Dependence Vulnerability Detector

Detects timestamp dependence vulnerabilities in Solidity smart contracts:
- Block timestamp usage in critical logic
- Timestamp-based access control
- Lottery/Randomness using block.timestamp
- Time-sensitive operations vulnerable to manipulation

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from . import (
    BaseDetector,
    VulnerabilityFinding,
    VulnerabilityType,
    Severity,
)


class TimestampPattern(Enum):
    TIMESTAMP_GAME = "timestamp_gameability"
    RANDOMNESS = "timestamp_randomness"
    TIME_LOCK = "timestamp_timelock"
    AUCTION_END = "timestamp_auction"
    LOCK_PERIOD = "timestamp_lock_period"


@dataclass
class TimestampContext:
    pattern: TimestampPattern
    function_name: str
    line_number: int
    timestamp_usage: str


class TimestampDetector(BaseDetector):
    TIMESTAMP_PATTERNS = {
        "block_timestamp": r"block\.timestamp",
        "now_alias": r"\bnow\b",
        "block_number_15": r"block\.number\s*[+\-]\s*15\b",
    }

    CRITICAL_OPERATIONS = {
        "random": r"(?:random|rand|entropy|VRF)",
        "lottery": r"(?:lottery|draw|raffle|lucky)",
        "auction": r"(?:auction|bid|highestBid|auctionEnd)",
        "timelock": r"(?:timelock|unlockTime|releaseTime|lockPeriod)",
        "staking": r"(?:stake|unstake|claim|reward|period)",
    }

    CWE_MAPPINGS = {
        TimestampPattern.TIMESTAMP_GAME: "CWE-829",
        TimestampPattern.RANDOMNESS: "CWE-330",
        TimestampPattern.TIME_LOCK: "CWE-672",
    }

    def __init__(self):
        super().__init__("TimestampDetector")
        self.compiled_timestamp = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.TIMESTAMP_PATTERNS.items()
        }
        self.compiled_critical = {
            key: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for key, pattern in self.CRITICAL_OPERATIONS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        timestamp_usage = self._find_timestamp_usage(source_code)

        for usage in timestamp_usage:
            context = self._analyze_timestamp_usage(source_code, usage)

            if self._is_critical_usage(context):
                finding = self._create_finding(source_code, context)
                findings.append(finding)

        return findings

    def _find_timestamp_usage(
        self, source_code: str
    ) -> List[TimestampContext]:
        usages = []

        for usage_type, pattern in self.compiled_timestamp.items():
            for match in pattern.finditer(source_code):
                line_num = source_code[:match.start()].count("\n") + 1
                func_name = self._get_enclosing_function(source_code, match.start())

                usages.append(
                    TimestampContext(
                        pattern=TimestampPattern.TIMESTAMP_GAME,
                        function_name=func_name,
                        line_number=line_num,
                        timestamp_usage=match.group(),
                    )
                )

        return usages

    def _get_enclosing_function(
        self, source_code: str, position: int
    ) -> str:
        search_area = source_code[:position]
        func_matches = list(
            re.finditer(r"function\s+(\w+)\s*\(", search_area)
        )

        if func_matches:
            return func_matches[-1].group(1)

        return "unknown"

    def _analyze_timestamp_usage(
        self, source_code: str, usage: TimestampContext
    ) -> TimestampContext:
        lines = source_code.split("\n")
        start = max(0, usage.line_number - 3)
        end = min(len(lines), usage.line_number + 3)
        context_area = "\n".join(lines[start:end])

        for crit_name, crit_pattern in self.compiled_critical.items():
            if crit_pattern.search(context_area):
                if "random" in crit_name.lower():
                    return TimestampContext(
                        pattern=TimestampPattern.RANDOMNESS,
                        function_name=usage.function_name,
                        line_number=usage.line_number,
                        timestamp_usage=usage.timestamp_usage,
                    )
                elif "lottery" in crit_name.lower():
                    return TimestampContext(
                        pattern=TimestampPattern.TIMESTAMP_GAME,
                        function_name=usage.function_name,
                        line_number=usage.line_number,
                        timestamp_usage=usage.timestamp_usage,
                    )
                elif "timelock" in crit_name.lower() or "lock" in crit_name.lower():
                    return TimestampContext(
                        pattern=TimestampPattern.TIME_LOCK,
                        function_name=usage.function_name,
                        line_number=usage.line_number,
                        timestamp_usage=usage.timestamp_usage,
                    )

        return usage

    def _is_critical_usage(self, context: TimestampContext) -> bool:
        critical_patterns = [
            TimestampPattern.RANDOMNESS,
            TimestampPattern.TIMESTAMP_GAME,
        ]
        return context.pattern in critical_patterns

    def _create_finding(
        self, source_code: str, context: TimestampContext
    ) -> VulnerabilityFinding:
        if context.pattern == TimestampPattern.RANDOMNESS:
            title = "Timestamp Dependence for Randomness"
            description = (
                f"Function '{context.function_name}' uses block.timestamp for "
                "randomness. Miners can manipulate timestamps within a range "
                "to influence the outcome."
            )
            severity = Severity.HIGH
        else:
            title = "Timestamp Dependence Vulnerability"
            description = (
                f"Function '{context.function_name}' depends on block.timestamp "
                "which can be manipulated by miners within certain constraints."
            )
            severity = Severity.MEDIUM

        location = {
            "function": context.function_name,
            "line": context.line_number,
            "timestamp_usage": context.timestamp_usage,
        }

        code_snippet = self._extract_snippet(source_code, context.line_number)

        cvss = self._calculate_cvss(severity)

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.TIMESTAMP_DEPENDENCE,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(context.pattern),
            cvss_score=cvss,
            confidence=0.85,
            cwe_id=self.CWE_MAPPINGS.get(context.pattern),
            references=self._get_references(),
            exploitability=self._generate_exploitability(context.pattern),
            remediation=self._generate_remediation(),
        )

    def _extract_snippet(
        self, source_code: str, line_number: int, context: int = 3
    ) -> str:
        lines = source_code.split("\n")
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])

    def _calculate_cvss(self, severity: Severity) -> float:
        cvss_map = {
            Severity.CRITICAL: 9.1,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 2.1,
        }
        return cvss_map.get(severity, 5.0)

    def _generate_fix_suggestion(self, pattern: TimestampPattern) -> str:
        if pattern == TimestampPattern.RANDOMNESS:
            return (
                "```solidity\n"
                "import '@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol';\n"
                "import '@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol';\n\n"
                "contract RandomNumber is VRFConsumerBaseV2 {\n"
                "    uint256 public randomResult;\n"
                "    \n"
                "    function requestRandomWords() external {\n"
                "        coordinator.requestRandomWords(\n"
                "            keyHash,\n"
                "            subscriptionId,\n"
                "            REQUEST_CONFIRMATIONS,\n"
                "            CALLBACK_GAS_LIMIT,\n"
                "            NUM_WORDS\n"
                "        );\n"
                "    }\n"
                "    \n"
                "    function fulfillRandomWords(\n"
                "        uint256 requestId,\n"
                "        uint256[] memory randomWords\n"
                "    ) internal override {\n"
                "        randomResult = randomWords[0];\n"
                "    }\n"
                "}\n"
                "```\n\n"
                "Use Chainlink VRF for provably fair randomness."
            )

        return (
            "```solidity\n"
            "function sensitiveOperation() external {\n"
            "    // Use block.number for time-sensitive operations\n"
            "    // instead of block.timestamp\n"
            "    require(\n"
            "        block.number >= lastActionBlock + BLOCKS_PER_ACTION,\n"
            "        'Too soon'\n"
            "    );\n"
            "    // ... operation logic\n"
            "}\n"
            "```\n\n"
            "block.number provides more reliable timing guarantees."
        )

    def _get_references(self) -> List[str]:
        return [
            "https://docs.soliditylang.org/en/v0.8.0/abi-spec.html#abi-encoding",
            "https://docs.chain.link/vrf/v2/introduction/",
        ]

    def _generate_exploitability(self, pattern: TimestampPattern) -> str:
        if pattern == TimestampPattern.RANDOMNESS:
            return (
                "Miners can manipulate block.timestamp within a ±15 second range "
                "to influence the random outcome in their favor."
            )

        return (
            "Miners can slightly adjust block.timestamp within acceptable bounds "
            "to affect time-dependent contract logic."
        )

    def _generate_remediation(self) -> str:
        return (
            "1. Use Chainlink VRF for randomness\n"
            "2. Use block.number instead of block.timestamp\n"
            "3. Add buffer times for critical operations\n"
            "4. Document timestamp tolerance in contract"
        )


__all__ = ["TimestampDetector", "TimestampPattern", "TimestampContext"]
















































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































