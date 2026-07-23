"""
Front-Running Vulnerability Detector

Detects front-running vulnerable patterns in Solidity smart contracts:
- Public mempool exposure
- Signed transactions vulnerable to front-running
- Uniswap V2/V3 sandwich vulnerable functions
- Batch auctions with front-running risk

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


class FrontRunPattern(Enum):
    PUBLIC_MEMPEXPOSURE = "public_memPool_exposure"
    SETTLE_ORDER = "settle_order"
    UNISWAP_SWAP = "uniswap_swap"
    BATCH_AUCTION = "batch_auction"
    SIGNATURE_REPLAY = "signature_replay"
    PERMIT_PATTERNS = "permit_patterns"


@dataclass
class FrontRunContext:
    pattern: FrontRunPattern
    function_name: str
    line_number: int
    details: str


class FrontRunDetector(BaseDetector):
    FRONTRUN_PATTERNS = {
        "set_price": r"function\s+setPrice\s*\(",
        "batch_swap": r"function\s+batchSwap\s*\(",
        "swap_exact": r"function\s+swapExact[A-Z]+\s*\(", 
        "multi_hop": r"function\s+multihopSwap\s*\(",
        "swap_router": r"function\s+swap\s*\([^)]*amountIn",
        "settle": r"function\s+settle\s*\(",
        "commit": r"function\s+commit\s*\(",
        "claim": r"function\s+claim\s*\(",
        "permit": r"function\s+permit\s*\(",
        "vote": r"function\s+vote\s*\(",
        "delegate": r"function\s+delegate\s*\(",
        "delegatecall_proxy": r"function\s+delegateCall\s*\(",
    }

    EXTERNAL_VISIBLE = {
        "public_function": r"function\s+\w+\s*\([^)]*\)\s+public\s*\{",
        "external_function": r"function\s+\w+\s*\([^)]*\)\s+external\s*\{",
    }

    UNISWAP_PATTERNS = {
        "uniswap_v2_swap": r"swap\s*\(\s*uint256\s+(?:amount|amountIn|amountOut)",
        "uniswap_v3_swap": r"exactInput\s*\(\s*bytes",
        "add_liquidity": r"addLiquidity\s*\(",
        "remove_liquidity": r"removeLiquidity\s*\(",
    }

    CWE_MAPPINGS = {
        FrontRunPattern.PUBLIC_MEMPEXPOSURE: "CWE-501",
        FrontRunPattern.SETTLE_ORDER: "CWE-1242",
        FrontRunPattern.UNISWAP_SWAP: "CWE-1241",
    }

    def __init__(self):
        super().__init__("FrontRunDetector")
        self.compiled_frontrun = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.FRONTRUN_PATTERNS.items()
        }
        self.compiled_external = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.EXTERNAL_VISIBLE.items()
        }
        self.compiled_uniswap = {
            key: re.compile(pattern, re.MULTILINE | re.DOTALL)
            for key, pattern in self.UNISWAP_PATTERNS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        functions = self._extract_functions(source_code)

        for func in functions:
            pattern = self._identify_pattern(func)
            if pattern:
                finding = self._create_finding(source_code, func, pattern)
                findings.append(finding)

        uniswap_findings = self._detect_uniswap_vulnerable(source_code)
        findings.extend(uniswap_findings)

        return findings

    def _extract_functions(self, source_code: str) -> List[Dict[str, Any]]:
        functions = []
        pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|external|internal|private)?\s*(?:pure|view|payable)?\s*\{",
            re.MULTILINE,
        )

        for match in pattern.finditer(source_code):
            start = match.start()
            end = self._find_function_end(source_code, start)
            func_body = source_code[start:end]
            line_num = source_code[:start].count("\n") + 1

            functions.append(
                {
                    "name": match.group(1),
                    "body": func_body,
                    "start": start,
                    "end": end,
                    "line": line_num,
                    "visibility": self._get_visibility(match.group(0)),
                }
            )

        return functions

    def _find_function_end(self, source: str, start: int) -> int:
        brace_count = 0
        in_string = False
        string_char = None

        for i in range(start, len(source)):
            char = source[i]

            if char in ('"', "'") and (i == 0 or source[i - 1] != "\\"):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False

            if not in_string:
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return i + 1

        return len(source)

    def _get_visibility(self, func_declaration: str) -> str:
        visibility_keywords = ["public", "external", "internal", "private"]
        for keyword in visibility_keywords:
            if keyword in func_declaration:
                return keyword
        return "external"

    def _identify_pattern(
        self, func: Dict[str, Any]
    ) -> Optional[FrontRunPattern]:
        func_name = func["name"].lower()

        for pattern_name, compiled in self.compiled_frontrun.items():
            if compiled.search(func["body"]):
                if "set" in func_name and "price" in func_name:
                    return FrontRunPattern.PUBLIC_MEMPEXPOSURE
                elif "swap" in func_name or "trade" in func_name:
                    return FrontRunPattern.UNISWAP_SWAP
                elif "settle" in func_name or "finalize" in func_name:
                    return FrontRunPattern.SETTLE_ORDER

        return None

    def _detect_uniswap_vulnerable(
        self, source_code: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        for pattern_name, compiled in self.compiled_uniswap.items():
            for match in compiled.finditer(source_code):
                line_num = source_code[:match.start()].count("\n") + 1

                func_name = self._get_enclosing_function(source_code, match.start())

                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.FRONT_RUNNING,
                    severity=Severity.MEDIUM,
                    title="Uniswap Swap Front-Running Risk",
                    description=f"Function '{func_name}' performs a swap that is "
                    "vulnerable to front-running. Attackers can sandwich this "
                    "transaction for profit.",
                    location={"function": func_name, "line": line_num},
                    code_snippet=self._extract_snippet(source_code, line_num),
                    fix_suggestion=self._generate_uniswap_fix(),
                    cvss_score=5.3,
                    confidence=0.75,
                    cwe_id= "CWE-1241",
                    references=self._get_references(),
                    exploitability=(
                        "Attackers can monitor the mempool and front-run this "
                        "swap transaction with a higher gas price."
                    ),
                    remediation=(
                        "Use flashbots bundles or implement at least min_expected "
                        "output with slippage protection."
                    ),
                )
                findings.append(finding)

        return findings

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

    def _create_finding(
        self,
        source_code: str,
        func: Dict[str, Any],
        pattern: FrontRunPattern,
    ) -> VulnerabilityFinding:
        title = f"Front-Running Vulnerability - {pattern.value}"
        description = (
            f"Function '{func['name']}' is exposed to the mempool and can be "
            f"front-run. Attackers can monitor pending transactions and submit "
            f"similar transactions with higher gas to execute first."
        )

        location = {
            "function": func["name"],
            "line": func["line"],
            "visibility": func["visibility"],
        }

        code_snippet = self._extract_snippet(source_code, func["line"])

        severity = self._determine_severity(pattern)
        cvss = self._calculate_cvss(severity)

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.FRONT_RUNNING,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(pattern),
            cvss_score=cvss,
            confidence=0.80,
            cwe_id=self.CWE_MAPPINGS.get(pattern),
            references=self._get_references(),
            exploitability=self._generate_exploitability(pattern),
            remediation=self._generate_remediation(),
        )

    def _determine_severity(self, pattern: FrontRunPattern) -> Severity:
        severity_map = {
            FrontRunPattern.PUBLIC_MEMPEXPOSURE: Severity.MEDIUM,
            FrontRunPattern.SETTLE_ORDER: Severity.MEDIUM,
            FrontRunPattern.UNISWAP_SWAP: Severity.MEDIUM,
            FrontRunPattern.BATCH_AUCTION: Severity.HIGH,
            FrontRunPattern.SIGNATURE_REPLAY: Severity.HIGH,
            FrontRunPattern.PERMIT_PATTERNS: Severity.MEDIUM,
        }
        return severity_map.get(pattern, Severity.MEDIUM)

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

    def _generate_fix_suggestion(self, pattern: FrontRunPattern) -> str:
        if pattern == FrontRunPattern.UNISWAP_SWAP:
            return (
                "```solidity\n"
                "function swap(uint256 amountIn, uint256 amountOutMin) external {\n"
                "    // Add slippage protection\n"
                "    uint256 amountOut = getAmountOut(amountIn, reserveIn, reserveOut);\n"
                "    require(amountOut >= amountOutMin, 'Insufficient output');\n"
                "    // ... swap logic\n"
                "}\n"
                "```\n\n"
                "Always set amountOutMin to protect against front-running."
            )

        return (
            "1. Use commit-reveal scheme for sensitive operations\n"
            "2. Implement minimum expected output (slippage protection)\n"
            "3. Consider using Flashbots bundles for private transactions\n"
            "4. Add deadline parameter to prevent stale transactions"
        )

    def _generate_uniswap_fix(self) -> str:
        return (
            "```solidity\n"
            "ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({\n"
            "    tokenIn: WETH9,\n"
            "    tokenOut: tokenOut,\n"
            "    fee: 3000,\n"
            "    recipient: msg.sender,\n"
            "    deadline: block.timestamp,\n"
            "    amountIn: amountIn,\n"
            "    amountOutMinimum: MIN_OUT, // Set minimum expected\n"
            "    sqrtPriceLimitX96: 0\n"
            "});\n"
            "amountOut = exactInputSingle(params);\n"
            "```\n\n"
            "Always set amountOutMinimum with slippage tolerance."
        )

    def _get_references(self) -> List[str]:
        return [
            "https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/swap-router/",
            "https://github.com/flashbots/flashbots/wiki",
        ]

    def _generate_exploitability(self, pattern: FrontRunPattern) -> str:
        return (
            "Attacker monitors mempool for pending transactions, then submits "
            "a higher-gas transaction to execute before the victim's transaction."
        )

    def _generate_remediation(self) -> str:
        return (
            "1. Implement minimum output/slippage protection\n"
            "2. Use commit-reveal scheme\n"
            "3. Consider private transactions (Flashbots)\n"
            "4. Add deadline parameter"
        )


__all__ = ["FrontRunDetector", "FrontRunPattern", "FrontRunContext"]
















































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































