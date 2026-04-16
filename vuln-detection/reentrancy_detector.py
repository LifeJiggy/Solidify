"""
Reentrancy Vulnerability Detector

Detects reentrancy vulnerabilities in Solidity smart contracts including:
- Classic reentrancy attacks
- Cross-function reentrancy
- Cross-contract reentrancy
- Read-only reentrancy
- ERC-777 reentrancy hooks

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from . import (
    BaseDetector,
    VulnerabilityFinding,
    VulnerabilityType,
    Severity,
    create_detection_result,
)


class ReentrancyPattern(Enum):
    CLASSIC = "classic_reentrancy"
    CROSS_FUNCTION = "cross_function"
    CROSS_CONTRACT = "cross_contract"
    READ_ONLY = "read_only"
    ERC777_HOOKS = "erc777_hooks"
    DELEGATE_CALL = "delegate_call"


@dataclass
class ReentrancyContext:
    state_variable: str
    function_name: str
    external_call: str
    pattern: ReentrancyPattern
    line_number: int
    has_checks_effects_pattern: bool = False
    has_reentrancy_guard: bool = False
    is_unsafe_erc777: bool = False


class ReentrancyDetector(BaseDetector):
    PATTERNS = {
        "external_call": r"\.(call|send|transfer|delegateCall|callStatic)\s*\(",
        "low_level_call": r"\.(call|send|delegateCall)\s*\.value\s*\(",
        "call_value": r"\.call\s*\{.*value:\s*",
        "transfer_no_gas": r"\.transfer\s*\(",
        "send_no_gas": r"\.send\s*\(",
        "erc777_tokens_received": r"tokensReceived\s*\(",
        "non_reentrant": r"nonReentrant\s*\(",
        "reentrancy_guard": r"ReentrancyGuard",
        "checks_effects": r"require\s*\(.*\)\s*;.*\n.*\n.*call",
    }

    CWE_MAPPINGS = {
        ReentrancyPattern.CLASSIC: "CWE-362",
        ReentrancyPattern.CROSS_FUNCTION: "CWE-367",
        ReentrancyPattern.READ_ONLY: "CWE-371",
        ReentrancyPattern.ERC777_HOOKS: "CWE-1156",
        ReentrancyPattern.DELEGATE_CALL: "CWE-829",
    }

    def __init__(self):
        super().__init__("ReentrancyDetector")
        self.compiled_patterns = {
            key: re.compile(pattern, re.MULTILINE | re.DOTALL)
            for key, pattern in self.PATTERNS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []
        functions = self._extract_functions(source_code)
        external_calls = self._find_external_calls(source_code)
        state_modifications = self._find_state_modifications(source_code)

        for func in functions:
            func_calls = self._get_function_external_calls(func, external_calls)
            func_state_mods = self._get_function_state_mods(
                func, state_modifications
            )

            for call in func_calls:
                if self._is_reentrant_pattern(func, call, func_state_mods):
                    finding = self._create_finding(
                        source_code, func, call, func_state_mods
                    )
                    if finding:
                        findings.append(finding)

        read_only_findings = self._detect_read_only_reentrancy(
            source_code, functions
        )
        findings.extend(read_only_findings)

        erc777_findings = self._detect_erc777_hooks(source_code)
        findings.extend(erc777_findings)

        return findings

    def _extract_functions(self, source_code: str) -> List[Dict[str, Any]]:
        functions = []
        pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private|view|payable)?\s*\{",
            re.MULTILINE,
        )

        for match in pattern.finditer(source_code):
            start = match.start()
            end = self._find_function_end(source_code, start)
            func_body = source_code[start:end]
            functions.append(
                {
                    "name": match.group(1),
                    "body": func_body,
                    "modifiers": self._extract_modifiers(match.group(3) or ""),
                    "start": start,
                    "end": end,
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

    def _extract_modifiers(self, modifier_str: str) -> List[str]:
        modifiers = []
        for mod in re.findall(r"(\w+)", modifier_str):
            if mod not in ["public", "external", "internal", "private", "view", "pure", "payable"]:
                modifiers.append(mod)
        return modifiers

    def _find_external_calls(self, source_code: str) -> List[Dict[str, Any]]:
        calls = []
        for pattern_name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(source_code):
                line_num = source_code[:match.start()].count("\n") + 1
                calls.append(
                    {
                        "type": pattern_name,
                        "match": match.group(),
                        "position": match.start(),
                        "line": line_num,
                    }
                )
        return calls

    def _find_state_modifications(self, source_code: str) -> List[Dict[str, Any]]:
        modifications = []
        state_var_pattern = re.compile(
            r"(?:storage|memory)\s+\w+\s+(\w+)\s*=",
            re.MULTILINE,
        )

        assignment_pattern = re.compile(
            r"^\s*(\w+)\s*\[.*\]\s*=|^\s*(\w+)\s*\.length\s*=|^\s*(\w+)\s*(\+\+|--)\s*|^\s*(\w+)\s*\+=|^\s*(\w+)\s*-=",
            re.MULTILINE,
        )

        for match in state_var_pattern.finditer(source_code):
            line_num = source_code[:match.start()].count("\n") + 1
            modifications.append(
                {
                    "variable": match.group(1),
                    "type": "state_assignment",
                    "line": line_num,
                    "position": match.start(),
                }
            )

        for match in assignment_pattern.finditer(source_code):
            groups = match.groups()
            var_name = next((g for g in groups if g), None)
            if var_name:
                line_num = source_code[:match.start()].count("\n") + 1
                modifications.append(
                    {
                        "variable": var_name,
                        "type": "assignment",
                        "line": line_num,
                        "position": match.start(),
                    }
                )

        return modifications

    def _get_function_external_calls(
        self, func: Dict[str, Any], all_calls: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        func_calls = []
        for call in all_calls:
            if func["start"] <= call["position"] < func["end"]:
                func_calls.append(call)
        return func_calls

    def _get_function_state_mods(
        self, func: Dict[str, Any], all_mods: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        func_mods = []
        for mod in all_mods:
            if func["start"] <= mod["position"] < func["end"]:
                func_mods.append(mod)
        return func_mods

    def _is_reentrant_pattern(
        self,
        func: Dict[str, Any],
        call: Dict[str, Any],
        state_mods: List[Dict[str, Any]],
    ) -> bool:
        if "nonReentrant" in func.get("modifiers", []):
            return False

        if not state_mods:
            return False

        call_line = call["line"]
        first_state_mod_line = min(m["line"] for m in state_mods)

        return call_line < first_state_mod_line

    def _create_finding(
        self,
        source_code: str,
        func: Dict[str, Any],
        call: Dict[str, Any],
        state_mods: List[Dict[str, Any]],
    ) -> Optional[VulnerabilityFinding]:
        pattern = self._determine_pattern(func, call, state_mods)
        severity = self._determine_severity(pattern)

        code_snippet = self._extract_code_snippet(source_code, call["line"])

        title = f"Reentrancy Vulnerability - {pattern.value.replace('_', ' ').title()}"
        description = self._generate_description(pattern, func["name"])

        location = {
            "function": func["name"],
            "line": call["line"],
            "column": 0,
            "file": "contract.sol",
        }

        cvss_score = self._calculate_cvss_score(pattern, severity)
        confidence = self._calculate_confidence(func, call, pattern)

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.REENTRANCY,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(pattern),
            cvss_score=cvss_score,
            confidence=confidence,
            cwe_id=self.CWE_MAPPINGS.get(pattern),
            references=self._get_references(pattern),
            exploitability=self._generate_exploitability(pattern),
            remediation=self._generate_remediation(pattern),
        )

    def _determine_pattern(
        self,
        func: Dict[str, Any],
        call: Dict[str, Any],
        state_mods: List[Dict[str, Any]],
    ) -> ReentrancyPattern:
        if call["type"] in ["call_value", "external_call"]:
            return ReentrancyPattern.CLASSIC
        return ReentrancyPattern.CROSS_FUNCTION

    def _determine_severity(self, pattern: ReentrancyPattern) -> Severity:
        severity_map = {
            ReentrancyPattern.CLASSIC: Severity.CRITICAL,
            ReentrancyPattern.CROSS_FUNCTION: Severity.HIGH,
            ReentrancyPattern.CROSS_CONTRACT: Severity.HIGH,
            ReentrancyPattern.READ_ONLY: Severity.MEDIUM,
            ReentrancyPattern.ERC777_HOOKS: Severity.HIGH,
            ReentrancyPattern.DELEGATE_CALL: Severity.CRITICAL,
        }
        return severity_map.get(pattern, Severity.HIGH)

    def _extract_code_snippet(self, source_code: str, line: int, context: int = 3) -> str:
        lines = source_code.split("\n")
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        snippet = "\n".join(lines[start:end])
        return f"...\n{snippet}\n..."

    def _generate_description(self, pattern: ReentrancyPattern, func_name: str) -> str:
        descriptions = {
            ReentrancyPattern.CLASSIC: (
                f"The function '{func_name}' makes an external call to an untrusted contract "
                "before updating state variables. This classic reentrancy vulnerability allows "
                "an attacker to call the function repeatedly to drain funds or manipulate state."
            ),
            ReentrancyPattern.CROSS_FUNCTION: (
                f"Cross-function reentrancy detected in '{func_name}'. The contract performs "
                "external calls that can be exploited through a different function that shares "
                "the same state variables."
            ),
            ReentrancyPattern.READ_ONLY: (
                f"Read-only reentrancy vulnerability in '{func_name}'. The function reads state "
                "after an external call that can modify the state through a view function."
            ),
            ReentrancyPattern.ERC777_HOOKS: (
                f"ERC-777 token callback vulnerability in '{func_name}'. The use of ERC-777 "
                "tokens with hooks allows reentrancy through the tokensReceived callback."
            ),
        }
        return descriptions.get(pattern, "Reentrancy vulnerability detected.")

    def _generate_fix_suggestion(self, pattern: ReentrancyPattern) -> str:
        suggestions = {
            ReentrancyPattern.CLASSIC: (
                "1. Apply the Checks-Effects-Interactions pattern:\n"
                "   - Update all state variables BEFORE making external calls\n"
                "   - Use ReentrancyGuard modifier\n"
                "   - Consider using OpenZeppelin's SafeERC20\n\n"
                "Example:\n"
                "```solidity\n"
                "function withdraw() external {\n"
                "    // Checks\n"
                "    require(balances[msg.sender] > 0, \"No balance\");\n"
                "    \n"
                "    // Effects - Update state FIRST\n"
                "    uint256 amount = balances[msg.sender];\n"
                "    balances[msg.sender] = 0;\n"
                "    \n"
                "    // Interactions - External call LAST\n"
                "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
                "    require(success, \"Transfer failed\");\n"
                "}\n"
                "```"
            ),
            ReentrancyPattern.CROSS_FUNCTION: (
                "Use a reentrancy guard and ensure all state modifications complete "
                "before any external calls. Consider using a state machine pattern."
            ),
            ReentrancyPattern.READ_ONLY: (
                "Re-read state variables after external calls if they are used for "
                "determining return values or critical calculations."
            ),
        }
        return suggestions.get(pattern, "Implement reentrancy guards and checks-effects-interactions pattern.")

    def _calculate_cvss_score(self, pattern: ReentrancyPattern, severity: Severity) -> float:
        base_scores = {
            Severity.CRITICAL: 9.8,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 2.1,
        }
        return base_scores.get(severity, 5.0)

    def _calculate_confidence(
        self, func: Dict[str, Any], call: Dict[str, Any], pattern: ReentrancyPattern
    ) -> float:
        confidence = 0.85

        if "nonReentrant" in func.get("modifiers", []):
            confidence -= 0.5

        if call["type"] == "call_value":
            confidence += 0.1

        return min(1.0, max(0.0, confidence))

    def _get_references(self, pattern: ReentrancyPattern) -> List[str]:
        return [
            "https://solidity-by-example.org/hacks/re-entrancy/",
            "https://github.com/uni-due-syssec/eth-reentrancy-attack-db",
            "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
        ]

    def _generate_exploitability(self, pattern: ReentrancyPattern) -> str:
        return (
            "This vulnerability can be exploited by deploying a malicious contract "
            "that calls the vulnerable function in a loop, draining funds or "
            "manipulating state before the balance is updated."
        )

    def _generate_remediation(self, pattern: ReentrancyPattern) -> str:
        return (
            "1. Implement Checks-Effects-Interactions pattern\n"
            "2. Use ReentrancyGuard from OpenZeppelin\n"
            "3. Consider using pull-payment pattern\n"
            "4. Update Solidity to 0.8+ for built-in overflow protection"
        )

    def _detect_read_only_reentrancy(
        self, source_code: str, functions: List[Dict[str, Any]]
    ) -> List[VulnerabilityFinding]:
        findings = []
        view_functions = [f for f in functions if "view" in f.get("modifiers", [])]

        for view_func in view_functions:
            has_external_call = self.compiled_patterns["external_call"].search(
                view_func["body"]
            )
            if has_external_call:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.REENTRANCY,
                    severity=Severity.MEDIUM,
                    title="Read-Only Reentrancy",
                    description=f"View function '{view_func['name']}' makes external calls that can manipulate returned state.",
                    location={
                        "function": view_func["name"],
                        "line": view_func["body"].count("\n") + 1,
                    },
                    code_snippet=self._extract_code_snippet(
                        source_code, view_func["body"].count("\n")
                    ),
                    fix_suggestion="Re-read state variables after external calls.",
                    cvss_score=5.3,
                    confidence=0.75,
                    cwe_id="CWE-371",
                )
                findings.append(finding)

        return findings

    def _detect_erc777_hooks(self, source_code: str) -> List[VulnerabilityFinding]:
        findings = []

        if "IERC777Recipient" in source_code or "tokensReceived" in source_code:
            has_unsafe_hook = True

            if "nonReentrant" in source_code or "ReentrancyGuard" in source_code:
                has_unsafe_hook = False

            if has_unsafe_hook:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.REENTRANCY,
                    severity=Severity.HIGH,
                    title="ERC-777 Token Callback Reentrancy",
                    description="Contract implements ERC-777 tokensReceived callback without reentrancy protection.",
                    location={"line": 1},
                    code_snippet="tokensReceived(...)",
                    fix_suggestion="Implement ReentrancyGuard when using ERC-777 tokens.",
                    cvss_score=7.5,
                    confidence=0.80,
                    cwe_id="CWE-1156",
                )
                findings.append(finding)

        return findings


__all__ = ["ReentrancyDetector", "ReentrancyPattern", "ReentrancyContext"]
