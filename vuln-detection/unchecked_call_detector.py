"""
Unchecked Call Vulnerability Detector

Detects unchecked return value vulnerabilities in Solidity smart contracts:
- Unchecked low-level calls (call, send)
- Unchecked external calls
- Missing return value checks
- Silent failures

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


class UncheckedCallPattern(Enum):
    UNCHECKED_CALL = "unchecked_call"
    UNCHECKED_SEND = "unchecked_send"
    IGNORED返回值 = "ignored_return_value"
    SILENT_FAILURE = "silent_failure"


@dataclass
class UncheckedCallContext:
    call_type: str
    function_name: str
    target: str
    line_number: int
    has_return_check: bool


class UncheckedCallDetector(BaseDetector):
    CALL_PATTERNS = {
        "low_level_call": r"\.call\s*(?:\{.*\})?\s*\(",
        "low_level_send": r"\.send\s*\(",
        "low_level_transfer": r"\.transfer\s*\(",
        "external_call": r"\w+\.\w+\s*\(",
        "delegatecall": r"\.delegateCall\s*\(",
        "staticcall": r"\.staticCall\s*\(",
    }

    RETURN_CHECK_PATTERNS = {
        "require_success": r"require\s*\(\s*(?:\w+|bool)",
        "assert_success": r"assert\s*\(\s*(?:\w+|bool)",
        "if_not_success": r"if\s*\(\s*!\s*(?:\w+|bool)",
        "success_check": r"(?:success|ok|res)\s*=",
    }

    CWE_MAPPINGS = {
        UncheckedCallPattern.UNCHECKED_CALL: "CWE-252",
        UncheckedCallPattern.UNCHECKED_SEND: "CWE-253",
        UncheckedCallPattern.IGNORED_RETURN_VALUE: "CWE-754",
        UncheckedCallPattern.SILENT_FAILURE: "CWE-391",
    }

    def __init__(self):
        super().__init__("UncheckedCallDetector")
        self.compiled_patterns = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.CALL_PATTERNS.items()
        }
        self.return_check_patterns = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.RETURN_CHECK_PATTERNS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        functions = self._extract_functions(source_code)

        for func in functions:
            func_calls = self._find_unchecked_calls(func)

            for call in func_calls:
                if not self._has_return_check(func, call):
                    finding = self._create_finding(source_code, func, call)
                    findings.append(finding)

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

    def _find_unchecked_calls(
        self, func: Dict[str, Any]
    ) -> List[UncheckedCallContext]:
        calls = []
        func_body = func["body"]

        for call_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(func_body):
                call_line = func_body[:match.start()].count("\n") + 1
                call_text = match.group()

                target_match = re.search(r"(\w+)\.", call_text)
                target = target_match.group(1) if target_match else "unknown"

                calls.append(
                    UncheckedCallContext(
                        call_type=call_type,
                        function_name=func["name"],
                        target=target,
                        line_number=func["line"] + call_line - 1,
                        has_return_check=False,
                    )
                )

        return calls

    def _has_return_check(
        self, func: Dict[str, Any], call: UncheckedCallContext
    ) -> bool:
        func_body = func["body"]

        for check_type, pattern in self.return_check_patterns.items():
            if pattern.search(func_body):
                return True

        return False

    def _create_finding(
        self,
        source_code: str,
        func: Dict[str, Any],
        call: UncheckedCallContext,
    ) -> VulnerabilityFinding:
        pattern = self._determine_pattern(call)

        severity = self._determine_severity(call)

        title = f"Unchecked Return Value - {call.call_type.replace('_', ' ').title()}"
        description = (
            f"Function '{func['name']}' makes a {call.call_type.replace('_', ' ')} "
            f"to '{call.target}' but does not check the return value. If the call "
            f"fails silently, the contract may proceed with incorrect state."
        )

        code_snippet = self._extract_snippet(source_code, call.line_number)

        location = {
            "function": func["name"],
            "line": call.line_number,
            "target": call.target,
            "call_type": call.call_type,
        }

        cvss = self._calculate_cvss(severity)
        confidence = 0.85

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.UNCHECKED_CALL,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(call),
            cvss_score=cvss,
            confidence=confidence,
            cwe_id=self.CWE_MAPPINGS.get(pattern),
            references=self._get_references(),
            exploitability=self._generate_exploitability(call),
            remediation=self._generate_remediation(),
        )

    def _determine_pattern(self, call: UncheckedCallContext) -> UncheckedCallPattern:
        pattern_map = {
            "low_level_call": UncheckedCallPattern.UNCHECKED_CALL,
            "low_level_send": UncheckedCallPattern.UNCHECKED_SEND,
            "low_level_transfer": UncheckedCallPattern.SILENT_FAILURE,
            "external_call": UncheckedCallPattern.IGNORED_RETURN_VALUE,
            "delegatecall": UncheckedCallPattern.UNCHECKED_CALL,
            "staticcall": UncheckedCallPattern.IGNORED_RETURN_VALUE,
        }
        return pattern_map.get(call.call_type, UncheckedCallPattern.UNCHECKED_CALL)

    def _determine_severity(self, call: UncheckedCallContext) -> Severity:
        high_risk_calls = ["send", "transfer", "delegatecall"]
        if any(risk in call.call_type for risk in high_risk_calls):
            return Severity.HIGH
        return Severity.MEDIUM

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

    def _generate_fix_suggestion(self, call: UncheckedCallContext) -> str:
        if call.call_type == "low_level_call":
            return (
                "```solidity\n"
                "(bool success, ) = target.call{value: amount}(\"\");\n"
                "require(success, \"Call failed\");\n"
                "```\n\n"
                "Always check the return value of low-level calls."
            )
        elif call.call_type == "low_level_send":
            return (
                "```solidity\n"
                "(bool success, ) = recipient.send{value: amount}(\"\");\n"
                "if (!success) {\n"
                "    // Handle failure - revert or log\n"
                "}\n"
                "```\n\n"
                "Note: transfer() is preferred over send() for EOAs."
            )

        return "Check the return value of the external call using require()."

    def _get_references(self) -> List[str]:
        return [
            "https://solidity-by-example.org/calling-contracts/",
            "https://docs.soliditylang.org/en/v0.8.0/control-structures.html#error-handling",
        ]

    def _generate_exploitability(self, call: UncheckedCallContext) -> str:
        return (
            f"If the {call.call_type.replace('_', ' ')} to '{call.target}' fails, "
            f"the contract will continue execution as if it succeeded, "
            f"leading to inconsistent state."
        )

    def _generate_remediation(self) -> str:
        return (
            "1. Always check return values of low-level calls\n"
            "2. Use require() for success check\n"
            "3. Consider using SafeERC20 from OpenZeppelin\n"
            "4. Implement error handling for failed calls"
        )


__all__ = ["UncheckedCallDetector", "UncheckedCallPattern", "UncheckedCallContext"]











































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































