"""
Denial of Service (DoS) Vulnerability Detector

Detects DoS vulnerabilities in Solidity smart contracts:
- Gas griefing attacks
- Unbounded loops
- Array length manipulation
- Revert denial
- Block
- Callable denial

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


class DoSPattern(Enum):
    GAS_GRIEFING = "gas_griefing"
    UNBOUNDED_LOOP = "unbounded_loop"
    ARRAY_MANIPULATION = "array_length_manipulation"
    REVERT_DENIAL = "revert_denial"
    BLOCK_GAS_LIMIT = "block_gas_limit"
    EXTERNAL_CALL_LOOP = "external_call_loop"


@dataclass
class DoSContext:
    pattern: DoSPattern
    function_name: str
    line_number: int
    severity: Severity
    details: str


class DoSDetector(BaseDetector):
    DOS_PATTERNS = {
        "loop_no_bounds": r"for\s*\(\s*(?:\w+)\s+\w+\s+in\s+\w+\.length",
        "while_loop": r"while\s*\(",
        "array_push": r"\.push\s*\(",
        "external_call_loop": r"for\s*\{[^}]*\.call\(",
        "send_loop": r"for\s*\{[^}]*\.send\(",
        "transfer_loop": r"for\s*\{[^}]*\.transfer\(",
        "delegatecall_loop": r"for\s*\{[^}]*\.delegateCall\(",
        "callcode_loop": r"for\s*\{[^}]*\.callcode\(",
        "external_call_iteration": r"for\s*\([^)]*\.length[^)]*\)[^}]*\w+\.\w+\s*\(",
    }

    GAS_LIMIT_PATTERNS = {
        "block_gas_limit": r"block\.gaslimit",
        "gas_left": r"gasleft\s*\(",
        "msg_gas": r"msg\.gas",
    }

    CWE_MAPPINGS = {
        DoSPattern.GAS_GRIEFING: "CWE-400",
        DoSPattern.UNBOUNDED_LOOP: "CWE-834",
        DoSPattern.REVERT_DENIAL: "CWE-1368",
    }

    def __init__(self):
        super().__init__("DoSDetector")
        self.compiled_dos = {
            key: re.compile(pattern, re.MULTILINE | re.DOTALL)
            for key, pattern in self.DOS_PATTERNS.items()
        }
        self.compiled_gas = {
            key: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for key, pattern in self.GAS_LIMIT_PATTERNS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        functions = self._extract_functions(source_code)

        for func in functions:
            if self._has_dos_pattern(func):
                finding = self._create_finding(source_code, func)
                findings.append(finding)

        array_findings = self._detect_array_dos(source_code)
        findings.extend(array_findings)

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

    def _has_dos_pattern(self, func: Dict[str, Any]) -> bool:
        for dos_type, pattern in self.compiled_dos.items():
            if pattern.search(func["body"]):
                return True
        return False

    def _detect_array_dos(
        self, source_code: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        array_push = re.finditer(r"(\w+)\.push\s*\([^)]*\)", source_code)

        for match in array_push:
            line_num = source_code[:match.start()].count("\n") + 1

            array_name = match.group(1)

            surrounding = self._get_surrounding(source_code, line_num, 5)

            if self._is_unbounded_push(surrounding, array_name):
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.DENIAL_OF_SERVICE,
                    severity=Severity.MEDIUM,
                    title="Unbounded Array Push",
                    description=f"The array '{array_name}' has unbounded push operations. "
                    "An attacker can fill the array with elements, causing the contract "
                    "to run out of gas and become unusable.",
                    location={
                        "array": array_name,
                        "line": line_num,
                        "operation": "push",
                    },
                    code_snippet=self._extract_snippet(source_code, line_num),
                    fix_suggestion="Implement array length limits or use mappings instead of arrays.",
                    cvss_score=5.3,
                    confidence=0.80,
                    cwe_id="CWE-834",
                    references=self._get_references(),
                    exploitability=(
                        "Attacker can repeatedly call functions that push to this array, "
                        "eventually making the contract unusable due to gas limits."
                    ),
                    remediation=(
                        "Add maximum array length checks, use mappings, or implement a pausable mechanism."
                    ),
                )
                findings.append(finding)

        return findings

    def _is_unbounded_push(self, surrounding: str, array_name: str) -> bool:
        if "require" in surrounding and "length" in surrounding:
            return False

        if "if" in surrounding and "length" in surrounding:
            return False

        return True

    def _get_surrounding(
        self, source_code: str, line_number: int, context: int
    ) -> str:
        lines = source_code.split("\n")
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])

    def _create_finding(
        self, source_code: str, func: Dict[str, Any]
    ) -> VulnerabilityFinding:
        dos_type = self._determine_dos_type(func)

        title = f"Denial of Service - {dos_type.value.replace('_', ' ').title()}"
        description = (
            f"Function '{func['name']}' contains a pattern that could lead to denial of service. "
            f"The {dos_type.value.replace('_', ' ')} can be exploited to render the contract unusable."
        )

        severity = self._determine_severity(dos_type)

        location = {
            "function": func["name"],
            "line": func["line"],
        }

        code_snippet = self._extract_snippet(source_code, func["line"])

        cvss = self._calculate_cvss(severity)
        confidence = 0.75

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.DENIAL_OF_SERVICE,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(dos_type),
            cvss_score=cvss,
            confidence=confidence,
            cwe_id=self.CWE_MAPPINGS.get(dos_type),
            references=self._get_references(),
            exploitability=self._generate_exploitability(dos_type),
            remediation=self._generate_remediation(dos_type),
        )

    def _determine_dos_type(self, func: Dict[str, Any]) -> DoSPattern:
        body = func["body"]

        if self.compiled_dos["external_call_loop"].search(body):
            return DoSPattern.EXTERNAL_CALL_LOOP

        if self.compiled_dos["loop_no_bounds"].search(body):
            return DoSPattern.UNBOUNDED_LOOP

        if self.compiled_dos["while_loop"].search(body):
            return DoSPattern.UNBOUNDED_LOOP

        if self.compiled_dos["array_push"].search(body):
            return DoSPattern.ARRAY_MANIPULATION

        return DoSPattern.GAS_GRIEFING

    def _determine_severity(self, dos_type: DoSPattern) -> Severity:
        severity_map = {
            DoSPattern.GAS_GRIEFING: Severity.MEDIUM,
            DoSPattern.UNBOUNDED_LOOP: Severity.HIGH,
            DoSPattern.ARRAY_MANIPULATION: Severity.MEDIUM,
            DoSPattern.REVERT_DENIAL: Severity.MEDIUM,
            DoSPattern.BLOCK_GAS_LIMIT: Severity.LOW,
            DoSPattern.EXTERNAL_CALL_LOOP: Severity.HIGH,
        }
        return severity_map.get(dos_type, Severity.MEDIUM)

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

    def _generate_fix_suggestion(self, dos_type: DoSPattern) -> str:
        if dos_type == DoSPattern.UNBOUNDED_LOOP:
            return (
                "```solidity\n"
                "contract SafeLoop is ReentrancyGuard {\n"
                "    uint256 public maxBatchSize = 100;\n\n"
                "    function processAll() external {\n"
                "        uint256 length = items.length;\n"
                "        uint256 batchSize = length < maxBatchSize ? \n"
                "            length : maxBatchSize;\n\n"
                "        for (uint256 i = 0; i < batchSize; i++) {\n"
                "            processItem(i);\n"
                "        }\n"
                "    }\n"
                "}\n"
                "```\n\n"
                "Process items in batches to avoid hitting block gas limits."
            )
        elif dos_type == DoSPattern.EXTERNAL_CALL_LOOP:
            return (
                "Use a pull payment pattern instead of iterating external calls:\n"
                "1. Users call a function to register themselves\n"
                "2. Use a separate withdrawal function\n"
                "3. Process payments one at a time when requested"
            )

        return "Implement gas limits and batch processing to prevent DoS."

    def _get_references(self) -> List[str]:
        return [
            "https://solidity-by-example.org/dos/",
            "https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html",
        ]

    def _generate_exploitability(self, dos_type: DoSPattern) -> str:
        if dos_type == DoSPattern.UNBOUNDED_LOOP:
            return "Attacker can pass large arrays to trigger excessive gas consumption."
        elif dos_type == DoSPattern.EXTERNAL_CALL_LOOP:
            return "Attacker can make the transaction run out of gas."

        return "This pattern can be exploited to render the contract unusable."

    def _generate_remediation(self, dos_type: DoSPattern) -> str:
        return (
            "1. Implement batch processing with size limits\n"
            "2. Use pull payment pattern instead of push\n"
            "3. Add gas checks before operations\n"
            "4. Consider using mappings instead of arrays"
        )


__all__ = ["DoSDetector", "DoSPattern", "DoSContext"]