"""
Self-Destruct Vulnerability Detector

Detects vulnerabilities related to self-destruct (selfdestruct/suicide) operations:
- Unprotected self-destruct
- Missing access control on self-destruct
- Improper initialization with self-destruct
- Unstoppable contracts

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


class SelfDestructPattern(Enum):
    UNPROTECTED = "unprotected_self_destruct"
    MISSING_GUARD = "missing_guard"
    UNAUTHORIZED_CALL = "unauthorized_call_any"
    DESTROYABLE = "destroyable_contract"


@dataclass
class SelfDestructContext:
    operation: str
    target: str
    function_name: str
    line_number: int
    has_access_control: bool
    beneficiary: Optional[str]


class SelfDestructDetector(BaseDetector):
    SELF_DESTRUCT_PATTERNS = {
        "selfdestruct": r"selfdestruct\s*\(",
        "suicide": r"suicide\s*\(",
        "extcodesize": r"extcodesize\s*\(",
    }

    ACCESS_CONTROL_PATTERNS = {
        "onlyOwner": r"onlyOwner",
        "only_role": r"onlyRole\s*\(",
        "requiresRole": r"requiresRole\s*\(",
        "hasRole": r"hasRole\s*\(",
        "msg_sender_check": r"msg\.sender\s*[!=]=",
    }

    CWE_MAPPINGS = {
        SelfDestructPattern.UNPROTECTED: "CWE-284",
        SelfDestructPattern.MISSING_GUARD: "CWE-862",
        SelfDestructPattern.UNAUTHORIZED_CALL: "CWE-284",
    }

    def __init__(self):
        super().__init__("SelfDestructDetector")
        self.compiled_selfdestruct = {
            key: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for key, pattern in self.SELF_DESTRUCT_PATTERNS.items()
        }
        self.compiled_access = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.ACCESS_CONTROL_PATTERNS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        selfdestruct_ops = self._find_selfdestruct_operations(source_code)

        for op in selfdestruct_ops:
            has_access = self._check_access_control(source_code, op)

            if not has_access:
                finding = self._create_finding(source_code, op, has_access)
                findings.append(finding)

        return findings

    def _find_selfdestruct_operations(
        self, source_code: str
    ) -> List[SelfDestructContext]:
        operations = []

        for op_type, pattern in self.compiled_selfdestruct.items():
            for match in pattern.finditer(source_code):
                line_num = source_code[:match.start()].count("\n") + 1

                beneficiary = self._extract_beneficiary(
                    source_code, match.start(), match.end()
                )

                func_name = self._get_enclosing_function(source_code, match.start())

                operations.append(
                    SelfDestructContext(
                        operation=op_type,
                        target=beneficiary or "address(0)",
                        function_name=func_name,
                        line_number=line_num,
                        has_access_control=False,
                        beneficiary=beneficiary,
                    )
                )

        return operations

    def _extract_beneficiary(
        self, source_code: str, start: int, end: int
    ) -> Optional[str]:
        call_content = source_code[start:end]

        paren_start = call_content.find("(")
        paren_end = call_content.find(")")

        if paren_start != -1 and paren_end != -1:
            beneficiary = call_content[paren_start + 1 : paren_end].strip()
            return beneficiary

        return None

    def _get_enclosing_function(
        self, source_code: str, position: int
    ) -> str:
        search_area = source_code[:position]
        func_matches = list(
            re.finditer(r"function\s+(\w+)\s*\(", search_area)
        )

        if func_matches:
            last_func = func_matches[-1]
            return last_func.group(1)

        return "unknown"

    def _check_access_control(
        self, source_code: str, op: SelfDestructContext
    ) -> bool:
        lines = source_code.split("\n")
        search_start = max(0, op.line_number - 10)
        search_end = min(len(lines), op.line_number + 5)
        search_area = "\n".join(lines[search_start:search_end])

        for access_pattern in self.compiled_access.values():
            if access_pattern.search(search_area):
                return True

        if "Ownable" in source_code or "AccessControl" in source_code:
            if "onlyOwner" in search_area or "requiresRole" in search_area:
                return True

        return False

    def _create_finding(
        self,
        source_code: str,
        op: SelfDestructContext,
        has_access: bool,
    ) -> VulnerabilityFinding:
        title = "Unprotected Self-Destruct"
        description = (
            f"The contract contains an unprotected '{op.operation}' "
            f"operation at line {op.line_number}. This allows anyone to "
            f"destroy the contract and permanently lose all funds."
        )

        if op.beneficiary:
            description += f" The contract balance will be sent to '{op.beneficiary}'."

        code_snippet = self._extract_snippet(source_code, op.line_number)

        location = {
            "function": op.function_name,
            "line": op.line_number,
            "operation": op.operation,
            "beneficiary": op.beneficiary or "address(0)",
        }

        severity = Severity.CRITICAL
        cvss = 9.8
        confidence = 0.95

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.SELF_DESTRUCT,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(op),
            cvss_score=cvss,
            confidence=confidence,
            cwe_id=self.CWE_MAPPINGS.get(SelfDestructPattern.UNPROTECTED),
            references=self._get_references(),
            exploitability=(
                "Attacker can call the function containing selfdestruct directly, "
                "sending all contract funds to their address and destroying the contract."
            ),
            remediation=self._generate_remediation(),
        )

    def _extract_snippet(
        self, source_code: str, line_number: int, context: int = 3
    ) -> str:
        lines = source_code.split("\n")
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])

    def _generate_fix_suggestion(self, op: SelfDestructContext) -> str:
        return (
            "```solidity\n"
            f"import '@openzeppelin/contracts/access/Ownable.sol';\n\n"
            "contract Destroyable is Ownable {\n"
            "    function destroy() public onlyOwner {{\n"
            f"        selfdestruct(payable(owner()));\n"
            "    }}\n"
            "}}\n"
            "```\n\n"
            "Add 'onlyOwner' modifier to protect the self-destruct operation."
        )

    def _get_references(self) -> List[str]:
        return [
            "https://docs.soliditylang.org/en/v0.8.0/control-structures.html#state-destroying-functions",
            "https://github.com/ethereum/solidity/issues/4113",
        ]

    def _generate_remediation(self) -> str:
        return (
            "1. Implement Ownable or AccessControl from OpenZeppelin\n"
            "2. Add 'onlyOwner' modifier to the self-destruct function\n"
            "3. Consider adding a timelock for additional safety\n"
            "4. Document the self-destruct mechanism in contract documentation"
        )


__all__ = ["SelfDestructDetector", "SelfDestructPattern", "SelfDestructContext"]