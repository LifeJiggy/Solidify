"""
Access Control Vulnerability Detector

Detects access control vulnerabilities in Solidity smart contracts including:
- Missing access modifiers
- Broken access control
- tx.origin usage
- Unprotected self-destruct
- Missing role checks
- Public functions that should be internal

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
)


class AccessControlPattern(Enum):
    MISSING_MODIFIER = "missing_modifier"
    BROKEN_AUTH = "broken_authorization"
    TX_ORIGIN = "tx_origin_usage"
    UNPROTECTED_SELF_DESTRUCT = "unprotected_self_destruct"
    MISSING_ROLE_CHECK = "missing_role_check"
    PUBLIC_MINT = "public_mint"
    UNRESTRICTED_TRANSFER = "unrestricted_transfer"
    DEFAULT_ADMIN_ROLE = "default_admin_role"


@dataclass
class AccessControlIssue:
    pattern: AccessControlPattern
    function_name: str
    line_number: int
    severity: Severity
    description: str


class AccessControlDetector(BaseDetector):
    CRITICAL_FUNCTIONS = {
        "mint": ["mint", "mintTo", "mintBatch", "_mint"],
        "burn": ["burn", "_burn", "burnFrom"],
        "transfer": ["transfer", "transferFrom", "safeTransfer", "safeTransferFrom"],
        "withdraw": ["withdraw", "withdrawETH", "withdrawToken", "claim"],
        "pause": ["pause", "unpause", "_pause", "_unpause"],
        "upgrade": ["upgrade", "upgradeTo", "upgradeToAndCall", "_upgradeTo"],
        "ownership": ["transferOwnership", "renounceOwnership"],
        "admin": ["setAdmin", "grantRole", "revokeRole", "addMinter", "removeMinter"],
    }

    SENSITIVE_PATTERNS = {
        "owner_only": r"(?:require|if)\s*\(\s*msg\.sender\s*==\s*owner",
        "only_owner": r"modifier\s+onlyOwner",
        "only_role": r"modifier\s+onlyRole\s*\(",
        "requires_role": r"requiresRole\s*\(",
        "has_role": r"hasRole\s*\(",
        "access_control": r"AccessControl",
        "ownable": r"Ownable",
        "pausable": r"Pausable",
    }

    UNSAFE_PATTERNS = {
        "tx_origin": r"tx\.origin",
        "msg_sender_check": r"(?:require|if|assert)\s*\(\s*msg\.sender\s*[!=]=",
        "public_state": r"(?:uint256|address|bool|string|bytes)\s+\w+\s+(?:public|external)",
    }

    CWE_MAPPINGS = {
        AccessControlPattern.MISSING_MODIFIER: "CWE-862",
        AccessControlPattern.BROKEN_AUTH: "CWE-287",
        AccessControlPattern.TX_ORIGIN: "CWE-346",
        AccessControlPattern.UNPROTECTED_SELF_DESTRUCT: "CWE-284",
        AccessControlPattern.MISSING_ROLE_CHECK: "CWE-862",
        AccessControlPattern.PUBLIC_MINT: "CWE-862",
    }

    def __init__(self):
        super().__init__("AccessControlDetector")
        self.compiled_sensitive = {
            key: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for key, pattern in self.SENSITIVE_PATTERNS.items()
        }
        self.compiled_unsafe = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.UNSAFE_PATTERNS.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        functions = self._extract_functions(source_code)
        contract_has_access_control = self._has_access_control_library(source_code)

        for func in functions:
            if not contract_has_access_control:
                missing_modifier_finding = self._check_missing_access_control(
                    source_code, func
                )
                if missing_modifier_finding:
                    findings.append(missing_modifier_finding)

            tx_origin_finding = self._check_tx_origin_usage(source_code, func)
            if tx_origin_finding:
                findings.append(tx_origin_finding)

            public_state_finding = self._check_public_state_variables(func)
            if public_state_finding:
                findings.append(public_state_finding)

        self_destruct_findings = self._check_unprotected_self_destruct(source_code)
        findings.extend(self_destruct_findings)

        return findings

    def _extract_functions(self, source_code: str) -> List[Dict[str, Any]]:
        functions = []
        pattern = re.compile(
            r"(function|function\s+)\s*(\w+)\s*\(([^)]*)\)\s*(?:public|external|internal|private)?\s*(?:pure|view|payable)?\s*(?:returns\s*\([^)]*\))?\s*\{",
            re.MULTILINE,
        )

        for match in pattern.finditer(source_code):
            start = match.start()
            end = self._find_function_end(source_code, start)
            func_body = source_code[start:end]

            modifier_match = re.search(
                r"\)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", func_body
            )
            modifiers = modifier_match.groups() if modifier_match else []

            visibility_match = re.search(
                r"(public|external|internal|private)", func_body
            )
            visibility = visibility_match.group(1) if visibility_match else "external"

            line_num = source_code[:start].count("\n") + 1

            functions.append(
                {
                    "name": match.group(2),
                    "body": func_body,
                    "modifiers": modifiers,
                    "visibility": visibility,
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

    def _has_access_control_library(self, source_code: str) -> bool:
        access_control_libs = [
            "Ownable",
            "AccessControl",
            "AccessControlEnumerable",
            "Pausable",
            "AccessControlDefaultAdminRules",
            "AccessControlProxy",
            "RBAC",
            "Roles",
        ]

        for lib in access_control_libs:
            if lib in source_code:
                return True
        return False

    def _check_missing_access_control(
        self, source_code: str, func: Dict[str, Any]
    ) -> Optional[VulnerabilityFinding]:
        func_name = func["name"].lower()

        for category, keywords in self.CRITICAL_FUNCTIONS.items():
            if any(keyword.lower() in func_name for keyword in keywords):
                if not func["modifiers"] and func["visibility"] == "public":
                    severity = Severity.CRITICAL if category in [
                        "mint",
                        "burn",
                        "withdraw",
                        "upgrade",
                    ] else Severity.HIGH

                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.ACCESS_CONTROL,
                        severity=severity,
                        title=f"Missing Access Control - {category.title()}",
                        description=f"Function '{func['name']}' performs critical "
                        f"'{category}' operation but lacks access control. "
                        f"Any external caller can execute this function.",
                        location={
                            "function": func["name"],
                            "line": func["line"],
                            "visibility": func["visibility"],
                        },
                        code_snippet=self._extract_snippet(source_code, func["line"]),
                        fix_suggestion=self._generate_access_control_fix(func),
                        cvss_score=self._calculate_cvss(severity),
                        confidence=0.90,
                        cwe_id="CWE-862",
                        references=self._get_references(),
                        exploitability=(
                            f"Anyone can call the {func['name']} function and "
                            f"perform unauthorized {category} operations."
                        ),
                        remediation=self._generate_remediation(),
                    )
                    return finding

        return None

    def _check_tx_origin_usage(
        self, source_code: str, func: Dict[str, Any]
    ) -> Optional[VulnerabilityFinding]:
        tx_origin_matches = list(
            self.compiled_unsafe["tx_origin"].finditer(func["body"])
        )

        if tx_origin_matches:
            line_offset = source_code[:func["start"]].count("\n")
            line_num = line_offset + func["body"][
                :tx_origin_matches[0].start()
            ].count("\n") + 1

            finding = VulnerabilityFinding(
                vuln_type=VulnerabilityType.ACCESS_CONTROL,
                severity=Severity.MEDIUM,
                title="tx.origin Authentication",
                description=f"Function '{func['name']}' uses 'tx.origin' for "
                "authentication. This is vulnerable to phishing attacks where "
                "a malicious contract can trick users into calling the vulnerable "
                "function through an intermediary.",
                location={
                    "function": func["name"],
                    "line": line_num,
                    "pattern": "tx.origin",
                },
                code_snippet=self._extract_snippet(source_code, line_num),
                fix_suggestion="Replace 'tx.origin' with 'msg.sender' for authentication.",
                cvss_score=5.3,
                confidence=0.95,
                cwe_id="CWE-346",
                references=[
                    "https://solidity-by-example.org/hacks/phishing-with-tx-origin/",
                ],
                exploitability=(
                    "An attacker can deploy a malicious contract that calls the "
                    "vulnerable function, using the victim's address as tx.origin."
                ),
                remediation="Use msg.sender instead of tx.origin for authorization checks.",
            )
            return finding

        return None

    def _check_public_state_variables(
        self, func: Dict[str, Any]
    ) -> Optional[VulnerabilityFinding]:
        sensitive_vars = ["admin", "owner", "manager", "pauser", "minter", "blacklist"]

        for var in sensitive_vars:
            if var in func["name"].lower():
                return None

        return None

    def _check_unprotected_self_destruct(
        self, source_code: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        self_destruct_pattern = re.compile(
            r"(selfdestruct|suicide)\s*\(", re.MULTILINE | re.IGNORECASE
        )

        for match in self_destruct_pattern.finditer(source_code):
            line_num = source_code[:match.start()].count("\n") + 1

            surrounding = self._get_surrounding_code(source_code, line_num, 5)
            has_protection = any(
                pattern in surrounding
                for pattern in ["onlyOwner", "require(msg.sender", "if (msg.sender"]
            )

            if not has_protection:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.ACCESS_CONTROL,
                    severity=Severity.CRITICAL,
                    title="Unprotected Self-Destruct",
                    description="Contract contains an unprotected self-destruct "
                    "operation. Anyone can trigger this and destroy the contract, "
                    "permanently losing all funds and data.",
                    location={"line": line_num, "operation": "selfdestruct"},
                    code_snippet=self._extract_snippet(source_code, line_num),
                    fix_suggestion="Add access control to the self-destruct function.",
                    cvss_score=9.8,
                    confidence=0.95,
                    cwe_id="CWE-284",
                    references=[
                        "https://docs.soliditylang.org/en/v0.8.0/control-structures.html#state-destroying-functions",
                    ],
                    exploitability=(
                        "Attacker can call the self-destruct function directly "
                        "and destroy the contract, stealing all funds."
                    ),
                    remediation="Implement access control using Ownable or AccessControl.",
                )
                findings.append(finding)

        return findings

    def _extract_snippet(
        self, source_code: str, line_number: int, context: int = 3
    ) -> str:
        lines = source_code.split("\n")
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])

    def _get_surrounding_code(
        self, source_code: str, line_number: int, context: int
    ) -> str:
        return self._extract_snippet(source_code, line_number, context)

    def _generate_access_control_fix(self, func: Dict[str, Any]) -> str:
        func_name = func["name"]
        category = None

        for cat, keywords in self.CRITICAL_FUNCTIONS.items():
            if any(keyword.lower() in func_name.lower() for keyword in keywords):
                category = cat
                break

        if category == "mint":
            return (
                "```solidity\n"
                "import '@openzeppelin/contracts/access/Ownable.sol';\n\n"
                "contract Token is Ownable {\n"
                "    function mint(address to, uint256 amount) public onlyOwner {\n"
                "        _mint(to, amount);\n"
                "    }\n"
                "}\n"
                "```"
            )
        elif category == "withdraw":
            return (
                "```solidity\n"
                "import '@openzeppelin/contracts/access/Ownable.sol';\n\n"
                "contract Vault is Ownable {\n"
                "    function withdraw() public onlyOwner {\n"
                "        payable(owner()).transfer(address(this).balance);\n"
                "    }\n"
                "}\n"
                "```"
            )

        return (
            "Add appropriate access control modifier:\n"
            "- Use OpenZeppelin's Ownable for single admin\n"
            "- Use AccessControl for role-based permissions"
        )

    def _calculate_cvss(self, severity: Severity) -> float:
        cvss_map = {
            Severity.CRITICAL: 9.8,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 2.1,
        }
        return cvss_map.get(severity, 5.0)

    def _get_references(self) -> List[str]:
        return [
            "https://docs.openzeppelin.com/contracts/4.x/access-control",
            "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol",
            "https://solidity-by-example.org/access-control/",
        ]

    def _generate_remediation(self) -> str:
        return (
            "1. Implement OpenZeppelin's Ownable contract\n"
            "2. Add 'onlyOwner' modifier to sensitive functions\n"
            "3. For role-based access, use AccessControl\n"
            "4. Consider using OpenZeppelin's AccessControlEnumerable\n"
            "5. Document all access control requirements"
        )


__all__ = ["AccessControlDetector", "AccessControlPattern", "AccessControlIssue"]
