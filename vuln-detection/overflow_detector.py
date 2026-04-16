"""
Integer Overflow and Underflow Detector

Detects integer overflow and underflow vulnerabilities in Solidity smart contracts.
Supports detection for:
- Unsigned integer overflow
- Signed integer overflow/underflow
- Assembly arithmetic overflow
- Unchecked arithmetic operations

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


@dataclass
class ArithmeticOperation:
    operation: str
    operand_left: str
    operand_right: str
    operator: str
    line_number: int
    is_unchecked: bool
    result_type: str
    position: int


class OverflowType(Enum):
    OVERFLOW = "overflow"
    UNDERFLOW = "underflow"
    UNCHECKED_ARITHMETIC = "unchecked_arithmetic"
    ASSEMBLY_OVERFLOW = "assembly_overflow"


class OverflowDetector(BaseDetector):
    SOLC_VERSION_PATTERNS = {
        "0.7.x": r"pragma\s+solidity\s+\^?0\.7\.",
        "0.8.x": r"pragma\s+solidity\s+\^?0\.8\.",
        "0.8.0+": r"pragma\s+solidity\s+0\.8\.[0-9]+",
    }

    ARITHMETIC_PATTERNS = {
        "addition": r"(\w+)\s*\+\s*(\w+)",
        "subtraction": r"(\w+)\s*-\s*(\w+)",
        "multiplication": r"(\w+)\s*\*\s*(\w+)",
        "division": r"(\w+)\s*/\s*(\w+)",
        "modulo": r"(\w+)\s*%\s*(\w+)",
        "increment": r"(\w+)\+\+",
        "decrement": r"(\w+)--",
        "compound_add": r"(\w+)\s*\+=",
        "compound_sub": r"(\w+)\s*-=",
        "compound_mul": r"(\w+)\s*\*=",
        "compound_div": r"(\w+)\s*/=",
    }

    UNCHECKED_PATTERNS = {
        "unchecked_block": r"unchecked\s*\{",
        "unchecked_add": r"unchecked\s*\{[^}]*\+[^}]*\}",
        "unchecked_sub": r"unchecked\s*\{[^}]*-[^}]*\}",
        "unchecked_mul": r"unchecked\s*\{[^}]*\*[^}]*\}",
    }

    ASSEMBLY_ARITHMETIC = {
        "add": r"add\(",
        "sub": r"sub\(",
        "mul": r"mul\(",
        "div": r"div\(",
        "mod": r"mod\(",
    }

    CWE_MAPPINGS = {
        OverflowType.OVERFLOW: "CWE-190",
        OverflowType.UNDERFLOW: "CWE-191",
        OverflowType.UNCHECKED_ARITHMETIC: "CWE-758",
        OverflowType.ASSEMBLY_OVERFLOW: "CWE-189",
    }

    def __init__(self):
        super().__init__("OverflowDetector")
        self.compiled_patterns = {
            key: re.compile(pattern, re.MULTILINE)
            for key, pattern in self.ARITHMETIC_PATTERNS.items()
        }
        self.unchecked_patterns = {
            key: re.compile(pattern, re.MULTILINE | re.DOTALL)
            for key, pattern in self.UNCHECKED_PATTERNS.items()
        }
        self.assembly_patterns = {
            key: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for key, pattern in self.ASSEMBLY_ARITHMETIC.items()
        }

    def detect(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        solidity_version = self._detect_solidity_version(source_code)
        is_safe_math_needed = self._needs_safe_math(solidity_version)

        if is_safe_math_needed:
            overflow_findings = self._detect_potential_overflows(
                source_code, contract_name
            )
            findings.extend(overflow_findings)

        unchecked_findings = self._detect_unchecked_arithmetic(source_code)
        findings.extend(unchecked_findings)

        assembly_findings = self._detect_unsafe_assembly(source_code)
        findings.extend(assembly_findings)

        return findings

    def _detect_solidity_version(self, source_code: str) -> Optional[str]:
        for version, pattern in self.SOLC_VERSION_PATTERNS.items():
            if re.search(pattern, source_code):
                return version
        return None

    def _needs_safe_math(self, version: Optional[str]) -> bool:
        if version is None:
            return True

        if version in ["0.7.x"]:
            return True

        if version.startswith("0.8") and not re.search(
            r"pragma\s+solidity\s+0\.8\.(19|[2-9]\d)", ""
        ):
            return True

        return False

    def _detect_potential_overflows(
        self, source_code: str, contract_name: str
    ) -> List[VulnerabilityFinding]:
        findings = []
        functions = self._extract_functions(source_code)

        for func in functions:
            arithmetic_ops = self._find_arithmetic_in_function(
                func["body"], func["start"]
            )

            for op in arithmetic_ops:
                if self._is_vulnerable_operation(op):
                    finding = self._create_overflow_finding(
                        source_code, func, op
                    )
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
            end = self._find_brace_end(source_code, start)
            func_body = source_code[start:end]
            functions.append(
                {
                    "name": match.group(1),
                    "body": func_body,
                    "start": start,
                    "end": end,
                    "line": source_code[:start].count("\n") + 1,
                }
            )

        return functions

    def _find_brace_end(self, source: str, start: int) -> int:
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

    def _find_arithmetic_in_function(
        self, func_body: str, offset: int
    ) -> List[ArithmeticOperation]:
        operations = []

        for op_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(func_body):
                line_num = func_body[:match.start()].count("\n") + 1
                full_line = self._get_full_line(func_body, match.start())

                is_unchecked = self._is_in_unchecked_block(func_body, match.start())

                result_type = self._infer_type(match.group(1), func_body)

                op = ArithmeticOperation(
                    operation=op_type,
                    operand_left=match.group(1),
                    operand_right=match.group(2) if match.lastindex >= 2 else None,
                    operator=self._get_operator(op_type),
                    line_number=offset + line_num,
                    is_unchecked=is_unchecked,
                    result_type=result_type,
                    position=match.start(),
                )
                operations.append(op)

        return operations

    def _get_full_line(self, source: str, position: int) -> str:
        line_start = source.rfind("\n", 0, position) + 1
        line_end = source.find("\n", position)
        if line_end == -1:
            line_end = len(source)
        return source[line_start:line_end]

    def _is_in_unchecked_block(self, source: str, position: int) -> bool:
        before = source[:position]
        unchecked_count = before.count("unchecked")
        brace_count = before.count("{") - before.count("}")

        return unchecked_count > 0 and brace_count >= 0

    def _infer_type(self, var_name: str, func_body: str) -> str:
        type_patterns = [
            (r"uint256\s+" + var_name, "uint256"),
            (r"uint8\s+" + var_name, "uint8"),
            (r"uint16\s+" + var_name, "uint16"),
            (r"uint32\s+" + var_name, "uint32"),
            (r"uint64\s+" + var_name, "uint64"),
            (r"int256\s+" + var_name, "int256"),
            (r"int8\s+" + var_name, "int8"),
            (r"int256\s+" + var_name, "int256"),
        ]

        for pattern, var_type in type_patterns:
            if re.search(pattern, func_body):
                return var_type

        return "uint256"

    def _get_operator(self, operation_type: str) -> str:
        operators = {
            "addition": "+",
            "subtraction": "-",
            "multiplication": "*",
            "division": "/",
            "modulo": "%",
            "increment": "++",
            "decrement": "--",
            "compound_add": "+=",
            "compound_sub": "-=",
            "compound_mul": "*=",
            "compound_div": "/=",
        }
        return operators.get(operation_type, "?")

    def _is_vulnerable_operation(self, op: ArithmeticOperation) -> bool:
        vulnerable_ops = [
            "addition",
            "subtraction",
            "multiplication",
            "increment",
            "decrement",
            "compound_add",
            "compound_sub",
            "compound_mul",
        ]

        if op.operation not in vulnerable_ops:
            return False

        if op.is_unchecked:
            return True

        is_unsigned = "uint" in op.result_type.lower()
        return is_unsigned

    def _create_overflow_finding(
        self,
        source_code: str,
        func: Dict[str, Any],
        op: ArithmeticOperation,
    ) -> VulnerabilityFinding:
        is_underflow = op.operation in [
            "subtraction",
            "decrement",
            "compound_sub",
        ]

        overflow_type = (
            OverflowType.UNDERFLOW if is_underflow else OverflowType.OVERFLOW
        )

        severity = Severity.HIGH

        if "uint8" in op.result_type or "uint16" in op.result_type:
            severity = Severity.CRITICAL

        title = f"Integer {'Underflow' if is_underflow else 'Overflow'} - {op.result_type}"
        description = (
            f"Potential {'underflow' if is_underflow else 'overflow'} in function "
            f"'{func['name']}' at line {op.line_number}. The {op.result_type} operation "
            f"'{op.operand_left} {op.operator} {op.operand_right or ''}' can {'underflow' if is_underflow else 'overflow'} "
            f"when dealing with extreme values."
        )

        location = {
            "function": func["name"],
            "line": op.line_number,
            "variable": op.operand_left,
            "operation": op.operation,
        }

        code_snippet = self._extract_code_snippet(
            source_code, op.line_number
        )

        cvss = self._calculate_cvss_score(overflow_type, severity)
        confidence = 0.90 if op.is_unchecked else 0.75

        return VulnerabilityFinding(
            vuln_type=VulnerabilityType.INTEGER_OVERFLOW
            if not is_underflow
            else VulnerabilityType.INTEGER_UNDERFLOW,
            severity=severity,
            title=title,
            description=description,
            location=location,
            code_snippet=code_snippet,
            fix_suggestion=self._generate_fix_suggestion(op),
            cvss_score=cvss,
            confidence=confidence,
            cwe_id=self.CWE_MAPPINGS.get(overflow_type),
            references=self._get_references(),
            exploitability=self._generate_exploitability(op),
            remediation=self._generate_remediation(),
        )

    def _extract_code_snippet(
        self, source_code: str, line_number: int, context: int = 3
    ) -> str:
        lines = source_code.split("\n")
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        snippet = "\n".join(lines[start:end])
        return f"...\n{snippet}\n..."

    def _calculate_cvss_score(
        self, overflow_type: OverflowType, severity: Severity
    ) -> float:
        base_scores = {
            Severity.CRITICAL: 9.1,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 2.1,
        }
        return base_scores.get(severity, 5.0)

    def _generate_fix_suggestion(self, op: ArithmeticOperation) -> str:
        return (
            f"1. Use OpenZeppelin's SafeMath library for {op.result_type}:\n"
            f"   ```solidity\n"
            f"   import '@openzeppelin/contracts/utils/math/SafeMath.sol';\n"
            f"   ```\n\n"
            f"2. Replace the operation with SafeMath:\n"
            f"   ```solidity\n"
            f"   // Before: {op.operand_left} {op.operator} {op.operand_right or ''}\n"
            f"   // After:\n"
            f"   {op.operand_left} = {op.operand_left}.{op.operation.replace('compound_', '')}({op.operand_right or '1'});\n"
            f"   ```\n\n"
            f"3. Or upgrade to Solidity 0.8.0+ which has built-in overflow checks"
        )

    def _get_references(self) -> List[str]:
        return [
            "https://docs.soliditylang.org/en/v0.8.0/080-breaking-changes.html",
            "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeMath.sol",
            "https://solidity-by-example.org/hacks/overflow/",
        ]

    def _generate_exploitability(self, op: ArithmeticOperation) -> str:
        return (
            f"An attacker can trigger this overflow/underflow by providing extreme "
            f"values for {op.operand_left} or {op.operand_right}. This can lead to "
            f"unexpected contract state, potential fund loss, or bypass of critical "
            f"checks that rely on arithmetic comparisons."
        )

    def _generate_remediation(self) -> str:
        return (
            "1. Use SafeMath library from OpenZeppelin\n"
            "2. Upgrade to Solidity 0.8.0+ for built-in overflow protection\n"
            "3. If using older Solidity, add explicit overflow checks\n"
            "4. Consider using smaller integer types with proper bounds checking"
        )

    def _detect_unchecked_arithmetic(
        self, source_code: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        unchecked_blocks = list(
            self.unchecked_patterns["unchecked_block"].finditer(source_code)
        )

        for block in unchecked_blocks:
            block_start = block.start()
            block_end = source_code.find("}", block_start)

            if block_end == -1:
                continue

            block_content = source_code[block_start:block_end]

            for op_type, pattern in self.compiled_patterns.items():
                for match in pattern.finditer(block_content):
                    line_num = source_code[:block_start].count("\n") + 1

                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
                        severity=Severity.HIGH,
                        title="Unchecked Arithmetic Operation",
                        description=f"Unchecked arithmetic in 'unchecked {{}}' block at line {line_num}. "
                        "Arithmetic operations inside unchecked blocks bypass Solidity's built-in overflow protection.",
                        location={"line": line_num, "operation": op_type},
                        code_snippet=block_content[:200],
                        fix_suggestion="Remove the unchecked block or add explicit overflow checks.",
                        cvss_score=7.5,
                        confidence=0.95,
                        cwe_id="CWE-758",
                    )
                    findings.append(finding)

        return findings

    def _detect_unsafe_assembly(
        self, source_code: str
    ) -> List[VulnerabilityFinding]:
        findings = []

        assembly_blocks = re.finditer(r"assembly\s+\{", source_code)

        for block in assembly_blocks:
            block_start = block.start()
            block_end = self._find_brace_end(source_code, block_start)
            assembly_content = source_code[block_start:block_end]

            for op_name, pattern in self.assembly_patterns.items():
                if pattern.search(assembly_content):
                    line_num = source_code[:block_start].count("\n") + 1

                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.INTEGER_OVERFLOW,
                        severity=Severity.HIGH,
                        title="Unsafe Assembly Arithmetic",
                        description=f"Assembly arithmetic '{op_name}' at line {line_num} "
                        "does not have built-in overflow protection. This can lead to "
                        "unexpected behavior if the operation exceeds type bounds.",
                        location={"line": line_num, "operation": op_name},
                        code_snippet=assembly_content[:200],
                        fix_suggestion="Use Solidity's built-in arithmetic with SafeMath or upgrade to 0.8+.",
                        cvss_score=7.5,
                        confidence=0.80,
                        cwe_id="CWE-189",
                    )
                    findings.append(finding)

        return findings


__all__ = ["OverflowDetector", "OverflowType", "ArithmeticOperation"]
