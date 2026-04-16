"""
Gas Analysis

Production-grade Solidity smart contract gas analysis and optimization detection.
Identifies gas inefficiencies, suggests optimizations, and estimates costs.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class GasIssueType(Enum):
    STORAGE_READ = "storage_read"
    STORAGE_WRITE = "storage_write"
    UNBOUNDED_LOOP = "unbounded_loop"
    REDUNDANT_CALCULATION = "redundant_calculation"
    INEFFICIENT_DATA_TYPE = "inefficient_data_type"
    UNCHECKED_MATH = "unchecked_math"
    STRING_ERROR = "string_error"
    EVENT_EMISSION = "event_emission"
    OUTSIDE_LOOP = "outside_loop"
    MEMORY_ALLOCATION = "memory_allocation"


@dataclass
class GasIssue:
    issue_type: GasIssueType
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    current_cost: int
    optimized_cost: int
    saved_gas: int
    suggestion: str


@dataclass
class GasAnalysisResult:
    contract_name: str
    function_gas: Dict[str, int] = field(default_factory=dict)
    storage_reads: int = 0
    storage_writes: int = 0
    external_calls: int = 0
    events: int = 0
    issues: List[GasIssue] = field(default_factory=list)
    total_optimization_potential: int = 0
    optimization_score: str = "C"


class GasAnalyzer:
    GAS_COSTS = {
        "SLOAD": 2100,
        "SSTORE": 2900,
        "CALL": 2600,
        "STATICCALL": 2600,
        "DELEGATECALL": 2600,
        "CREATE": 32000,
        "CREATE2": 32000,
        "CALLDATACOPY": 3,
        "EXTCODESIZE": 2600,
        "EXTCODEHASH": 2600,
        "BALANCE": 2600,
        "BLOCKHASH": 20,
        "LOG0": 375,
        "LOG1": 750,
        "LOG2": 1125,
        "LOG3": 1500,
        "LOG4": 1875,
    }

    OPTIMIZABLE_PATTERNS = {
        "storage_in_loop": {
            "pattern": r"(?:for|while)\s*\([^)]*\{[^}]*(?:storage|mapping)",
            "severity": "HIGH",
            "explanation": "Storage reads/writes inside loops are very expensive",
        },
        "repeated_storage": {
            "pattern": r"(\w+)\s*=\s*.*\1\s*=\s*",
            "severity": "MEDIUM",
            "explanation": "Multiple assignments to storage variable",
        },
        "string_require": {
            "pattern": r'require\s*\([^,]+,\s*"[^"]*"',
            "severity": "MEDIUM",
            "explanation": "String error messages cost more gas than custom errors",
        },
        "public_var": {
            "pattern": r"(uint|int|address|bool|string|bytes)\s+(\w+)\s+public",
            "severity": "LOW",
            "explanation": "Public vars generate automatic getters",
        },
        "memory_allocation": {
            "pattern": r"new\s+\w+\s*\(\s*\)",
            "severity": "LOW",
            "explanation": "Dynamic array allocation may be expensive",
        },
    }

    FIXED_TYPES = {
        "uint256": "uint256",
        "uint8": "uint8",
        "uint16": "uint16",
        "uint32": "uint32",
        "uint64": "uint64",
        "uint128": "uint128",
    }

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.functions: Dict[str, Dict[str, Any]] = {}
        self._parse_functions()

    def _parse_functions(self):
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:public|external|internal|private|pure|view|payable)\s*)*"
            r"\{",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(self.source_code):
            func_name = match.group(1)
            start = match.start()
            end = self._find_function_end(start)

            self.functions[func_name] = {
                "name": func_name,
                "body": self.source_code[start:end],
                "line": self.source_code[:start].count("\n") + 1,
            }

    def _find_function_end(self, start: int) -> int:
        brace_count = 0
        in_string = False

        for i in range(start, len(self.source_code)):
            char = self.source_code[i]

            if char in ('"', "'") and (i == 0 or self.source_code[i - 1] != "\\"):
                in_string = not in_string

            if not in_string:
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        return i + 1

        return len(self.source_code)

    def analyze(self) -> GasAnalysisResult:
        result = GasAnalysisResult(contract_name="Unknown")

        name_match = re.search(r"contract\s+(\w+)", self.source_code)
        if name_match:
            result.contract_name = name_match.group(1)

        result.storage_reads = self._count_storage_reads()
        result.storage_writes = self._count_storage_writes()
        result.external_calls = self._count_external_calls()
        result.events = self._count_events()

        result.issues = self._find_issues()

        total_current = (
            result.storage_reads * 2100 +
            result.storage_writes * 2900 +
            result.external_calls * 2600
        )

        total_optimized = 0
        for issue in result.issues:
            total_optimized += issue.saved_gas
            result.function_gas[issue.location.get("function", "unknown")] = issue.current_cost

        result.total_optimization_potential = max(0, total_current - total_optimized)

        result.optimization_score = self._calculate_score(result)

        return result

    def _count_storage_reads(self) -> int:
        reads = len(re.findall(r"(?<!m)sload\s*\(", self.source_code.lower()))
        reads += len(re.findall(r"\.balance\b", self.source_code))
        return reads

    def _count_storage_writes(self) -> int:
        writes = len(re.findall(r"sstore\s*\(", self.source_code.lower()))
        return writes

    def _count_external_calls(self) -> int:
        return len(re.findall(
            r"\.(call|send|transfer|delegateCall|callStatic)\s*\(",
            self.source_code
        ))

    def _count_events(self) -> int:
        return len(re.findall(r"emit\s+\w+\s*\(", self.source_code))

    def _find_issues(self) -> List[GasIssue]:
        issues = []

        issues.extend(self._find_loop_storage_issues())
        issues.extend(self._find_string_require_issues())
        issues.extend(self._find_public_var_issues())
        issues.extend(self._find_repeated_storage_issues())
        issues.extend(self._find_memory_issues())

        return issues

    def _find_loop_storage_issues(self) -> List[GasIssue]:
        issues = []

        for func_name, func_data in self.functions.items():
            body = func_data["body"]

            if re.search(r"(?:for|while)\s*\(.*\{[^}]*(?:storage|mapping)", body):
                for match in re.finditer(r"(?:for|while)", body):
                    location = {
                        "function": func_name,
                        "line": func_data["line"],
                    }
                    
                    issue = GasIssue(
                        issue_type=GasIssueType.STORAGE_READ,
                        severity="HIGH",
                        title="Storage Access in Loop",
                        description=f"Function {func_name} reads/writes storage in a loop",
                        location=location,
                        current_cost=50000,
                        optimized_cost=5000,
                        saved_gas=45000,
                        suggestion="Cache storage values in memory variables before the loop",
                    )
                    issues.append(issue)

        return issues

    def _find_string_require_issues(self) -> List[GasIssue]:
        issues = []

        for match in re.finditer(
            r'require\s*\(([^,]+),\s*"([^"]+)"',
            self.source_code
        ):
            error_msg = match.group(2)
            line_num = self.source_code[:match.start()].count("\n") + 1

            msg_cost = len(error_msg) * 68

            issue = GasIssue(
                issue_type=GasIssueType.STRING_ERROR,
                severity="MEDIUM",
                title="String Error Message",
                description=f"Error string '{error_msg}' costs ~{msg_cost} gas more than custom error",
                location={"line": line_num},
                current_cost=msg_cost + 2000,
                optimized_cost=2000,
                saved_gas=msg_cost,
                suggestion="Define and use custom errors (error Name()):\n"
                "```solidity\n"
                "error CustomError();\n"
                "require(condition, CustomError());\n"
                "```",
            )
            issues.append(issue)

        return issues

    def _find_public_var_issues(self) -> List[GasIssue]:
        issues = []

        for match in re.finditer(
            r"(uint256|int256|address|bool|string|bytes)\s+(\w+)\s+public",
            self.source_code
        ):
            var_type = match.group(1)
            var_name = match.group(2)
            line_num = self.source_code[:match.start()].count("\n") + 1

            if var_type in ["string", "bytes", "uint256", "int256"]:
                issue = GasIssue(
                    issue_type=GasIssueType.INEFFICIENT_DATA_TYPE,
                    severity="LOW",
                    title="Public Variable with Auto-Generated Getter",
                    description=f"Public {var_type} {var_name} generates an external getter function",
                    location={"variable": var_name, "line": line_num},
                    current_cost=2000,
                    optimized_cost=500,
                    saved_gas=1500,
                    suggestion="Consider using external visibility if getter is not needed externally",
                )
                issues.append(issue)

        return issues

    def _find_repeated_storage_issues(self) -> List[GasIssue]:
        issues = []

        for func_name, func_data in self.functions.items():
            body = func_data["body"]

            for match in re.finditer(r"(\w+)\s*=\s*[^;]+;\s*\1\s*=", body):
                var_name = match.group(1)

                issue = GasIssue(
                    issue_type=GasIssueType.REDUNDANT_CALCULATION,
                    severity="MEDIUM",
                    title="Repeated Storage Access",
                    description=f"Variable {var_name} is assigned multiple times",
                    location={"function": func_name, "line": func_data["line"]},
                    current_cost=5800,
                    optimized_cost=2900,
                    saved_gas=2900,
                    suggestion="Use a memory variable and write to storage once at the end",
                )
                issues.append(issue)

        return issues

    def _find_memory_issues(self) -> List[GasIssue]:
        issues = []

        for match in re.finditer(
            r"function\s+(\w+)\s*\(([^)]+)\)\s+public",
            self.source_code
        ):
            func_name = match.group(1)
            params = match.group(2)

            if "memory" not in params and "calldata" not in params:
                continue

            issue = GasIssue(
                issue_type=GasIssueType.MEMORY_ALLOCATION,
                severity="LOW",
                title="Memory Parameter",
                description=f"Function {func_name} should use calldata instead of memory",
                location={"function": func_name},
                current_cost=500,
                optimized_cost=50,
                saved_gas=450,
                suggestion="Use calldata instead of memory for external functions:\n"
                "```solidity\n"
                "function foo(uint256[] calldata data) external {}\n"
                "```",
            )
            issues.append(issue)

        return issues

    def _calculate_score(self, result: GasAnalysisResult) -> str:
        if result.total_optimization_potential > 100000:
            return "F"
        elif result.total_optimization_potential > 50000:
            return "D"
        elif result.total_optimization_potential > 20000:
            return "C"
        elif result.total_optimization_potential > 5000:
            return "B"
        else:
            return "A"

    def estimate_function_gas(
        self,
        function_name: str,
    ) -> Dict[str, int]:
        if function_name not in self.functions:
            return {}

        body = self.functions[function_name]["body"]

        storage_reads = len(re.findall(r"\.balance|storage\[", body))
        storage_writes = len(re.findall(r"=\s*[^;]+;", body))
        external_calls = len(re.findall(r"\.(call|send)", body))

        return {
            "base": 21000,
            "storage_reads": storage_reads * 2100,
            "storage_writes": storage_writes * 2900,
            "external_calls": external_calls * 2600,
            "total": (
                21000 +
                storage_reads * 2100 +
                storage_writes * 2900 +
                external_calls * 2600
            ),
        }

    def generate_optimization_report(self) -> str:
        result = self.analyze()

        lines = []
        lines.append(f"Gas Analysis Report: {result.contract_name}")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Optimization Score: {result.optimization_score}")
        lines.append(f"Potential Savings: {result.total_optimization_potential:,} gas")
        lines.append("")
        lines.append("Issues Found:")
        lines.append("-" * 30)

        if not result.issues:
            lines.append("No issues found!")
        else:
            for issue in result.issues:
                lines.append(f"[{issue.severity}] {issue.title}")
                lines.append(f"  {issue.description}")
                lines.append(f"  Savings: ~{issue.saved_gas:,} gas")
                lines.append(f"  {issue.suggestion}")
                lines.append("")

        return "\n".join(lines)


def analyze_gas(source_code: str) -> GasAnalysisResult:
    analyzer = GasAnalyzer(source_code)
    return analyzer.analyze()


__all__ = [
    "GasAnalyzer",
    "GasIssueType",
    "GasIssue",
    "GasAnalysisResult",
    "analyze_gas",
]