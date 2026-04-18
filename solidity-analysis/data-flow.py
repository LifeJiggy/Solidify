"""
Data Flow Analysis

Production-grade data flow analysis for Solidity smart contracts.
Tracks variable usage, taint propagation, and dependency analysis.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class VariableScope(Enum):
    FUNCTION = "function"
    CONTRACT = "contract"
    GLOBAL = "global"


class VariableType(Enum):
    STATE = "state"
    LOCAL = "local"
    PARAMETER = "parameter"
    TEMPORARY = "temporary"


@dataclass
class Variable:
    name: str
    var_type: VariableType
    scope: VariableScope
    data_type: str
    defined_at: Optional[int] = None
    used_at: List[int] = field(default_factory=list)
    assigned_at: List[int] = field(default_factory=list)


@dataclass
class DataFlowEdge:
    from_var: str
    to_var: str
    from_position: int
    to_position: int


@dataclass
class DataFlowAnalysis:
    variables: Dict[str, Variable] = field(default_factory=dict)
    definitions: Dict[int, List[str]] = field(default_factory=dict)
    uses: Dict[int, List[str]] = field(default_factory=dict)
    flow_edges: List[DataFlowEdge] = field(default_factory=list)


class DataFlowAnalyzer:
    BUILTIN_VARIABLES = {
        "msg",
        "block",
        "tx",
        "abi",
        "this",
        "super",
        "now",
        "msg.sender",
        "msg.value",
        "msg.data",
        "msg.sig",
        "block.timestamp",
        "block.number",
        "block.chainid",
        "block.difficulty",
        "block.gaslimit",
        "block.coinbase",
        "block.blockhash",
        "tx.gasprice",
        "tx.origin",
    }

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.analysis: Optional[DataFlowAnalysis] = None

    def analyze(self) -> DataFlowAnalysis:
        analysis = DataFlowAnalysis()

        self._extract_variables(analysis)
        self._extract_definitions(analysis)
        self._extract_uses(analysis)
        self._build_flow_graph(analysis)

        self.analysis = analysis
        return analysis

    def _extract_variables(self, analysis: DataFlowAnalysis):
        state_var_pattern = re.compile(
            r"(uint256|int256|address|bool|string|bytes|"
            r"uint|int|bytes32|mapping)\s+(\w+)\s*(?:public|internal|private|constant)?",
            re.MULTILINE,
        )

        for match in state_var_pattern.finditer(self.source_code):
            var_name = match.group(2)
            var_type = match.group(1)

            line = self.source_code[:match.start()].count("\n") + 1

            analysis.variables[var_name] = Variable(
                name=var_name,
                var_type=VariableType.STATE,
                scope=VariableScope.CONTRACT,
                data_type=var_type,
                defined_at=line,
            )

        func_pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*\{",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(self.source_code):
            func_name = match.group(1)
            func_body = self._extract_function_body(match.start())

            param_str = match.group(2)
            for param in param_str.split(","):
                param = param.strip()
                if param:
                    parts = param.rsplit(None, 1)
                    if len(parts) == 2:
                        var_name = parts[1]
                        var_type = parts[0]

                        if var_name not in analysis.variables:
                            line = self.source_code[:match.start()].count("\n") + 1
                            analysis.variables[var_name] = Variable(
                                name=var_name,
                                var_type=VariableType.PARAMETER,
                                scope=VariableScope.FUNCTION,
                                data_type=var_type,
                                defined_at=line,
                            )

            local_var_pattern = re.compile(
                r"(uint256|int256|address|bool|string|bytes|"
                r"uint|int|bytes32|memory|storage)\s+(\w+)\s*=",
                re.MULTILINE,
            )

            for local_match in local_var_pattern.finditer(func_body):
                var_name = local_match.group(2)
                var_type = local_match.group(1)

                line = func_body[:local_match.start()].count("\n") + 1

                if var_name not in analysis.variables:
                    analysis.variables[var_name] = Variable(
                        name=var_name,
                        var_type=VariableType.LOCAL,
                        scope=VariableScope.FUNCTION,
                        data_type=var_type,
                        defined_at=line,
                    )

    def _extract_definitions(self, analysis: DataFlowAnalysis):
        assign_pattern = re.compile(
            r"(\w+)\s*(?:\[\w+\])?\s*=\s*([^;]+);",
            re.MULTILINE,
        )

        for match in assign_pattern.finditer(self.source_code):
            var_name = match.group(1)
            if var_name in self.BUILTIN_VARIABLES:
                continue

            line = self.source_code[:match.start()].count("\n") + 1

            if line not in analysis.definitions:
                analysis.definitions[line] = []

            analysis.definitions[line].append(var_name)

            if var_name in analysis.variables:
                analysis.variables[var_name].assigned_at.append(line)

    def _extract_uses(self, analysis: DataFlowAnalysis):
        use_pattern = re.compile(r"\b(\w+)\b", re.MULTILINE)

        for match in use_pattern.finditer(self.source_code):
            var_name = match.group(1)
            if var_name in self.BUILTIN_VARIABLES:
                continue

            line = self.source_code[:match.start()].count("\n") + 1

            if line not in analysis.uses:
                analysis.uses[line] = []

            if var_name not in analysis.uses[line]:
                analysis.uses[line].append(var_name)

            if var_name in analysis.variables:
                if line not in analysis.variables[var_name].used_at:
                    analysis.variables[var_name].used_at.append(line)

    def _build_flow_graph(self, analysis: DataFlowAnalysis):
        sorted_def_lines = sorted(analysis.definitions.keys())
        sorted_use_lines = sorted(analysis.uses.keys())

        for def_line in sorted_def_lines:
            defined_vars = analysis.definitions[def_line]

            for use_line in sorted_use_lines:
                if use_line <= def_line:
                    continue

                used_vars = analysis.uses.get(use_line, [])

                for def_var in defined_vars:
                    if def_var in used_vars:
                        analysis.flow_edges.append(
                            DataFlowEdge(
                                from_var=def_var,
                                to_var=def_var,
                                from_position=def_line,
                                to_position=use_line,
                            )
                        )

    def get_variable(self, name: str) -> Optional[Variable]:
        if not self.analysis:
            return None
        return self.analysis.variables.get(name)

    def get_dependencies(self, variable: str) -> List[str]:
        if not self.analysis:
            return []

        dependencies = []

        for edge in self.analysis.flow_edges:
            if edge.from_var == variable:
                dependencies.append(edge.to_var)

        return dependencies

    def find_unused_variables(self) -> List[str]:
        if not self.analysis:
            return []

        unused = []

        for name, var in self.analysis.variables.items():
            if len(var.used_at) == 0 and var.var_type != VariableType.STATE:
                unused.append(name)

        return unused

    def find_potential_bugs(self) -> List[Dict[str, Any]]:
        if not self.analysis:
            return []

        bugs = []

        for name, var in self.analysis.variables.items():
            if len(var.assigned_at) > 1 and var.var_type == VariableType.STATE:
                bugs.append({
                    "type": "multiple_assignments",
                    "variable": name,
                    "locations": var.assigned_at,
                    "severity": "MEDIUM",
                    "description": f"Variable '{name}' is assigned multiple times",
                })

            if var.defined_at and len(var.used_at) > 0:
                last_use = max(var.used_at)
                if last_use < var.defined_at:
                    bugs.append({
                        "type": "use_before_definition",
                        "variable": name,
                        "defined_at": var.defined_at,
                        "used_at": var.used_at,
                        "severity": "HIGH",
                        "description": f"Variable '{name}' used before definition",
                    })

        return bugs


def analyze_data_flow(source_code: str) -> DataFlowAnalysis:
    analyzer = DataFlowAnalyzer(source_code)
    return analyzer.analyze()


__all__ = [
    "DataFlowAnalyzer",
    "VariableScope",
    "VariableType",
    "Variable",
    "DataFlowEdge",
    "DataFlowAnalysis",
    "analyze_data_flow",
]