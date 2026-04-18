"""
Call Graph Analysis

Production-grade call graph analysis for Solidity smart contracts.
Builds and analyzes function call relationships and dependencies.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class CallType(Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    DELEGATE = "delegate"
    STATIC = "static"
    LIBRARY = "library"
    EVENT = "event"
    ERROR = "error"
    CONSTRUCTOR = "constructor"
    FALLBACK = "fallback"


@dataclass
class CallEdge:
    from_function: str
    to_function: str
    call_type: CallType
    line_number: int
    call_target: Optional[str] = None
    value: Optional[str] = None
    gas: Optional[str] = None


@dataclass
class FunctionNode:
    name: str
    visibility: str
    is_view: bool
    is_pure: bool
    is_payable: bool
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    external_calls: List[CallEdge] = field(default_factory=list)


@dataclass
class CallGraph:
    functions: Dict[str, FunctionNode] = field(default_factory=dict)
    edges: List[CallEdge] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)


class CallGraphAnalyzer:
    BUILTIN_FUNCTIONS = {
        "require",
        "assert",
        "revert",
        "keccak256",
        "sha256",
        "ripemd160",
        "ecrecover",
        "blockhash",
        "gasleft",
        "addmod",
        "mulmod",
        "this",
        "super",
        "selfdestruct",
    }

    EXTERNAL_CALL_PATTERNS = [
        r"(\w+)\s*\.\s*(call|send|transfer|delegateCall|callStatic)\s*\(",
        r"(\w+)\s*\.\s*\((\w+)\s*\(",
    ]

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.call_graph: Optional[CallGraph] = None

    def analyze(self) -> CallGraph:
        graph = CallGraph()

        self._extract_functions(graph)
        self._extract_calls(graph)
        self._identify_entry_points(graph)

        self.call_graph = graph
        return graph

    def _extract_functions(self, graph: CallGraph):
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:public|external|internal|private|"
            r"pure|view|payable)\s*)*"
            r"(?:returns\s*\(([^)]+)\))?",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(self.source_code):
            func_name = match.group(1)
            visibility = self._determine_visibility(match.group(3) or "")
            is_pure = "pure" in (match.group(3) or "")
            is_view = "view" in (match.group(3) or "")
            is_payable = "payable" in (match.group(3) or "")

            graph.functions[func_name] = FunctionNode(
                name=func_name,
                visibility=visibility,
                is_view=is_view,
                is_pure=is_pure,
                is_payable=is_payable,
            )

    def _extract_calls(self, graph: CallGraph):
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(self.source_code):
            func_name = match.group(1)
            func_node = graph.functions.get(func_name)
            if not func_node:
                continue

            start = match.start()
            end = self._find_function_end(start)
            func_body = self.source_code[start:end]

            internal_calls = self._find_internal_calls(func_body, func_name)
            func_node.calls.extend(internal_calls)

            external_calls = self._find_external_calls(func_body, func_name)
            func_node.external_calls.extend(external_calls)

            for call in internal_calls:
                if call in graph.functions:
                    target_node = graph.functions[call]
                    if func_name not in target_node.called_by:
                        target_node.called_by.append(func_name)

            for ext_call in external_calls:
                graph.edges.append(ext_call)

    def _determine_visibility(self, modifiers: str) -> str:
        if "public" in modifiers:
            return "public"
        elif "external" in modifiers:
            return "external"
        elif "internal" in modifiers:
            return "internal"
        elif "private" in modifiers:
            return "private"
        return "external"

    def _find_internal_calls(self, body: str, current_func: str) -> List[str]:
        calls = []

        call_pattern = re.compile(r"\b(\w+)\s*\([^)]*\)(?!\s*\.)", re.MULTILINE)

        for match in call_pattern.finditer(body):
            func_name = match.group(1)

            if func_name in self.BUILTIN_FUNCTIONS:
                continue

            if func_name != current_func and func_name in self.source_code:
                if func_name not in calls:
                    calls.append(func_name)

        return calls

    def _find_external_calls(
        self, body: str, current_func: str
    ) -> List[CallEdge]:
        edges = []

        call_pattern = re.compile(
            r"(\w+)\s*\.\s*(call|send|transfer|delegateCall|callStatic)\s*\(",
            re.MULTILINE,
        )

        for match in call_pattern.finditer(body):
            target = match.group(1)
            call_method = match.group(2)
            line_num = body[:match.start()].count("\n") + 1

            call_type = CallType.EXTERNAL
            if call_method == "delegateCall":
                call_type = CallType.DELEGATE

            edges.append(
                CallEdge(
                    from_function=current_func,
                    to_function=target,
                    call_type=call_type,
                    line_number=line_num,
                    call_target=target,
                )
            )

        return edges

    def _find_function_end(self, start: int) -> int:
        brace_count = 0

        for i in range(start, len(self.source_code)):
            char = self.source_code[i]

            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    return i + 1

        return len(self.source_code)

    def _identify_entry_points(self, graph: CallGraph):
        entry_points = []

        for func_name, func_node in graph.functions.items():
            if func_node.visibility in ("external", "public"):
                entry_points.append(func_name)

            if func_name == "constructor":
                entry_points.append(func_name)

        graph.entry_points = entry_points

    def get_callers(self, function_name: str) -> List[str]:
        if not self.call_graph:
            return []

        func_node = self.call_graph.functions.get(function_name)
        if func_node:
            return func_node.called_by

        return []

    def get_callees(self, function_name: str) -> List[str]:
        if not self.call_graph:
            return []

        func_node = self.call_graph.functions.get(function_name)
        if func_node:
            return func_node.calls

        return []

    def is_reachable(self, from_func: str, to_func: str) -> bool:
        if not self.call_graph:
            return False

        if from_func not in self.call_graph.functions:
            return False

        visited = set()
        queue = deque([from_func])

        while queue:
            current = queue.popleft()

            if current == to_func:
                return True

            if current in visited:
                continue

            visited.add(current)

            func_node = self.call_graph.functions.get(current)
            if func_node:
                for callee in func_node.calls:
                    if callee not in visited:
                        queue.append(callee)

        return False

    def find_circular_dependencies(self) -> List[List[str]]:
        if not self.call_graph:
            return []

        cycles = []
        visited = set()
        rec_stack = set()

        def dfs(func_name: str, path: List[str]) -> bool:
            if func_name in rec_stack:
                cycle_start = path.index(func_name)
                cycles.append(path[cycle_start:] + [func_name])
                return True

            if func_name in visited:
                return False

            visited.add(func_name)
            rec_stack.append(func_name)

            func_node = self.call_graph.functions.get(func_name)
            if func_node:
                for callee in func_node.calls:
                    if callee in self.call_graph.functions:
                        dfs(callee, path + [callee])

            rec_stack.remove(func_name)
            return False

        for func_name in self.call_graph.functions:
            if func_name not in visited:
                dfs(func_name, [func_name])

        return cycles

    def calculate_depth(self, function_name: str) -> int:
        if not self.call_graph:
            return 0

        if function_name not in self.call_graph.functions:
            return 0

        max_depth = 0

        def traverse(func: str, depth: int):
            nonlocal max_depth
            max_depth = max(max_depth, depth)

            func_node = self.call_graph.functions.get(func)
            if func_node:
                for callee in func_node.calls:
                    if callee in self.call_graph.functions:
                        traverse(callee, depth + 1)

        traverse(function_name, 1)
        return max_depth

    def find_external_calls(self, function_name: str) -> List[CallEdge]:
        if not self.call_graph:
            return []

        func_node = self.call_graph.functions.get(function_name)
        if func_node:
            return func_node.external_calls

        return []

    def get_call_graph_summary(self) -> Dict[str, Any]:
        if not self.call_graph:
            return {}

        total_functions = len(self.call_graph.functions)
        total_edges = len(self.call_graph.edges)
        entry_points = len(self.call_graph.entry_points)

        external_calls = sum(
            len(func.external_calls)
            for func in self.call_graph.functions.values()
        )

        return {
            "total_functions": total_functions,
            "total_call_edges": total_edges,
            "external_calls": external_calls,
            "entry_points": entry_points,
        }


def analyze_calls(source_code: str) -> CallGraph:
    analyzer = CallGraphAnalyzer(source_code)
    return analyzer.analyze()


__all__ = [
    "CallGraphAnalyzer",
    "CallType",
    "CallEdge",
    "FunctionNode",
    "CallGraph",
    "analyze_calls",
]