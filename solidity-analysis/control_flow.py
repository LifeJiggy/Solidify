"""
Control Flow Analysis

Production-grade control flow analysis for Solidity smart contracts.
Identifies control flow graphs, branches, loops, and complexity metrics.

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


class ControlFlowNodeType(Enum):
    ENTRY = "entry"
    EXIT = "exit"
    STATEMENT = "statement"
    BRANCH = "branch"
    LOOP = "loop"
    JUMP = "jump"
    RETURN = "return"
    CALL = "call"


@dataclass
class ControlFlowNode:
    id: int
    node_type: ControlFlowNodeType
    statement: str
    line_number: int
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)


@dataclass
class ControlFlowEdge:
    from_node: int
    to_node: int
    edge_type: str = "normal"


@dataclass
class BasicBlock:
    start_line: int
    end_line: int
    statements: List[str] = field(default_factory=list)
    nodes: List[ControlFlowNode] = field(default_factory=list)


@dataclass
class ControlFlowGraph:
    entry_node: int
    exit_node: int
    nodes: Dict[int, ControlFlowNode] = field(default_factory=dict)
    edges: List[ControlFlowEdge] = field(default_factory=list)
    basic_blocks: List[BasicBlock] = field(default_factory=list)


class ControlFlowAnalyzer:
    BRANCH_KEYWORDS = {"if", "else", "switch", "case"}
    LOOP_KEYWORDS = {"for", "while", "do"}
    JUMP_KEYWORDS = {"return", "break", "continue", "goto", "throw"}

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.cfg: Optional[ControlFlowGraph] = None

    def analyze(self, function_name: str = "") -> ControlFlowGraph:
        if function_name:
            return self._analyze_function(function_name)
        return self._analyze_all_functions()

    def _analyze_function(self, function_name: str) -> ControlFlowGraph:
        func = self._extract_function(function_name)
        if not func:
            raise ValueError(f"Function not found: {function_name}")

        cfg = ControlFlowGraph(
            entry_node=0,
            exit_node=1,
            nodes={},
            edges=[],
        )

        node_id = 0
        entry = ControlFlowNode(
            id=node_id,
            node_type=ControlFlowNodeType.ENTRY,
            statement="Entry",
            line_number=func.get("line", 0),
        )
        cfg.nodes[node_id] = entry
        node_id += 1

        statements = self._extract_statements(func["body"])
        current_block_id = node_id

        for stmt in statements:
            node = ControlFlowNode(
                id=current_block_id,
                node_type=self._determine_node_type(stmt),
                statement=stmt["text"],
                line_number=stmt["line"],
            )
            cfg.nodes[current_block_id] = node
            current_block_id += 1

        exit_node = ControlFlowNode(
            id=current_block_id,
            node_type=ControlFlowNodeType.EXIT,
            statement="Exit",
            line_number=func.get("end_line", 0),
        )
        cfg.nodes[current_block_id] = exit_node

        cfg.entry_node = 0
        cfg.exit_node = current_block_id

        self._connect_nodes(cfg, len(statements))
        self._detect_branches(cfg, statements)
        self._detect_loops(cfg, statements)

        self.cfg = cfg
        return cfg

    def _analyze_all_functions(self) -> ControlFlowGraph:
        self._extract_functions()

        combined_cfg = ControlFlowGraph(
            entry_node=0,
            exit_node=1,
            nodes={},
            edges=[],
        )

        return combined_cfg

    def _extract_function(self, name: str) -> Optional[Dict[str, Any]]:
        pattern = re.compile(
            rf"function\s+{name}\s*\([^)]*\)\s*"
            r"((?:public|external|internal|private|pure|view|payable)\s*)*"
            r"\{",
            re.MULTILINE,
        )

        match = pattern.search(self.source_code)
        if not match:
            return None

        start = match.start()
        end = self._find_brace_end(start)

        return {
            "name": name,
            "body": self.source_code[start:end],
            "line": self.source_code[:start].count("\n") + 1,
            "end_line": self.source_code[:end].count("\n") + 1,
        }

    def _extract_functions(self):
        pattern = re.compile(
            r"function\s+(\w+)\s*\([^)]*\)\s*"
            r"((?:public|external|internal|private|pure|view|payable)\s*)*"
            r"\{",
            re.MULTILINE,
        )

        for match in pattern.finditer(self.source_code):
            func_name = match.group(1)
            start = match.start()
            end = self._find_brace_end(start)

            self.functions[func_name] = {
                "name": func_name,
                "body": self.source_code[start:end],
                "line": self.source_code[:start].count("\n") + 1,
            }

    def _find_brace_end(self, start: int) -> int:
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

    def _extract_statements(self, body: str) -> List[Dict[str, Any]]:
        statements = []

        lines = body.split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("/*"):
                continue

            statements.append({
                "text": line,
                "line": body[:body.find(line)].count("\n") + 1,
            })

        return statements

    def _determine_node_type(self, statement: str) -> ControlFlowNodeType:
        stmt = statement["text"] if isinstance(statement, dict) else statement
        stmt = stmt.strip()

        if any(kw in stmt.lower() for kw in self.LOOP_KEYWORDS):
            return ControlFlowNodeType.LOOP

        if any(kw in stmt.lower() for kw in self.BRANCH_KEYWORDS):
            return ControlFlowNodeType.BRANCH

        if any(kw in stmt.lower() for kw in self.JUMP_KEYWORDS):
            return ControlFlowNodeType.JUMP

        return ControlFlowNodeType.STATEMENT

    def _connect_nodes(self, cfg: ControlFlowGraph, statement_count: int):
        if cfg.nodes.get(0) and statement_count > 0:
            cfg.nodes[0].successors.append(2)

        for i in range(2, 2 + statement_count - 1):
            if i in cfg.nodes:
                cfg.nodes[i].successors.append(i + 1)
                cfg.edges.append(ControlFlowEdge(i, i + 1))

        last_node = 2 + statement_count - 1
        if last_node in cfg.nodes:
            cfg.nodes[last_node].successors.append(cfg.exit_node)
            cfg.edges.append(ControlFlowEdge(last_node, cfg.exit_node))

    def _detect_branches(self, cfg: ControlFlowGraph, statements: List[Dict[str, Any]]):
        for i, stmt in enumerate(statements):
            stmt_text = stmt.get("text", "")
            if "if" in stmt_text.lower():
                node_id = 2 + i

                if_node = cfg.nodes.get(node_id)
                if if_node:
                    true_target = node_id + 1
                    false_target = self._find_else_target(statements, i)

                    if true_target != false_target:
                        if_node.successors.extend([true_target, false_target])
                        cfg.edges.append(
                            ControlFlowEdge(node_id, true_target, "true")
                        )
                        cfg.edges.append(
                            ControlFlowEdge(node_id, false_target, "false")
                        )

    def _detect_loops(self, cfg: ControlFlowGraph, statements: List[Dict[str, Any]]):
        for i, stmt in enumerate(statements):
            stmt_text = stmt.get("text", "")

            if any(kw in stmt_text.lower() for kw in self.LOOP_KEYWORDS):
                node_id = 2 + i

                loop_node = cfg.nodes.get(node_id)
                if loop_node:
                    loop_node.node_type = ControlFlowNodeType.LOOP

    def _find_else_target(self, statements: List[Dict[str, Any]], if_index: int) -> int:
        for i in range(if_index + 1, len(statements)):
            stmt = statements[i].get("text", "")
            if "else" in stmt.lower():
                return 2 + i

        return 2 + len(statements) - 1

    def calculate_complexity(self) -> Dict[str, int]:
        if not self.cfg:
            return {}

        complexity = 1
        branches = 0
        loops = 0

        for node in self.cfg.nodes.values():
            if node.node_type == ControlFlowNodeType.BRANCH:
                branches += 1
                complexity += 1
            elif node.node_type == ControlFlowNodeType.LOOP:
                loops += 1
                complexity += 1

        return {
            "cyclomatic_complexity": complexity,
            "branches": branches,
            "loops": loops,
            "total_nodes": len(self.cfg.nodes),
            "total_edges": len(self.cfg.edges),
        }

    def find_reachable_nodes(self, start: int) -> Set[int]:
        if not self.cfg:
            return set()

        visited = set()
        stack = [start]

        while stack:
            node_id = stack.pop()
            if node_id in visited:
                continue

            visited.add(node_id)

            node = self.cfg.nodes.get(node_id)
            if node:
                for successor in node.successors:
                    if successor not in visited:
                        stack.append(successor)

        return visited

    def detect_unreachable_code(self) -> List[int]:
        if not self.cfg:
            return []

        reachable = self.find_reachable_nodes(self.cfg.entry_node)

        unreachable = []
        for node_id in self.cfg.nodes:
            if node_id not in reachable and node_id != self.cfg.exit_node:
                unreachable.append(node_id)

        return unreachable


def analyze_control_flow(source_code: str, function_name: str = "") -> ControlFlowGraph:
    analyzer = ControlFlowAnalyzer(source_code)
    return analyzer.analyze(function_name)


__all__ = [
    "ControlFlowAnalyzer",
    "ControlFlowNodeType",
    "ControlFlowNode",
    "ControlFlowEdge",
    "BasicBlock",
    "ControlFlowGraph",
    "analyze_control_flow",
]