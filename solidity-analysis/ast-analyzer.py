"""
AST Analyzer

Abstract Syntax Tree (AST) analysis for Solidity smart contracts.
Parses Solidity source code into AST and performs deep analysis.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ASTNodeType(Enum):
    SOURCE_UNIT = "SourceUnit"
    CONTRACT_DEFINITION = "ContractDefinition"
    FUNCTION_DEFINITION = "FunctionDefinition"
    VARIABLE_DECLARATION = "VariableDeclaration"
    EXPRESSION_STATEMENT = "ExpressionStatement"
    IF_STATEMENT = "IfStatement"
    FOR_STATEMENT = "ForStatement"
    WHILE_STATEMENT = "WhileStatement"
    DO_WHILE_STATEMENT = "DoWhileStatement"
    RETURN_STATEMENT = "ReturnStatement"
    EMIT_STATEMENT = "EmitStatement"
    UNARY_OPERATION = "UnaryOperation"
    BINARY_OPERATION = "BinaryOperation"
    MEMBER_ACCESS = "MemberAccess"
    INDEX_ACCESS = "IndexAccess"
    FUNCTION_CALL = "FunctionCall"
    MAPPING = "Mapping"
    STRUCT_DEFINITION = "StructDefinition"
    ENUM_DEFINITION = "EnumDefinition"


@dataclass
class ASTNode:
    node_type: str
    name: Optional[str]
    attributes: Dict[str, Any] = field(default_factory=dict)
    children: List["ASTNode"] = field(default_factory=list)
    line_number: int = 0
    source_span: Tuple[int, int] = (0, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": self.node_type,
            "name": self.name,
            "attributes": self.attributes,
            "children": [c.to_dict() for c in self.children],
            "line_number": self.line_number,
        }

    def find_nodes(self, node_type: str) -> List["ASTNode"]:
        results = []
        if self.node_type == node_type:
            results.append(self)
        for child in self.children:
            results.extend(child.find_nodes(node_type))
        return results

    def get_attribute(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)


@dataclass
class ImportDirective:
    file: str
    symbol_aliases: Dict[str, str] = field(default_factory=dict)
    unit_alias: Optional[str] = None


@dataclass
class ContractDefinition:
    name: str
    kind: str
    base_contracts: List[str] = field(default_factory=list)
    sub_nodes: List[ASTNode] = field(default_factory=list)
    linearized_base: List[str] = field(default_factory=list)
    documentation: Optional[str] = None


@dataclass
class FunctionDefinition:
    name: str
    visibility: str
    state_mutability: str
    kind: str
    parameters: List[ASTNode] = field(default_factory=list)
    return_parameters: List[ASTNode] = field(default_factory=list)
    modifiers: List[ASTNode] = field(default_factory=list)
    body: Optional[ASTNode] = None
    override: List[str] = field(default_factory=list)


@dataclass
class VariableDeclaration:
    name: str
    type_string: str
    visibility: str
    mutability: str
    value: Optional[ASTNode] = None
    override: List[str] = field(default_factory=list)


@dataclass
class Statement:
    node_type: str
    expression: Optional[ASTNode] = None
    statements: List[ASTNode] = field(default_factory=list)


class ASTAnalyzer:
    KEYWORDS = {
        "contract",
        "interface",
        "library",
        "struct",
        "enum",
        "function",
        "modifier",
        "event",
        "error",
        "constructor",
        "fallback",
        "receive",
        "using",
        "import",
        "pragma",
    }

    VISIBILITY_KEYWORDS = {"public", "external", "internal", "private"}

    STATE_MUTABILITY = {"pure", "view", "payable", "nonpayable"}

    EXPRESSION_OPERATORS = {
        "+",
        "-",
        "*",
        "/",
        "%",
        "**",
        "<<",
        ">>",
        "&",
        "|",
        "^",
        "~",
        "&&",
        "||",
        "==",
        "!=",
        "<",
        ">",
        "<=",
        ">=",
        "=",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "<<=",
        ">>=",
        "&=",
        "|=",
        "^=",
    }

    BUILTIN_FUNCTIONS = {
        "block",
        "msg",
        "tx",
        "abi",
        "this",
        "super",
        "selfdestruct",
        "revert",
        "require",
        "assert",
        "emit",
        "type",
        "new",
        "delete",
        "echo",
        "gasleft",
        "blockhash",
        "ecrecover",
        "keccak256",
        "sha256",
        "ripemd160",
        "addmod",
        "mulmod",
    }

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.tokens: List[Dict[str, Any]] = []
        self.ast: Optional[ASTNode] = None
        self.contracts: List[ContractDefinition] = []
        self.functions: List[FunctionDefinition] = []
        self.variables: List[VariableDeclaration] = []

    def parse(self) -> ASTNode:
        self.tokens = self._tokenize()
        self.ast = self._build_ast()
        self._extract_definitions()
        return self.ast

    def _tokenize(self) -> List[Dict[str, Any]]:
        tokens = []
        position = 0
        line_number = 1

        token_patterns = [
            ("COMMENT_MULTI", r"/\*[\s\S]*?\*/"),
            ("COMMENT_SINGLE", r"//[^\n]*"),
            ("STRING", r'"(?:[^"\\]|\\.)*"'),
            ("HEX_STRING", r"hex'(?:[0-9a-fA-F]{2})*'"),
            ("ADDRESS", r"0x[0-9a-fA-F]{40}"),
            ("NUMBER", r"\b\d+(\.\d+)?(gwei|ether|wei)?\b"),
            ("IDENTIFIER", r"\b[a-zA-Z_][a-zA-Z0-9_]*\b"),
            ("LPAREN", r"\("),
            ("RPAREN", r"\)"),
            ("LBRACE", r"\{"),
            ("RBRACE", r"\}"),
            ("LBRACKET", r"\["),
            ("RBRACKET", r"\]"),
            ("COLON", r":"),
            ("SEMICOLON", r";"),
            ("COMMA", r","),
            ("DOT", r"\."),
            ("ASSIGN", r"=>"),
            ("OPERATOR", r"(?:" + "|".join(re.escape(op) for op in sorted(self.EXPRESSION_OPERATORS, key=len, reverse=True)) + r")"),
            ("WHITESPACE", r"\s+"),
        ]

        token_pattern = re.compile(
            "|".join(f"(?P<{name}>{pattern})" for name, pattern in token_patterns)
        )

        for match in token_pattern.finditer(self.source_code):
            token_type = match.lastgroup
            token_value = match.group()

            if token_type == "WHITESPACE":
                line_number += token_value.count("\n")
                continue

            if token_type in ("COMMENT_MULTI", "COMMENT_SINGLE"):
                line_number += token_value.count("\n")
                continue

            tokens.append({
                "type": token_type,
                "value": token_value,
                "line": line_number,
                "position": position,
            })

            position = match.end()

        return tokens

    def _build_ast(self) -> ASTNode:
        root = ASTNode(
            node_type=ASTNodeType.SOURCE_UNIT.value,
            name=None,
            line_number=1,
        )

        contracts = self._find_contracts()
        for contract_node in contracts:
            root.children.append(contract_node)

        return root

    def _find_contracts(self) -> List[ASTNode]:
        contract_nodes = []

        contract_pattern = re.compile(
            r"(contract|interface|library)\s+(\w+)\s*(?:is\s+([^{]+))?\s*\{",
            re.MULTILINE,
        )

        for match in contract_pattern.finditer(self.source_code):
            contract_type = match.group(1)
            contract_name = match.group(2)
            inherit = match.group(3) or ""

            line_number = self.source_code[:match.start()].count("\n") + 1

            node = ASTNode(
                node_type=ASTNodeType.CONTRACT_DEFINITION.value,
                name=contract_name,
                line_number=line_number,
                attributes={
                    "kind": contract_type,
                    "baseContracts": [i.strip() for i in inherit.split(",") if i.strip()],
                },
            )

            contract_nodes.append(node)

        return contract_nodes

    def _extract_definitions(self):
        for contract_match in re.finditer(
            r"(contract|interface|library)\s+(\w+)\s*(?:is\s+([^{]+))?\s*\{",
            self.source_code
        ):
            contract_name = contract_match.group(2)

            functions = self._extract_functions_in_contract(
                contract_name
            )
            self.functions.extend(functions)

            vars = self._extract_variables_in_contract(contract_name)
            self.variables.extend(vars)

    def _extract_functions_in_contract(
        self,
        contract_name: str,
    ) -> List[FunctionDefinition]:
        functions = []

        func_pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:public|external|internal|private|pure|view|payable|nonpayable)\s*)*"
            r"(?:returns\s*\(([^)]+)\))?\s*\{",
            re.MULTILINE,
        )

        for match in func_pattern.finditer(self.source_code):
            func_name = match.group(1)
            func = FunctionDefinition(
                name=func_name,
                visibility="external",
                state_mutability="nonpayable",
                kind="function",
            )

            if "public" in match.group(0):
                func.visibility = "public"
            elif "external" in match.group(0):
                func.visibility = "external"
            elif "internal" in match.group(0):
                func.visibility = "internal"
            elif "private" in match.group(0):
                func.visibility = "private"

            if "pure" in match.group(0):
                func.state_mutability = "pure"
            elif "view" in match.group(0):
                func.state_mutability = "view"
            elif "payable" in match.group(0):
                func.state_mutability = "payable"

            functions.append(func)

        return functions

    def _extract_variables_in_contract(
        self,
        contract_name: str,
    ) -> List[VariableDeclaration]:
        variables = []

        var_pattern = re.compile(
            r"(uint256|int256|address|bool|bytes32|string|bytes|"
            r"uint8|uint16|uint32|uint64|uint128|"
            r"int8|int16|int32|int64|int128|mapping)"
            r"\s+(\w+)\s*(?:public|internal|private|"
            r"memory|storage|immutable|constant)?",
            re.MULTILINE,
        )

        for match in var_pattern.finditer(self.source_code):
            var_type = match.group(0).split()[0]
            var_name = match.group(1)

            visibility = "internal"
            if "public" in match.group(0):
                visibility = "public"
            elif "private" in match.group(0):
                visibility = "private"

            variables.append(
                VariableDeclaration(
                    name=var_name,
                    type_string=var_type,
                    visibility=visibility,
                    mutability="mutable",
                )
            )

        return variables

    def get_contract(
        self,
        name: str,
    ) -> Optional[ContractDefinition]:
        for contract in self.contracts:
            if contract.name == name:
                return contract
        return None

    def get_function(
        self,
        name: str,
    ) -> Optional[FunctionDefinition]:
        for func in self.functions:
            if func.name == name:
                return func
        return None

    def get_variable(
        self,
        name: str,
    ) -> Optional[VariableDeclaration]:
        for var in self.variables:
            if var.name == name:
                return var
        return None

    def find_calls(
        self,
        function_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        calls = []

        call_pattern = re.compile(
            r"(\w+)\s*\.\s*(\w+)\s*\(|"
            r"(\w+)\s*\(",
            re.MULTILINE,
        )

        for match in call_pattern.finditer(self.source_code):
            target = match.group(1) or ""
            func = match.group(2) or match.group(3) or ""

            if target and target in self.BUILTIN_FUNCTIONS:
                continue

            calls.append({
                "target": target,
                "function": func,
                "line": self.source_code[:match.start()].count("\n") + 1,
            })

        return calls

    def find_modifiers(self) -> List[str]:
        modifiers = []

        mod_pattern = re.compile(
            r"modifier\s+(\w+)",
            re.MULTILINE,
        )

        for match in mod_pattern.finditer(self.source_code):
            modifiers.append(match.group(1))

        return modifiers

    def find_events(self) -> List[str]:
        events = []

        event_pattern = re.compile(
            r"event\s+(\w+)\s*\(",
            re.MULTILINE,
        )

        for match in event_pattern.finditer(self.source_code):
            events.append(match.group(1))

        return events

    def find_errors(self) -> List[str]:
        errors = []

        error_pattern = re.compile(
            r"error\s+(\w+)\s*\(",
            re.MULTILINE,
        )

        for match in error_pattern.finditer(self.source_code):
            errors.append(match.group(1))

        return errors

    def get_inheritance_hierarchy(
        self,
    ) -> Dict[str, List[str]]:
        hierarchy = {}

        inherit_pattern = re.compile(
            r"(contract|interface|library)\s+(\w+)\s*is\s+([^{]+)\s*\{",
            re.MULTILINE,
        )

        for match in inherit_pattern.finditer(self.source_code):
            name = match.group(2)
            bases = [b.strip() for b in match.group(3).split(",")]
            hierarchy[name] = bases

        return hierarchy

    def analyze_complexity(self) -> Dict[str, Any]:
        complexity = {
            "cyclomatic": 1,
            "functions": len(self.functions),
            "variables": len(self.variables),
            "contracts": len(self.contracts),
            "events": len(self.find_events()),
            "modifiers": len(self.find_modifiers()),
            "inheritance_depth": self._get_inheritance_depth(),
        }

        complexity["cyclomatic"] += len(re.findall(
            r"\bif\s*\(|for\s*\(|while\s*\(|&&\s*|\|\|\s*",
            self.source_code
        ))

        return complexity

    def _get_inheritance_depth(self) -> int:
        hierarchy = self.get_inheritance_hierarchy()
        if not hierarchy:
            return 0

        max_depth = 0
        for bases in hierarchy.values():
            max_depth = max(max_depth, len(bases))

        return max_depth


def create_ast_analyzer(source_code: str) -> ASTAnalyzer:
    analyzer = ASTAnalyzer(source_code)
    analyzer.parse()
    return analyzer


__all__ = [
    "ASTAnalyzer",
    "ASTNodeType",
    "ASTNode",
    "ImportDirective",
    "ContractDefinition",
    "FunctionDefinition",
    "VariableDeclaration",
    "Statement",
    "create_ast_analyzer",
]