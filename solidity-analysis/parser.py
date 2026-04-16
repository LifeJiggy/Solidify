"""
Solidity Parser

Production-grade Solidity smart contract parser for code analysis.
Tokenizes and parses Solidity source code into structured representations.

Author: Joel Emmanuel Adinoyi
Security Lead - Team Solidify
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TokenType(Enum):
    KEYWORD = "KEYWORD"
    IDENTIFIER = "IDENTIFIER"
    STRING = "STRING"
    NUMBER = "NUMBER"
    ADDRESS = "ADDRESS"
    OPERATOR = "OPERATOR"
    DELIMITER = "DELIMITER"
    COMMENT = "COMMENT"
    WHITESPACE = "WHITESPACE"


class Token:
    def __init__(
        self,
        token_type: TokenType,
        value: str,
        line: int,
        column: int,
    ):
        self.type = token_type
        self.value = value
        self.line = line
        self.column = column

    def __repr__(self):
        return f"Token({self.type.value}, '{self.value}', L{self.line}:C{self.column})"


@dataclass
class SourceLocation:
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass
class ParsedContract:
    name: str
    kind: str
    base_contracts: List[str] = field(default_factory=list)
    documentation: Optional[str] = None
    location: Optional[SourceLocation] = None


@dataclass
class ParsedFunction:
    name: str
    visibility: str
    state_mutability: str
    kind: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    return_parameters: List[Dict[str, str]] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    body_location: Optional[SourceLocation] = None


@dataclass
class ParsedVariable:
    name: str
    type: str
    visibility: str
    mutability: str
    location: Optional[SourceLocation] = None


@dataclass
class ParsedEvent:
    name: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    location: Optional[SourceLocation] = None


class SolidityParser:
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
        "import",
        "using",
        "pragma",
        "abstract",
        "virtual",
        "override",
        "immutable",
        "payable",
        "pure",
        "view",
        "external",
        "public",
        "internal",
        "private",
        "storage",
        "memory",
        "calldata",
        "indexed",
        "anonymous",
        "type",
        "assembly",
        "try",
        "catch",
        "return",
        "returns",
        "emit",
        "for",
        "while",
        "do",
        "if",
        "else",
        "break",
        "continue",
        "unchecked",
        "false",
        "true",
        "this",
        "super",
        "now",
        "wei",
        "ether",
        "seconds",
        "minutes",
        "hours",
        "days",
        "weeks",
    }

    TYPE_KEYWORDS = {
        "uint8",
        "uint16",
        "uint24",
        "uint32",
        "uint40",
        "uint48",
        "uint56",
        "uint64",
        "uint72",
        "uint80",
        "uint88",
        "uint96",
        "uint104",
        "uint112",
        "uint120",
        "uint128",
        "uint136",
        "uint144",
        "uint152",
        "uint160",
        "uint168",
        "uint176",
        "uint184",
        "uint192",
        "uint200",
        "uint208",
        "uint216",
        "uint224",
        "uint232",
        "uint240",
        "uint248",
        "uint256",
        "int8",
        "int16",
        "int24",
        "int32",
        "int40",
        "int48",
        "int56",
        "int64",
        "int72",
        "int80",
        "int88",
        "int96",
        "int104",
        "int112",
        "int120",
        "int128",
        "int136",
        "int144",
        "int152",
        "int160",
        "int168",
        "int176",
        "int184",
        "int192",
        "int200",
        "int208",
        "int216",
        "int224",
        "int232",
        "int240",
        "int248",
        "int256",
        "address",
        "bool",
        "bytes1",
        "bytes2",
        "bytes4",
        "bytes8",
        "bytes16",
        "bytes24",
        "bytes32",
        "byte",
        "string",
        "bytes",
        "uint",
        "int",
    }

    OPERATORS = {
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
        "++",
        "--",
        "=>",
    }

    DELIMITERS = {
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        ",",
        ":",
        ";",
        ".",
        "?",
    }

    def __init__(self, source_code: str = ""):
        self.source_code = source_code
        self.tokens: List[Token] = []
        self.contracts: List[ParsedContract] = []
        self.functions: List[ParsedFunction] = []
        self.variables: List[ParsedVariable] = []
        self.events: List[ParsedEvent] = []

    def parse(self):
        self.tokens = self._tokenize()
        self._parse_structure()
        return self

    def _tokenize(self) -> List[Token]:
        tokens = []
        position = 0
        line = 1
        column = 1

        patterns = [
            (r"/\*[\s\S]*?\*/", TokenType.COMMENT),
            (r"//[^\n]*", TokenType.COMMENT),
            (r'"(?:[^"\\]|\\.)*"', TokenType.STRING),
            (r"hex'(?:[0-9a-fA-F]{2})*'", TokenType.STRING),
            (r"0x[0-9a-fA-F]{40}", TokenType.ADDRESS),
            (r"\b\d+(\.\d+)?(gwei|ether|wei)?\b", TokenType.NUMBER),
            (r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", TokenType.IDENTIFIER),
            (r"[+\-*/%=<>!&|^~?:]+", TokenType.OPERATOR),
            (r"[\(\[\]{};,.:]", TokenType.DELIMITER),
        ]

        combined = "|".join(f"(?P<{i}^{p})" for i, p in enumerate(patterns))

        pattern = re.compile(combined)

        while position < len(self.source_code):
            match = pattern.match(self.source_code, position)
            if not match:
                position += 1
                column += 1
                continue

            token_value = match.group()
            token_type = self._determine_token_type(match.lastgroup, token_value)

            if token_type != TokenType.WHITESPACE:
                tokens.append(Token(token_type, token_value, line, column))
            else:
                line += token_value.count("\n")
                if "\n" in token_value:
                    column = 1
                else:
                    column += len(token_value)

            position = match.end()
            column += len(token_value) - (token_value.count("\n"))

        return tokens

    def _determine_token_type(self, group_index: int, value: str) -> TokenType:
        if value in self.KEYWORDS or value in self.TYPE_KEYWORDS:
            return TokenType.KEYWORD
        if value in self.OPERATORS:
            return TokenType.OPERATOR
        if value in self.DELIMITERS:
            return TokenType.DELIMITER
        if group_index == 0 or group_index == 1:
            return TokenType.COMMENT
        if group_index == 2 or group_index == 3:
            return TokenType.STRING
        if group_index == 4:
            return TokenType.ADDRESS
        if group_index == 5:
            return TokenType.NUMBER
        return TokenType.IDENTIFIER

    def _parse_structure(self):
        self._parse_contracts()
        self._parse_functions()
        self._parse_variables()
        self._parse_events()

    def _parse_contracts(self):
        pattern = re.compile(
            r"(contract|interface|library)\s+(\w+)\s*(?:is\s+([^{]+))?",
            re.MULTILINE,
        )
        for match in pattern.finditer(self.source_code):
            base_contracts = []
            if match.group(3):
                base_contracts = [c.strip() for c in match.group(3).split(",")]

            self.contracts.append(
                ParsedContract(
                    name=match.group(2),
                    kind=match.group(1),
                    base_contracts=base_contracts,
                )
            )

    def _parse_functions(self):
        pattern = re.compile(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*"
            r"((?:external|public|internal|private|"
            r"pure|view|payable)\s*)*",
            re.MULTILINE,
        )
        for match in pattern.finditer(self.source_code):
            visibility = "external"
            state_mutability = "nonpayable"

            if "external" in match.group(3) or "public" in match.group(3):
                visibility = "external"
            elif "internal" in match.group(3):
                visibility = "internal"
            elif "private" in match.group(3):
                visibility = "private"

            if "pure" in match.group(3):
                state_mutability = "pure"
            elif "view" in match.group(3):
                state_mutability = "view"
            elif "payable" in match.group(3):
                state_mutability = "payable"

            params = self._parse_params(match.group(2))

            self.functions.append(
                ParsedFunction(
                    name=match.group(1),
                    visibility=visibility,
                    state_mutability=state_mutability,
                    kind="function",
                    parameters=params,
                )
            )

    def _parse_variables(self):
        pattern = re.compile(
            r"(uint|int|address|bool|string|bytes|"
            r"mapping)\s+(\w+)\s*(?:public|internal|private"
            r"|constant|immutable)?",
            re.MULTILINE,
        )
        for match in pattern.finditer(self.source_code):
            self.variables.append(
                ParsedVariable(
                    name=match.group(2),
                    type=match.group(1),
                    visibility="internal",
                    mutability="mutable",
                )
            )

    def _parse_events(self):
        pattern = re.compile(r"event\s+(\w+)\s*\(([^)]+)\)", re.MULTILINE)
        for match in pattern.finditer(self.source_code):
            params = self._parse_params(match.group(2))
            self.events.append(ParsedEvent(name=match.group(1), parameters=params))

    def _parse_params(self, param_str: str) -> List[Dict[str, str]]:
        params = []
        if not param_str.strip():
            return params

        for param in param_str.split(","):
            param = param.strip()
            if not param:
                continue
            parts = param.rsplit(None, 1)
            if len(parts) == 2:
                params.append({"type": parts[0], "name": parts[1]})
            else:
                params.append({"type": parts[0], "name": ""})

        return params

    def get_contract(self, name: str) -> Optional[ParsedContract]:
        for contract in self.contracts:
            if contract.name == name:
                return contract
        return None

    def get_function(self, name: str) -> Optional[ParsedFunction]:
        for func in self.functions:
            if func.name == name:
                return func
        return None

    def get_variable(self, name: str) -> Optional[ParsedVariable]:
        for var in self.variables:
            if var.name == name:
                return var
        return None

    def get_event(self, name: str) -> Optional[ParsedEvent]:
        for event in self.events:
            if event.name == name:
                return event
        return None

    def get_view_functions(self) -> List[ParsedFunction]:
        return [f for f in self.functions if f.state_mutability in ("view", "pure")]

    def get_payable_functions(self) -> List[ParsedFunction]:
        return [f for f in self.functions if f.state_mutability == "payable"]

    def get_external_functions(self) -> List[ParsedFunction]:
        return [f for f in self.functions if f.visibility == "external"]

    def to_json(self) -> str:
        import json
        return json.dumps(
            {
                "contracts": [
                    {
                        "name": c.name,
                        "kind": c.kind,
                        "base_contracts": c.base_contracts,
                    }
                    for c in self.contracts
                ],
                "functions": [
                    {
                        "name": f.name,
                        "visibility": f.visibility,
                        "state_mutability": f.state_mutability,
                        "parameters": f.parameters,
                    }
                    for f in self.functions
                ],
                "variables": [
                    {"name": v.name, "type": v.type, "visibility": v.visibility}
                    for v in self.variables
                ],
                "events": [
                    {"name": e.name, "parameters": e.parameters}
                    for e in self.events
                ],
            },
            indent=2,
        )


def parse(source_code: str) -> SolidityParser:
    parser = SolidityParser(source_code)
    parser.parse()
    return parser


__all__ = [
    "SolidityParser",
    "TokenType",
    "Token",
    "SourceLocation",
    "ParsedContract",
    "ParsedFunction",
    "ParsedVariable",
    "ParsedEvent",
    "parse",
]