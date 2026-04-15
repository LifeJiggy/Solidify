"""
SoliGuard Runtime Parser
Command and input parsing

Author: Peace Stephen (Tech Lead)
Description: Parses user input and command arguments
"""

import re
import shlex
import json
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import traceback

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class TokenType(Enum):
    """Token types"""
    COMMAND = "command"
    ARGUMENT = "argument"
    FLAG = "flag"
    VALUE = "value"
    STRING = "string"
    NUMBER = "number"
    IDENTIFIER = "identifier"
    NEWLINE = "newline"
    EOF = "eof"


class ParseMode(Enum):
    """Parse mode"""
    STRICT = "strict"
    RELAXED = "relaxed"
    JSON = "json"


@dataclass
class Token:
    """Token representation"""
    type: TokenType
    value: str
    position: int
    line: int
    column: int


@dataclass
class ParseResult:
    """Parse result"""
    success: bool
    command: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    raw_args: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ParserConfig:
    """Parser configuration"""
    mode: ParseMode = ParseMode.RELAXED
    allow_comments: bool = True
    enable_auto_complete: bool = True
    max_depth: int = 10
    timeout: float = 30.0


# ============================================================================
# Lexer
# ============================================================================

class Lexer:
    """
    Tokenizer/Lexer for input
    
    Features:
    - Character-by-character scanning
    - Token generation
    - Position tracking
    """
    
    def __init__(self, input_text: str):
        self.input = input_text
        self.position = 0
        self.line = 1
        self.column = 1
        self.current_char: Optional[str] = None
        self._advance()
    
    def _advance(self) -> None:
        """Advance to next character"""
        if self.current_char == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        
        if self.position < len(self.input):
            self.current_char = self.input[self.position]
            self.position += 1
        else:
            self.current_char = None
    
    def _peek(self, offset: int = 1) -> Optional[str]:
        """Peek at character without consuming"""
        pos = self.position + offset - 1
        if 0 <= pos < len(self.input):
            return self.input[pos]
        return None
    
    def skip_whitespace(self) -> None:
        """Skip whitespace characters"""
        while self.current_char and self.current_char.isspace():
            self._advance()
    
    def skip_comments(self) -> None:
        """Skip comment lines"""
        if self.current_char == '#':
            while self.current_char and self.current_char != '\n':
                self._advance()
    
    def read_string(self) -> str:
        """Read quoted string"""
        quote = self.current_char
        self._advance()
        
        result = ""
        while self.current_char and self.current_char != quote:
            if self.current_char == '\\' and self._peek():
                self._advance()
                result += self.current_char or ""
            else:
                result += self.current_char or ""
            self._advance()
        
        self._advance()
        return result
    
    def read_number(self) -> str:
        """Read number"""
        result = ""
        while self.current_char and (self.current_char.isdigit() or self.current_char == '.'):
            result += self.current_char or ""
            self._advance()
        return result
    
    def read_identifier(self) -> str:
        """Read identifier"""
        result = ""
        while self.current_char and (self.current_char.isalnum() or self.current_char in '_-'):
            result += self.current_char or ""
            self._advance()
        return result
    
    def read_flag(self) -> str:
        """Read flag"""
        result = ""
        while self.current_char and (self.current_char.isalnum() or self.current_char in '_-'):
            result += self.current_char or ""
            self._advance()
        return result
    
    def tokenize(self) -> List[Token]:
        """Tokenize input"""
        tokens = []
        
        while self.current_char:
            if self.current_char.isspace():
                self.skip_whitespace()
                continue
            
            if self.current_char == '#':
                self.skip_comments()
                continue
            
            pos = self.position
            line = self.line
            col = self.column
            
            if self.current_char in '"\'':
                value = self.read_string()
                tokens.append(Token(TokenType.STRING, value, pos, line, col))
            
            elif self.current_char.isdigit() or (self.current_char == '.' and self._peek().isdigit()):
                value = self.read_number()
                tokens.append(Token(TokenType.NUMBER, value, pos, line, col))
            
            elif self.current_char == '-':
                self._advance()
                if self.current_char and (self.current_char.isalnum() or self.current_char == '-'):
                    value = self.read_flag()
                    tokens.append(Token(TokenType.FLAG, value, pos, line, col))
                else:
                    tokens.append(Token(TokenType.FLAG, "-", pos, line, col))
            
            elif self.current_char.isalpha() or self.current_char == '_':
                value = self.read_identifier()
                if self.current_char == ':':
                    tokens.append(Token(TokenType.IDENTIFIER, value, pos, line, col))
                else:
                    tokens.append(Token(TokenType.COMMAND, value, pos, line, col))
            
            elif self.current_char == '\n':
                tokens.append(Token(TokenType.NEWLINE, '\n', pos, line, col))
                self._advance()
            
            else:
                self._advance()
        
        tokens.append(Token(TokenType.EOF, '', self.position, self.line, self.column))
        
        return tokens


# ============================================================================
# Parser
# ============================================================================

class Parser:
    """
    Main parser
    
    Features:
    - Recursive descent parsing
    - AST generation
    - Error recovery
    """
    
    def __init__(self, config: ParserConfig = None):
        self.config = config or ParserConfig()
        self.tokens: List[Token] = []
        self.position = 0
        self.current_token: Optional[Token] = None
    
    def parse(self, input_text: str) -> ParseResult:
        """Parse input text"""
        try:
            if self.config.mode == ParseMode.JSON:
                return self._parse_json(input_text)
            
            lexer = Lexer(input_text)
            self.tokens = lexer.tokenize()
            self.position = 0
            self.current_token = self.tokens[0] if self.tokens else None
            
            return self._parse_command()
            
        except Exception as e:
            logger.error(f"Parse error: {str(e)}")
            logger.debug(traceback.format_exc())
            return ParseResult(
                success=False,
                errors=[str(e)]
            )
    
    def _parse_json(self, input_text: str) -> ParseResult:
        """Parse as JSON"""
        try:
            data = json.loads(input_text)
            return ParseResult(
                success=True,
                args=data
            )
        except json.JSONDecodeError as e:
            return ParseResult(
                success=False,
                errors=[f"JSON parse error: {str(e)}"]
            )
    
    def _parse_command(self) -> ParseResult:
        """Parse command structure"""
        if not self.current_token:
            return ParseResult(success=False, errors=["No tokens"])
        
        if self.current_token.type != TokenType.COMMAND:
            return ParseResult(
                success=False,
                errors=[f"Expected command, got {self.current_token.type.value}"]
            )
        
        command = self.current_token.value
        self._advance()
        
        args = {}
        raw_args = []
        errors = []
        warnings = []
        
        while self.current_token and self.current_token.type != TokenType.EOF:
            if self.current_token.type == TokenType.NEWLINE:
                self._advance()
                continue
            
            if self.current_token.type == TokenType.FLAG:
                flag_result = self._parse_flag()
                if flag_result:
                    args.update(flag_result)
                else:
                    warnings.append("Failed to parse flag")
                continue
            
            if self.current_token.type == TokenType.STRING:
                raw_args.append(self.current_token.value)
                self._advance()
                continue
            
            if self.current_token.type == TokenType.NUMBER:
                raw_args.append(self.current_token.value)
                self._advance()
                continue
            
            if self.current_token.type == TokenType.IDENTIFIER:
                ident_result = self._parse_identifier()
                if ident_result:
                    args.update(ident_result)
                continue
            
            if self.current_token.type == TokenType.COMMAND:
                raw_args.append(self.current_token.value)
                self._advance()
                continue
            
            self._advance()
        
        return ParseResult(
            success=True,
            command=command,
            args=args,
            raw_args=raw_args,
            errors=errors,
            warnings=warnings
        )
    
    def _parse_flag(self) -> Optional[Dict[str, Any]]:
        """Parse flag"""
        flag = self.current_token.value
        self._advance()
        
        result = {}
        
        if self.current_token and self.current_token.type == TokenType.VALUE:
            result[flag] = self.current_token.value
            self._advance()
        elif self.current_token and self.current_token.type == TokenType.NUMBER:
            result[flag] = float(self.current_token.value)
            self._advance()
        elif self.current_token and self.current_token.type == TokenType.STRING:
            result[flag] = self.current_token.value
            self._advance()
        elif self.current_token and self.current_token.type == TokenType.FLAG:
            result[flag] = True
        else:
            result[flag] = True
        
        return result
    
    def _parse_identifier(self) -> Optional[Dict[str, Any]]:
        """Parse identifier: value"""
        identifier = self.current_token.value
        self._advance()
        
        if self.current_token and self.current_token.type == TokenType.VALUE:
            value = self.current_token.value
            self._advance()
            return {identifier: value}
        
        if self.current_token and self.current_token.type == TokenType.NUMBER:
            return {identifier: float(self.current_token.value)}
        
        return None
    
    def _advance(self) -> None:
        """Advance to next token"""
        self.position += 1
        self.current_token = (
            self.tokens[self.position]
            if self.position < len(self.tokens)
            else None
        )


# ============================================================================
# Command Parser
# ============================================================================

class CommandParser:
    """
    High-level command parser
    
    Features:
    - Command registration
    - Argument validation
    - Auto-complete
    """
    
    def __init__(self, config: ParserConfig = None):
        self.config = config or ParserConfig()
        self.parser = Parser(self.config)
        self._commands: Dict[str, Dict[str, Any]] = {}
        self._aliases: Dict[str, str] = {}
    
    def register_command(
        self,
        name: str,
        handler: Any,
        args_schema: Optional[Dict[str, Any]] = None,
        description: str = "",
        aliases: Optional[List[str]] = None
    ) -> None:
        """Register command"""
        self._commands[name] = {
            "handler": handler,
            "args_schema": args_schema or {},
            "description": description,
            "aliases": aliases or []
        }
        
        for alias in aliases or []:
            self._aliases[alias] = name
    
    def parse(self, input_text: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """Parse and validate command"""
        result = self.parser.parse(input_text)
        
        if not result.success:
            return None, {"error": result.errors[0] if result.errors else "Parse failed"}
        
        command = result.command
        if command in self._aliases:
            command = self._aliases[command]
        
        if command not in self._commands:
            return None, {"error": f"Unknown command: {command}"}
        
        validated_args = self._validate_args(
            result.args,
            self._commands[command]["args_schema"]
        )
        
        return command, validated_args
    
    def _validate_args(
        self,
        args: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate arguments against schema"""
        validated = {}
        
        for key, spec in schema.items():
            if key in args:
                value = args[key]
                expected_type = spec.get("type", "string")
                
                if not self._validate_type(value, expected_type):
                    logger.warning(f"Invalid type for {key}: expected {expected_type}")
                
                validated[key] = value
            elif spec.get("required", False):
                logger.warning(f"Missing required argument: {key}")
        
        for key in args:
            if key not in schema:
                validated[key] = args[key]
        
        return validated
    
    def _validate_type(self, value: Any, expected_type: str) -> bool:
        """Validate value type"""
        if expected_type == "string":
            return isinstance(value, str)
        elif expected_type == "number":
            return isinstance(value, (int, float))
        elif expected_type == "boolean":
            return isinstance(value, bool)
        elif expected_type == "list":
            return isinstance(value, list)
        elif expected_type == "dict":
            return isinstance(value, dict)
        return True
    
    def get_commands(self) -> Dict[str, Dict[str, Any]]:
        """Get registered commands"""
        return self._commands.copy()
    
    def get_command_names(self) -> List[str]:
        """Get command names"""
        return list(self._commands.keys())
    
    def get_auto_complete(self, partial: str) -> List[str]:
        """Get auto-complete suggestions"""
        suggestions = []
        
        for name in self._commands:
            if name.startswith(partial):
                suggestions.append(name)
        
        for alias, command in self._aliases.items():
            if alias.startswith(partial):
                if alias not in suggestions:
                    suggestions.append(alias)
        
        return sorted(suggestions)


# ============================================================================
# Argument Parser
# ============================================================================

class ArgumentParser:
    """
    Argument parser for CLI
    
    Features:
    - Positional arguments
    - Optional arguments
    - Subcommands
    """
    
    def __init__(self, prog: str = "soliguard"):
        self.prog = prog
        self._positional: List[Tuple[str, Dict[str, Any]]] = []
        self._optional: List[Tuple[str, Dict[str, Any]]] = []
        self._subparsers: Dict[str, "ArgumentParser"] = {}
    
    def add_argument(
        self,
        name: str,
        help: str = "",
        type: Type = str,
        default: Any = None,
        required: bool = False,
        nargs: Optional[int] = None
    ) -> "ArgumentParser":
        """Add positional argument"""
        self._positional.append((
            name,
            {"help": help, "type": type, "default": default, "required": required, "nargs": nargs}
        ))
        return self
    
    def add_option(
        self,
        short: str,
        long: str,
        help: str = "",
        type: Type = str,
        default: Any = None,
        required: bool = False,
        nargs: Optional[int] = None
    ) -> "ArgumentParser":
        """Add optional argument"""
        self._optional.append((
            (short, long),
            {"help": help, "type": type, "default": default, "required": required, "nargs": nargs}
        ))
        return self
    
    def add_subparser(self, name: str) -> "ArgumentParser":
        """Add subparser"""
        subparser = ArgumentParser(f"{self.prog} {name}")
        self._subparsers[name] = subparser
        return subparser
    
    def parse_args(self, args: List[str]) -> Dict[str, Any]:
        """Parse arguments"""
        result = {}
        i = 0
        
        while i < len(args):
            arg = args[i]
            
            if arg.startswith('-'):
                matched = False
                
                for (short, long), spec in self._optional:
                    if arg == short or arg == long:
                        if spec.get("nargs") == 0:
                            result[long.lstrip('-')] = True
                        else:
                            value = args[i + 1] if i + 1 < len(args) else spec["default"]
                            result[long.lstrip('-')] = self._convert_type(value, spec["type"])
                            i += 1
                        matched = True
                        break
                
                if not matched:
                    logger.warning(f"Unknown option: {arg}")
            
            else:
                if len(self._positional) > len([k for k in result if not k.startswith('-')]):
                    idx = len([k for k in result if not k.startswith('-')])
                    name, spec = self._positional[idx]
                    result[name] = self._convert_type(arg, spec["type"])
            
            i += 1
        
        return result
    
    def _convert_type(self, value: Any, type: Type) -> Any:
        """Convert value to type"""
        try:
            return type(value)
        except Exception:
            return value


# ============================================================================
# Query Parser
# ============================================================================

class QueryParser:
    """
    Natural language query parser
    
    Features:
    - Intent recognition
    - Entity extraction
    - Query classification
    """
    
    def __init__(self):
        self._intents: Dict[str, List[str]] = {
            "audit": ["audit", "scan", "analyze", "check", "security"],
            "explain": ["explain", "what", "why", "how", "describe"],
            "fix": ["fix", "patch", "repair", "resolve", "solve"],
            "compare": ["compare", "diff", "versus", "vs"],
            "report": ["report", "generate", "create", "export"],
            "help": ["help", "commands", "list", "show"]
        }
    
    def parse(self, query: str) -> Dict[str, Any]:
        """Parse natural language query"""
        query_lower = query.lower()
        
        intent = self._classify_intent(query_lower)
        entities = self._extract_entities(query_lower)
        modifiers = self._extract_modifiers(query_lower)
        
        return {
            "intent": intent,
            "entities": entities,
            "modifiers": modifiers,
            "original": query
        }
    
    def _classify_intent(self, query: str) -> str:
        """Classify query intent"""
        for intent, keywords in self._intents.items():
            for keyword in keywords:
                if keyword in query:
                    return intent
        return "unknown"
    
    def _extract_entities(self, query: str) -> Dict[str, Any]:
        """Extract entities from query"""
        entities = {}
        
        chains = ["ethereum", "bsc", "polygon", "arbitrum", "optimism", "base", "avalanche"]
        for chain in chains:
            if chain in query:
                entities["chain"] = chain
        
        severities = ["critical", "high", "medium", "low", "info"]
        for severity in severities:
            if severity in query:
                entities["severity"] = severity
        
        return entities
    
    def _extract_modifiers(self, query: str) -> Dict[str, bool]:
        """Extract query modifiers"""
        return {
            "verbose": "verbose" in query or "detailed" in query,
            "fast": "fast" in query or "quick" in query,
            "deep": "deep" in query or "thorough" in query,
            "json": "json" in query
        }


# ============================================================================
# Main Parser Interface
# ============================================================================

class RuntimeParser:
    """
    Main parser interface
    
    Features:
    - Unified API
    - Multiple parse modes
    - Error handling
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        parser_config = ParserConfig(
            mode=ParseMode[self.config.get("mode", "RELAXED").upper()],
            allow_comments=self.config.get("allow_comments", True),
            enable_auto_complete=self.config.get("enable_auto_complete", True)
        )
        
        self.command_parser = CommandParser(parser_config)
        self.query_parser = QueryParser()
        self._setup_default_commands()
        
        logger.info("✅ Runtime Parser initialized")
    
    def _setup_default_commands(self) -> None:
        """Setup default commands"""
        self.command_parser.register_command(
            "audit",
            lambda args: {"result": "audit started"},
            {"contract": {"type": "string", "required": True}},
            "Run security audit"
        )
        
        self.command_parser.register_command(
            "explain",
            lambda args: {"result": "explanation"},
            {"vulnerability": {"type": "string", "required": False}},
            "Explain vulnerability"
        )
        
        self.command_parser.register_command(
            "report",
            lambda args: {"result": "report generated"},
            {"format": {"type": "string", "required": False}},
            "Generate report"
        )
        
        self.command_parser.register_command(
            "help",
            lambda args: {"commands": self.command_parser.get_command_names()},
            {},
            "Show help"
        )
    
    def parse_command(self, input_text: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """Parse command input"""
        return self.command_parser.parse(input_text)
    
    def parse_query(self, query: str) -> Dict[str, Any]:
        """Parse natural language query"""
        return self.query_parser.parse(query)
    
    def parse(self, input_text: str) -> ParseResult:
        """Parse generic input"""
        return self.command_parser.parser.parse(input_text)
    
    def register_command(
        self,
        name: str,
        handler: Any,
        args_schema: Optional[Dict[str, Any]] = None,
        description: str = "",
        aliases: Optional[List[str]] = None
    ) -> None:
        """Register custom command"""
        self.command_parser.register_command(
            name, handler, args_schema, description, aliases
        )
    
    def get_commands(self) -> List[str]:
        """Get available commands"""
        return self.command_parser.get_command_names()
    
    def auto_complete(self, partial: str) -> List[str]:
        """Get auto-complete suggestions"""
        return self.command_parser.get_auto_complete(partial)