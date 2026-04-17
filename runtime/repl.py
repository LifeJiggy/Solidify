"""
Solidify Runtime REPL
Interactive command line interface

Author: Peace Stephen (Tech Lead)
Description: Interactive REPL for Solidify
"""

import asyncio
import logging
import sys
import readline
import os
import json
import traceback
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class REPLMode(Enum):
    """REPL mode"""
    NORMAL = "normal"
    COMMAND = "command"
    SCRIPT = "script"
    DEBUG = "debug"


class OutputFormat(Enum):
    """Output format"""
    TEXT = "text"
    JSON = "json"
    TABLE = "table"
    VERBOSE = "verbose"


@dataclass
class REPLState:
    """REPL state"""
    mode: REPLMode = REPLMode.NORMAL
    history: List[str] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    last_result: Optional[Any] = None
    error_count: int = 0


@dataclass
class CommandResult:
    """Command result"""
    success: bool
    output: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# History Manager
# ============================================================================

class HistoryManager:
    """
    Command history management
    
    Features:
    - Persistent history
    - Search
    - Session history
    """
    
    def __init__(self, max_size: int = 1000, history_file: Optional[str] = None):
        self.max_size = max_size
        self.history_file = history_file or os.path.expanduser("~/.Solidify_history")
        self._history: List[str] = []
        self._load_history()
    
    def _load_history(self) -> None:
        """Load history from file"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    self._history = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.warning(f"Failed to load history: {e}")
    
    def save_history(self) -> None:
        """Save history to file"""
        try:
            with open(self.history_file, 'w') as f:
                for line in self._history[-self.max_size:]:
                    f.write(line + '\n')
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")
    
    def add(self, command: str) -> None:
        """Add command to history"""
        if command.strip() and command != self._history[-1] if self._history else True:
            self._history.append(command)
            if len(self._history) > self.max_size:
                self._history = self._history[-self.max_size:]
    
    def search(self, pattern: str) -> List[str]:
        """Search history"""
        return [cmd for cmd in self._history if pattern in cmd]
    
    def get_history(self) -> List[str]:
        """Get all history"""
        return self._history.copy()
    
    def clear(self) -> None:
        """Clear history"""
        self._history.clear()


# ============================================================================
# Command Registry
# ============================================================================

class CommandRegistry:
    """
    Command registration and management
    
    Features:
    - Command aliases
    - Help generation
    - Command validation
    """
    
    def __init__(self):
        self._commands: Dict[str, Callable] = {}
        self._aliases: Dict[str, str] = {}
        self._help: Dict[str, str] = {}
        self._completions: Dict[str, List[str]] = {}
        self._setup_default_commands()
    
    def _setup_default_commands(self) -> None:
        """Setup default commands"""
        self.register("help", self._help_command, "Show help", ["?", "commands"])
        self.register("exit", self._exit_command, "Exit REPL", ["quit", "q"])
        self.register("clear", self._clear_command, "Clear screen", ["cls"])
        self.register("history", self._history_command, "Show command history", ["hist"])
        self.register("set", self._set_command, "Set variable")
        self.register("get", self._get_command, "Get variable")
        self.register("audit", self._audit_command, "Run audit")
        self.register("explain", self._explain_command, "Explain vulnerability")
        self.register("report", self._report_command, "Generate report")
    
    def register(
        self,
        name: str,
        handler: Callable,
        help_text: str = "",
        aliases: Optional[List[str]] = None
    ) -> None:
        """Register command"""
        self._commands[name] = handler
        self._help[name] = help_text
        
        for alias in aliases or []:
            self._aliases[alias] = name
    
    def get_command(self, name: str) -> Optional[Callable]:
        """Get command handler"""
        if name in self._commands:
            return self._commands[name]
        if name in self._aliases:
            return self._commands[self._aliases[name]]
        return None
    
    def get_help(self, name: str) -> Optional[str]:
        """Get command help"""
        if name in self._help:
            return self._help[name]
        if name in self._aliases:
            return self._help.get(self._aliases[name])
        return None
    
    def list_commands(self) -> List[Dict[str, str]]:
        """List all commands"""
        commands = []
        for name in sorted(self._commands.keys()):
            commands.append({
                "name": name,
                "help": self._help.get(name, ""),
                "aliases": [a for a, n in self._aliases.items() if n == name]
            })
        return commands
    
    def add_completion(self, command: str, completions: List[str]) -> None:
        """Add completions for command"""
        self._completions[command] = completions
    
    def get_completions(self, command: str) -> List[str]:
        """Get completions"""
        return self._completions.get(command, [])
    
    def _help_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Help command"""
        if args:
            cmd = args[0]
            help_text = self.get_help(cmd)
            return CommandResult(
                success=True,
                output=help_text or f"No help for: {cmd}"
            )
        
        output = "Available commands:\n"
        for cmd in self.list_commands():
            aliases = f" (aliases: {', '.join(cmd['aliases'])})" if cmd['aliases'] else ""
            output += f"  {cmd['name']}{aliases} - {cmd['help']}\n"
        
        return CommandResult(success=True, output=output)
    
    def _exit_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Exit command"""
        state.running = False
        return CommandResult(success=True, output="Goodbye!")
    
    def _clear_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Clear command"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return CommandResult(success=True, output="")
    
    def _history_command(self, args: List[str], state: "REPL") -> CommandResult:
        """History command"""
        history = state.history.get_history()
        output = "\n".join(f"{i+1}: {cmd}" for i, cmd in enumerate(history[-20:]))
        return CommandResult(success=True, output=output or "No history")
    
    def _set_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Set variable"""
        if len(args) < 2:
            return CommandResult(success=False, error="Usage: set <name> <value>")
        
        name, value = args[0], " ".join(args[1:])
        state.variables[name] = value
        return CommandResult(success=True, output=f"Set {name} = {value}")
    
    def _get_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Get variable"""
        if not args:
            return CommandResult(success=True, output=str(state.variables))
        
        name = args[0]
        value = state.variables.get(name)
        return CommandResult(success=True, output=value if value is not None else "Not found")
    
    def _audit_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Audit command"""
        return CommandResult(success=True, output="Running audit...")
    
    def _explain_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Explain command"""
        return CommandResult(success=True, output="Explaining vulnerability...")
    
    def _report_command(self, args: List[str], state: "REPL") -> CommandResult:
        """Report command"""
        return CommandResult(success=True, output="Generating report...")


# ============================================================================
# Auto-Complete
# ============================================================================

class AutoCompleter:
    """
    Auto-completion for REPL
    
    Features:
    - Command completion
    - Variable completion
    - Custom completers
    """
    
    def __init__(self, registry: CommandRegistry, state: REPLState):
        self.registry = registry
        self.state = state
    
    def complete(self, text: str, index: int) -> Optional[str]:
        """Complete input"""
        matches = self._get_matches(text)
        
        if index < len(matches):
            return matches[index]
        return None
    
    def _get_matches(self, text: str) -> List[str]:
        """Get matching completions"""
        matches = []
        
        if text.startswith('/'):
            matches.extend(self.registry.list_commands())
        else:
            matches.extend([cmd['name'] for cmd in self.registry.list_commands()])
            matches.extend(self.state.variables.keys())
        
        return [m for m in matches if m.startswith(text)]


# ============================================================================
# Output Formatter
# ============================================================================

class OutputFormatter:
    """
    Output formatting
    
    Features:
    - JSON formatting
    - Table formatting
    - Color support
    """
    
    def __init__(self, format: OutputFormat = OutputFormat.TEXT):
        self.format = format
        self._colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "reset": "\033[0m"
        }
    
    def format_output(self, result: CommandResult) -> str:
        """Format command result"""
        if not result.success:
            return self._format_error(result.error or "Unknown error")
        
        output = result.output
        
        if self.format == OutputFormat.JSON:
            return self._format_json(output)
        elif self.format == OutputFormat.TABLE:
            return self._format_table(output)
        elif self.format == OutputFormat.VERBOSE:
            return self._format_verbose(result)
        else:
            return self._format_text(output)
    
    def _format_text(self, output: Any) -> str:
        """Format as text"""
        if output is None:
            return ""
        if isinstance(output, (dict, list)):
            return json.dumps(output, indent=2)
        return str(output)
    
    def _format_json(self, output: Any) -> str:
        """Format as JSON"""
        return json.dumps(output, indent=2)
    
    def _format_table(self, output: Any) -> str:
        """Format as table"""
        if isinstance(output, list):
            if not output:
                return "No data"
            
            if isinstance(output[0], dict):
                headers = list(output[0].keys())
                rows = [[str(row.get(h, "")) for h in headers] for row in output]
                
                col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]
                
                header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
                separator = "-+-".join("-" * w for w in col_widths)
                
                lines = [header_line, separator]
                for row in rows:
                    lines.append(" | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)))
                
                return "\n".join(lines)
        
        return str(output)
    
    def _format_verbose(self, result: CommandResult) -> str:
        """Format verbose output"""
        lines = []
        
        lines.append(f"Success: {result.success}")
        if result.output:
            lines.append(f"Output: {result.output}")
        if result.error:
            lines.append(f"Error: {result.error}")
        lines.append(f"Execution time: {result.execution_time:.3f}s")
        
        return "\n".join(lines)
    
    def _format_error(self, error: str) -> str:
        """Format error"""
        return f"{self._colors['red']}Error: {error}{self._colors['reset']}"


# ============================================================================
# Main REPL
# ============================================================================

class REPL:
    """
    Main REPL interface
    
    Features:
    - Interactive input
    - Command processing
    - History management
    - Auto-complete
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        self.state = REPLState()
        self.history = HistoryManager(
            max_size=self.config.get("history_size", 1000)
        )
        self.registry = CommandRegistry()
        self.completer = AutoCompleter(self.registry, self.state)
        self.formatter = OutputFormatter(
            format=OutputFormat[self.config.get("format", "TEXT").upper()]
        )
        
        self.prompt = self.config.get("prompt", "Solidify> ")
        self.debug = self.config.get("debug", False)
        self.running = True
        
        self._hooks: Dict[str, List[Callable]] = {
            "pre_command": [],
            "post_command": [],
            "on_error": []
        }
        
        logger.info("✅ REPL initialized")
    
    def add_hook(self, event: str, handler: Callable) -> None:
        """Add event hook"""
        if event in self._hooks:
            self._hooks[event].append(handler)
    
    async def run(self) -> None:
        """Run REPL"""
        self._print_welcome()
        
        while self.running:
            try:
                line = await self._read_line()
                
                if not line:
                    continue
                
                self.history.add(line)
                await self._process_input(line)
                
            except KeyboardInterrupt:
                print("\n(Use 'exit' to quit)")
            except EOFError:
                break
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                else:
                    print(f"Error: {str(e)}")
        
        self.history.save_history()
        print("Goodbye!")
    
    def _print_welcome(self) -> None:
        """Print welcome message"""
        print("=" * 50)
        print("  Solidify Security Auditor REPL")
        print("  Type 'help' for available commands")
        print("=" * 50)
    
    async def _read_line(self) -> str:
        """Read input line"""
        try:
            return input(self.prompt).strip()
        except Exception:
            return ""
    
    async def _process_input(self, line: str) -> None:
        """Process input line"""
        for hook in self._hooks.get("pre_command", []):
            await hook(line, self.state)
        
        if line.startswith('/'):
            command_line = line[1:]
        else:
            command_line = line
        
        parts = shlex.split(command_line) if ' ' in command_line else [command_line]
        
        if not parts:
            return
        
        command_name = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        command = self.registry.get_command(command_name)
        
        if not command:
            print(f"Unknown command: {command_name}")
            return
        
        start_time = datetime.utcnow()
        
        try:
            result = command(args, self)
            
            for hook in self._hooks.get("post_command", []):
                await hook(result, self.state)
            
            output = self.formatter.format_output(result)
            if output:
                print(output)
            
            self.state.last_result = result
            
        except Exception as e:
            self.state.error_count += 1
            
            for hook in self._hooks.get("on_error", []):
                await hook(e, self.state)
            
            if self.debug:
                traceback.print_exc()
            else:
                print(f"Error: {str(e)}")
    
    def execute(self, line: str) -> CommandResult:
        """Execute command programmatically"""
        parts = shlex.split(line) if ' ' in line else [line]
        
        if not parts:
            return CommandResult(success=False, error="Empty command")
        
        command_name = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        command = self.registry.get_command(command_name)
        
        if not command:
            return CommandResult(success=False, error=f"Unknown command: {command_name}")
        
        try:
            return command(args, self)
        except Exception as e:
            return CommandResult(success=False, error=str(e))
    
    def get_state(self) -> Dict[str, Any]:
        """Get REPL state"""
        return {
            "mode": self.state.mode.value,
            "variables": self.state.variables,
            "context": self.state.context,
            "error_count": self.state.error_count,
            "history_size": len(self.history.get_history())
        }
    
    def set_variable(self, name: str, value: Any) -> None:
        """Set variable"""
        self.state.variables[name] = value
    
    def get_variable(self, name: str) -> Any:
        """Get variable"""
        return self.state.variables.get(name)
    
    def get_commands(self) -> List[str]:
        """Get available commands"""
        return [cmd['name'] for cmd in self.registry.list_commands()]


# ============================================================================
# Async REPL
# ============================================================================

class AsyncREPL(REPL):
    """
    Async REPL with coroutine support
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._coroutines: Dict[str, Callable] = {}
    
    def register_coroutine(self, name: str, coro: Callable) -> None:
        """Register coroutine"""
        self._coroutines[name] = coro
    
    async def run_async(self) -> None:
        """Run async REPL"""
        self._print_welcome()
        
        while self.running:
            try:
                line = await self._read_line()
                
                if not line:
                    continue
                
                self.history.add(line)
                
                if line.startswith('!'):
                    await self._run_coroutine(line[1:])
                else:
                    await self._process_input(line)
                    
            except KeyboardInterrupt:
                print("\n(Use 'exit' to quit)")
            except EOFError:
                break
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                else:
                    print(f"Error: {str(e)}")
        
        self.history.save_history()
    
    async def _run_coroutine(self, line: str) -> None:
        """Run registered coroutine"""
        parts = line.split()
        
        if not parts:
            return
        
        name = parts[0]
        args = parts[1:]
        
        coro = self._coroutines.get(name)
        
        if not coro:
            print(f"Unknown coroutine: {name}")
            return
        
        try:
            result = await coro(*args)
            print(result)
        except Exception as e:
            print(f"Error: {str(e)}")


# ============================================================================
# Script Runner
# ============================================================================

class ScriptRunner:
    """
    Run REPL scripts
    
    Features:
    - Script loading
    - Variable passing
    - Error handling
    """
    
    def __init__(self, repl: REPL):
        self.repl = repl
    
    def run_script(self, script_path: str) -> List[CommandResult]:
        """Run script file"""
        results = []
        
        try:
            with open(script_path, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Failed to load script: {e}")
            return results
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            result = self.repl.execute(line)
            results.append(result)
            
            if not result.success:
                print(f"Script error at line: {line}")
                break
        
        return results
    
    def run_commands(self, commands: List[str]) -> List[CommandResult]:
        """Run list of commands"""
        results = []
        
        for cmd in commands:
            result = self.repl.execute(cmd)
            results.append(result)
        
        return results