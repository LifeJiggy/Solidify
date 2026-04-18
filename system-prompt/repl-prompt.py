"""
Solidify REPL Prompt
Interactive REPL command prompts

Author: Peace Stephen (Tech Lead)
Description: Prompts for REPL commands
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


REPL_COMMANDS = {
    "audit": {"args": "<contract>", "description": "Run security audit"},
    "explain": {"args": "<vuln_id>", "description": "Explain vulnerability"},
    "scan": {"args": "[options]", "description": "Quick scan"},
    "report": {"args": "[format]", "description": "Generate report"},
    "hunt": {"args": "<protocol>", "description": "Hunt for bugs"},
    "chain": {"args": "<chain>", "description": "Switch chain"},
    "mode": {"args": "<mode>", "description": "Set audit mode"},
    "history": {"args": "", "description": "Show history"},
    "vars": {"args": "", "description": "Show variables"},
    "help": {"args": "", "description": "Show help"},
    "exit": {"args": "", "description": "Exit"}
}


REPL_HELP = """
Solidify REPL Commands:

audit <contract> - Run security audit
explain <vuln> - Explain vulnerability
scan - Quick security scan
report - Generate report
hunt <protocol> - Bug bounty hunt
chain <chain> - Set chain (ethereum, bsc, polygon, etc)
mode <mode> - Set mode (standard, deep, fast)
history - Show command history
vars - Show variables
help - Show this help
exit - Exit REPL

Examples:
  audit 0x1234...
  scan --fast
  chain polygon
  report --markdown
"""


@dataclass
class REPLContext:
    command: str
    args: List[str] = field(default_factory=list)
    chain: str = "ethereum"
    mode: str = "standard"


class REPLPromptBuilder:
    """Build REPL prompts"""
    
    def __init__(self):
        self.commands = REPL_COMMANDS
    
    def build_help(self) -> str:
        return REPL_HELP
    
    def build_audit_command(self, contract: str, chain: str = "ethereum") -> str:
        return f"""Run audit on contract:

Contract: {contract}
Chain: {chain}

Audit steps:
1. Load contract code
2. Run vulnerability scan
3. Generate report
4. Return findings"""
    
    def build_scan_command(self, mode: str = "fast") -> str:
        return f"""Quick scan (mode: {mode}):

Scan for:
1. Critical vulnerabilities
2. Common patterns
3. Access control
4. Reentrancy"""


class REPLPrompt:
    """Main REPL prompt manager"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = REPLPromptBuilder()
        self.context = REPLContext("audit")
        
        logger.info("✅ REPL Prompt initialized")
    
    def get_help(self) -> str:
        return self.builder.build_help()
    
    def build_audit_prompt(self, contract: str) -> str:
        return self.builder.build_audit_command(contract, self.context.chain)
    
    def build_scan_prompt(self, mode: str = "fast") -> str:
        return self.builder.build_scan_command(mode)
    
    def set_chain(self, chain: str) -> None:
        self.context.chain = chain
    
    def set_mode(self, mode: str) -> None:
        self.context.mode = mode
    
    def get_commands(self) -> Dict[str, Dict[str, str]]:
        return self.commands