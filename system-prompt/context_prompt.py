"""
Solidify Context Prompt
Context management and memory prompts

Author: Peace Stephen (Tech Lead)
Description: Context-aware prompts for session management
"""

import json
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ContextType(Enum):
    """Context types"""
    AUDIT = "audit"
    EXPLAIN = "explain"
    SCAN = "scan"
    HUNT = "hunt"
    REPORT = "report"
    EXPLOIT = "exploit"
    RECON = "recon"


class ContextScope(Enum):
    """Context scope"""
    SINGLE_CONTRACT = "single_contract"
    PROJECT = "project"
    PROTOCOL = "protocol"
    MULTI_CHAIN = "multi_chain"


@dataclass
class AuditContext:
    contract_code: str
    contract_name: str
    chain: str
    audit_type: str
    scope: ContextScope
    previous_findings: List[Dict[str, Any]] = field(default_factory=list)
    user_preferences: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionContext:
    session_id: str
    user_id: Optional[str]
    chain: str
    mode: str
    history: List[Dict[str, Any]] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)


CONTEXT_TEMPLATES = {
    ContextType.AUDIT: {
        "system": """You are performing a smart contract security audit.

Contract: {contract_name}
Chain: {chain}
Type: {audit_type}

Previous findings: {previous_findings}

Analyze the contract thoroughly.""",
        "user": """Audit this contract for security vulnerabilities:

{contract_code}

Provide findings in JSON format."""
    },
    ContextType.EXPLAIN: {
        "system": """You are explaining a smart contract vulnerability.

Focus on:
1. What the vulnerability is
2. How it can be exploited
3. The potential impact
4. How to fix it""",
        "user": """Explain this vulnerability: {vulnerability_description}

Location: {location}"""
    },
    ContextType.HUNT: {
        "system": """You are hunting for security vulnerabilities in a DeFi protocol.

Focus on:
1. Flash loan attacks
2. Oracle manipulation
3. Reentrancy
4. Access control
5. Economic attacks""",
        "user": """Hunt for vulnerabilities in this protocol: {protocol_code}"""
    }
}


class ContextBuilder:
    """Build context-aware prompts"""
    
    def __init__(self):
        self.templates = CONTEXT_TEMPLATES
    
    def build_audit_context(
        self,
        contract_code: str,
        contract_name: str,
        chain: str = "ethereum",
        audit_type: str = "standard"
    ) -> AuditContext:
        return AuditContext(
            contract_code=contract_code,
            contract_name=contract_name,
            chain=chain,
            audit_type=audit_type,
            scope=ContextScope.SINGLE_CONTRACT,
            previous_findings=[],
            user_preferences={},
            metadata={}
        )
    
    def build_system_prompt(self, context_type: ContextType, **kwargs) -> str:
        template = self.templates.get(context_type, {})
        return template.get("system", "").format(**kwargs)
    
    def build_user_prompt(self, context_type: ContextType, **kwargs) -> str:
        template = self.templates.get(context_type, {})
        return template.get("user", "").format(**kwargs)
    
    def merge_contexts(
        self,
        contexts: List[AuditContext]
    ) -> Dict[str, Any]:
        merged = {
            "contracts": [],
            "chains": set(),
            "findings": []
        }
        
        for ctx in contexts:
            merged["contracts"].append(ctx.contract_name)
            merged["chains"].add(ctx.chain)
            merged["findings"].extend(ctx.previous_findings)
        
        merged["chains"] = list(merged["chains"])
        return merged


class ContextMemory:
    """Context memory management"""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self._memory: Dict[str, List[Dict[str, Any]]] = {}
    
    def add(self, session_id: str, event: Dict[str, Any]) -> None:
        if session_id not in self._memory:
            self._memory[session_id] = []
        
        self._memory[session_id].append({
            **event,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        if len(self._memory[session_id]) > self.max_history:
            self._memory[session_id] = self._memory[session_id][-self.max_history:]
    
    def get_history(
        self,
        session_id: str,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        return self._memory.get(session_id, [])[-limit:]
    
    def search(
        self,
        session_id: str,
        query: str
    ) -> List[Dict[str, Any]]:
        results = []
        for event in self._memory.get(session_id, []):
            if query.lower() in str(event).lower():
                results.append(event)
        return results
    
    def clear(self, session_id: str) -> None:
        self._memory.pop(session_id, None)


class ConversationContext:
    """Conversation context manager"""
    
    def __init__(self):
        self.current: Optional[AuditContext] = None
        self.history: List[AuditContext] = []
        self.variables: Dict[str, Any] = {}
    
    def set_context(self, context: AuditContext) -> None:
        self.current = context
        self.history.append(context)
    
    def get_current(self) -> Optional[AuditContext]:
        return self.current
    
    def update_variable(self, key: str, value: Any) -> None:
        self.variables[key] = value
    
    def get_variable(self, key: str, default: Any = None) -> Any:
        return self.variables.get(key, default)
    
    def get_context_summary(self) -> str:
        if not self.current:
            return "No active context"
        
        return f"Contract: {self.current.contract_name}, Chain: {self.current.chain}, Type: {self.current.audit_type}"


class ContextPrompt:
    """Main context prompt manager"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = ContextBuilder()
        self.memory = ContextMemory()
        self.conversation = ConversationContext()
        
        logger.info("✅ Context Prompt initialized")
    
    def create_audit_context(
        self,
        contract_code: str,
        contract_name: str,
        chain: str = "ethereum"
    ) -> AuditContext:
        context = self.builder.build_audit_context(
            contract_code, contract_name, chain
        )
        self.conversation.set_context(context)
        return context
    
    def get_system_prompt(
        self,
        context_type: ContextType,
        **kwargs
    ) -> str:
        return self.builder.build_system_prompt(context_type, **kwargs)
    
    def get_user_prompt(
        self,
        context_type: ContextType,
        **kwargs
    ) -> str:
        return self.builder.build_user_prompt(context_type, **kwargs)
    
    def remember(
        self,
        session_id: str,
        finding: Dict[str, Any]
    ) -> None:
        self.memory.add(session_id, {
            "type": "finding",
            "data": finding
        })
    
    def recall(
        self,
        session_id: str,
        query: str
    ) -> List[Dict[str, Any]]:
        return self.memory.search(session_id, query)