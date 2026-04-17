"""
Solidify MCP Prompts
MCP prompt templates for smart contract security analysis

Author: Peace Stephen (Tech Lead)
Description: MCP prompts for model context protocol
"""

import re
import logging
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class PromptType(Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    CONTEXT = "context"
    ANALYSIS = "analysis"
    EXPLOIT = "exploit"
    REPORT = "report"
    HUNTING = "hunting"
    RECON = "recon"


class PromptRole(Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class PromptFormat(Enum):
    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"
    XML = "xml"
    JSONL = "jsonl"


@dataclass
class PromptMessage:
    role: PromptRole
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptTemplate:
    name: str
    template: str
    prompt_type: PromptType
    format: PromptFormat = PromptFormat.TEXT
    variables: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptContext:
    source_code: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    history: List[PromptMessage] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BasePromptBuilder(ABC):
    def __init__(self, name: str):
        self.name = name
        self.templates: Dict[str, PromptTemplate] = {}
        
    @abstractmethod
    def build(self, context: PromptContext) -> List[PromptMessage]:
        pass
    
    def add_template(self, template: PromptTemplate) -> None:
        self.templates[template.name] = template
        
    def get_template(self, name: str) -> Optional[PromptTemplate]:
        return self.templates.get(name)


class SystemPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "system_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        system_prompt = """You are Solidify, an AI-powered smart contract security auditor for the GDG Abuja × Build with AI Sprint Hackathon.

Your capabilities include:
- Static analysis of Solidity smart contracts
- Vulnerability detection and classification
- Exploit scenario generation
- Security best practice recommendations
- Comprehensive security reporting

Always prioritize security and provide detailed, actionable recommendations."""

        return [PromptMessage(role=PromptRole.SYSTEM, content=system_prompt)]


class AnalysisPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "analysis_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content="You are analyzing a Solidity smart contract for security vulnerabilities."
        ))
        
        messages.append(PromptMessage(
            role=PromptRole.USER,
            content=self._build_analysis_request(context)
        ))
        
        return messages
        
    def _build_analysis_request(self, context: PromptContext) -> str:
        source_preview = context.source_code[:2000] + "..." if len(context.source_code) > 2000 else context.source_code
        
        return f"""Analyze the following Solidity smart contract for security vulnerabilities:

```{source_preview}
```

Provide a detailed analysis covering:
1. Identified vulnerabilities
2. Severity assessment (Critical/High/Medium/Low)
3. Line numbers and code snippets
4. Exploit scenarios
5. Recommendations"""


class VulnerabilityPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "vulnerability_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content="You are a smart contract security expert focused on vulnerability analysis."
        ))
        
        for finding in context.findings:
            messages.append(PromptMessage(
                role=PromptRole.USER,
                content=self._build_finding_request(finding)
            ))
            
        return messages
        
    def _build_finding_request(self, finding: Dict[str, Any]) -> str:
        return f"""Analyze this vulnerability:

Type: {finding.get('type', 'unknown')}
Severity: {finding.get('severity', 'unknown')}
Description: {finding.get('description', 'no description')}

Provide:
1. Technical explanation
2. Potential impact
3. Exploit scenario
4. Remediation steps"""


class ExploitPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "exploit_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content="You are a smart contract security expert generating exploit scenarios."
        ))
        
        messages.append(PromptMessage(
            role=PromptRole.USER,
            content=self._build_exploit_request(context)
        ))
        
        return messages
        
    def _build_exploit_request(self, context: PromptContext) -> str:
        exploits = []
        
        for finding in context.findings:
            severity = finding.get("severity", "")
            if severity in ["critical", "high"]:
                exploits.append(finding)
                
        if not exploits:
            return "No critical vulnerabilities found for exploit generation."
            
        return f"""Generate exploit scenarios for the following critical vulnerabilities:

{json.dumps(exploits, indent=2)}

For each exploit, provide:
1. Attack steps
2. Required preconditions
3. Expected outcomes
4. Complexity assessment"""


class ReportPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "report_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content="You are generating a comprehensive security report."
        ))
        
        messages.append(PromptMessage(
            role=PromptRole.USER,
            content=self._build_report_request(context)
        ))
        
        return messages
        
    def _build_report_request(self, context: PromptContext) -> str:
        finding_count = len(context.findings)
        critical = len([f for f in context.findings if f.get("severity") == "critical"])
        high = len([f for f in context.findings if f.get("severity") == "high"])
        
        return f"""Generate a comprehensive security report.

Summary:
- Total Findings: {finding_count}
- Critical: {critical}
- High: {high}

Include:
1. Executive Summary
2. Vulnerability Breakdown
3. Risk Assessment
4. Detailed Findings
5. Recommendations
6. Conclusion"""


class HuntingPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "hunting_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content="You are hunting for specific vulnerability patterns in smart contracts."
        ))
        
        messages.append(PromptMessage(
            role=PromptRole.USER,
            content=self._build_hunt_request(context)
        ))
        
        return messages
        
    def _build_hunt_request(self, context: PromptContext) -> str:
        hunt_types = context.config.get("hunt_types", ["reentrancy", "access_control"])
        
        return f"""Hunt for the following vulnerability types:
{', '.join(hunt_types)}

Search the source code for patterns indicating these vulnerabilities.
Provide detailed findings with line numbers and code snippets."""


class ReconPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "recon_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content="You are performing reconnaissance on a smart contract."
        ))
        
        messages.append(PromptMessage(
            role=PromptRole.USER,
            content=self._build_recon_request(context)
        ))
        
        return messages
        
    def _build_recon_request(self, context: PromptContext) -> str:
        return """Perform reconnaissance on the smart contract:

1. Identify contract type and purpose
2. Extract key functions
3. Map contract dependencies
4. Identify access control mechanisms
5. Analyze external interactions
6. Check for upgradeability"""


class ContextPromptBuilder(BasePromptBuilder):
    def __init__(self, name: str = "context_prompt"):
        super().__init__(name)
        
    def build(self, context: PromptContext) -> List[PromptMessage]:
        messages = []
        
        system_context = self._build_system_context(context)
        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content=system_context
        ))
        
        if context.history:
            messages.extend(context.history[-5:])
            
        return messages
        
    def _build_system_context(self, context: PromptContext) -> str:
        return f"""You are analyzing a Solidity smart contract for security vulnerabilities.

Contract Analysis Context:
- File: {context.metadata.get('file_path', 'unknown')}
- Lines: {len(context.source_code.split(chr(10)))}
- Findings: {len(context.findings)}

Prioritize findings by severity:
1. Critical: Immediate security risk
2. High: Significant security risk
3. Medium: Moderate security risk
4. Low: Minor security issue"""


class PromptManager:
    def __init__(self):
        self.builders: Dict[str, BasePromptBuilder] = {}
        self.templates: Dict[str, PromptTemplate] = {}
        self.history: Dict[str, List[PromptMessage]] = defaultdict(list)
        
    def register_builder(self, builder: BasePromptBuilder) -> None:
        self.builders[builder.name] = builder
        
    def register_template(self, template: PromptTemplate) -> None:
        self.templates[template.name] = template
        
    def build_prompt(
        self,
        builder_name: str,
        context: PromptContext
    ) -> List[PromptMessage]:
        if builder_name not in self.builders:
            return []
            
        return self.builders[builder_name].build(context)
    
    def build_from_template(
        self,
        template_name: str,
        variables: Dict[str, Any]
    ) -> str:
        if template_name not in self.templates:
            return ""
            
        template = self.templates[template_name]
        return self._render_template(template, variables)
        
    def _render_template(
        self,
        template: PromptTemplate,
        variables: Dict[str, Any]
    ) -> str:
        content = template.template
        
        for key, value in variables.items():
            content = content.replace(f"{{{key}}}", str(value))
            
        return content
        
    def save_history(
        self,
        session_id: str,
        messages: List[PromptMessage]
    ) -> None:
        self.history[session_id].extend(messages)
        
    def get_history(self, session_id: str) -> List[PromptMessage]:
        return self.history.get(session_id, [])
        
    def clear_history(self, session_id: str) -> None:
        if session_id in self.history:
            self.history[session_id].clear()
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_builders": len(self.builders),
            "total_templates": len(self.templates),
            "active_sessions": len(self.history)
        }


def build_analysis_prompt(source_code: str) -> List[PromptMessage]:
    context = PromptContext(source_code=source_code)
    builder = AnalysisPromptBuilder()
    return builder.build(context)


def build_vulnerability_prompt(findings: List[Dict[str, Any]]) -> List[PromptMessage]:
    context = PromptContext(findings=findings)
    builder = VulnerabilityPromptBuilder()
    return builder.build(context)


def build_exploit_prompt(findings: List[Dict[str, Any]]) -> List[PromptMessage]:
    context = PromptContext(findings=findings)
    builder = ExploitPromptBuilder()
    return builder.build(context)


def build_report_prompt(findings: List[Dict[str, Any]]) -> List[PromptMessage]:
    context = PromptContext(findings=findings)
    builder = ReportPromptBuilder()
    return builder.build(context)


def build_hunting_prompt(config: Dict[str, Any]) -> List[PromptMessage]:
    context = PromptContext(config=config)
    builder = HuntingPromptBuilder()
    return builder.build(context)


def build_recon_prompt(source_code: str) -> List[PromptMessage]:
    context = PromptContext(source_code=source_code)
    builder = ReconPromptBuilder()
    return builder.build(context)


def build_context_prompt(
    source_code: str,
    findings: List[Dict[str, Any]],
    metadata: Optional[Dict[str, Any]] = None
) -> List[PromptMessage]:
    context = PromptContext(
        source_code=source_code,
        findings=findings,
        metadata=metadata or {}
    )
    builder = ContextPromptBuilder()
    return builder.build(context)


def format_messages(messages: List[PromptMessage], format: PromptFormat = PromptFormat.TEXT) -> str:
    if format == PromptFormat.JSON:
        return json.dumps([
            {
                "role": m.role.value,
                "content": m.content,
                "name": m.name,
            }
            for m in messages
        ], indent=2)
    elif format == PromptFormat.XML:
        return "\n".join([
            f"<message role=\"{m.role.value}\">\n{m.content}\n</message>"
            for m in messages
        ])
    else:
        return "\n\n".join([
            f"## {m.role.value.upper()}\n\n{m.content}"
            for m in messages
        ])


_default_prompt_manager: Optional[PromptManager] = None


def get_default_prompt_manager() -> PromptManager:
    global _default_prompt_manager
    
    if _default_prompt_manager is None:
        _default_prompt_manager = PromptManager()
        _default_prompt_manager.register_builder(SystemPromptBuilder())
        _default_prompt_manager.register_builder(AnalysisPromptBuilder())
        _default_prompt_manager.register_builder(VulnerabilityPromptBuilder())
        _default_prompt_manager.register_builder(ExploitPromptBuilder())
        _default_prompt_manager.register_builder(ReportPromptBuilder())
        _default_prompt_manager.register_builder(HuntingPromptBuilder())
        _default_prompt_manager.register_builder(ReconPromptBuilder())
        _default_prompt_manager.register_builder(ContextPromptBuilder())
        
    return _default_prompt_manager


def build_prompt(prompt_type: PromptType, context: PromptContext) -> List[PromptMessage]:
    manager = get_default_prompt_manager()
    
    builders = {
        PromptType.SYSTEM: "system_prompt",
        PromptType.ANALYSIS: "analysis_prompt",
        PromptType.EXPLOIT: "exploit_prompt",
        PromptType.REPORT: "report_prompt",
        PromptType.HUNTING: "hunting_prompt",
        PromptType.RECON: "recon_prompt",
        PromptType.CONTEXT: "context_prompt",
    }
    
    builder_name = builders.get(prompt_type, "analysis_prompt")
    return manager.build_prompt(builder_name, context)


def get_prompt_stats() -> Dict[str, Any]:
    return get_default_prompt_manager().get_stats()