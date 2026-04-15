"""
SoliGuard Base Prompt
Foundation prompt templates and utilities

Author: Peace Stephen (Tech Lead)
Description: Base prompt system for SoliGuard security auditing
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Callable, Set, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class PromptType(Enum):
    """Prompt types"""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    FUNCTION = "function"
    CHAIN_OF_THOUGHT = "chain_of_thought"
    FEW_SHOT = "few_shot"
    ZERO_SHOT = "zero_shot"
    CHAIN = "chain"
    TREE_OF_THOUGHT = "tree_of_thought"


class PromptStyle(Enum):
    """Prompt style"""
    CONCISE = "concise"
    STANDARD = "standard"
    DETAILED = "detailed"
    VERBOSE = "verbose"
    TECHNICAL = "technical"


class SecurityDomain(Enum):
    """Security domains"""
    SMART_CONTRACT = "smart_contract"
    DEFI = "defi"
    NFT = "nft"
    BRIDGE = "bridge"
    ORACLE = "oracle"
    GOVERNANCE = "governance"
    TOKEN = "token"
    MULTISIG = "multisig"
    GENERAL = "general"


@dataclass
class PromptTemplate:
    """Prompt template"""
    name: str
    template: str
    prompt_type: PromptType = PromptType.SYSTEM
    style: PromptStyle = PromptStyle.STANDARD
    domain: SecurityDomain = SecurityDomain.GENERAL
    variables: List[str] = field(default_factory=list)
    examples: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptResponse:
    """Parsed prompt response"""
    content: str
    raw_response: str
    parsed_data: Optional[Dict[str, Any]] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class PromptContext:
    """Prompt context"""
    contract_code: str = ""
    contract_name: Optional[str] = None
    chain: str = "ethereum"
    audit_type: str = "standard"
    include_patches: bool = True
    confidence_threshold: float = 0.5
    max_vulnerabilities: int = 50
    language: str = "en"
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Vulnerability Categories
# ============================================================================

VULNERABILITY_CATEGORIES = {
    "reentrancy": {
        "name": "Reentrancy",
        "severity": "critical",
        "cwe": "CWE-362",
        "capec": "CAPEC-46"
    },
    "access_control": {
        "name": "Access Control",
        "severity": "critical",
        "cwe": "CWE-284",
        "capec": "CAPEC-39"
    },
    "arithmetic_overflow": {
        "name": "Integer Overflow",
        "severity": "high",
        "cwe": "CWE-190",
        "capec": "CAPEC-128"
    },
    "front_running": {
        "name": "Front Running",
        "severity": "medium",
        "cwe": "CWE-506",
        "capec": "CAPEC-117"
    },
    "flash_loan_attack": {
        "name": "Flash Loan Attack",
        "severity": "high",
        "cwe": "CWE-362",
        "capec": "CAPEC-31"
    },
    "oracle_manipulation": {
        "name": "Oracle Manipulation",
        "severity": "high",
        "cwe": "CWE-506",
        "capec": "CAPEC-128"
    },
    "approval_giveaway": {
        "name": "Token Approval Giveaway",
        "severity": "high",
        "cwe": "CWE-284",
        "capec": "CAPEC-39"
    },
    "unprotected_function": {
        "name": "Unprotected Function",
        "severity": "critical",
        "cwe": "CWE-284",
        "capec": "CAPEC-39"
    },
    "tx_origin": {
        "name": "Tx.origin Usage",
        "severity": "medium",
        "cwe": "CWE-478",
        "capec": "CAPEC-68"
    },
    "weak_randomness": {
        "name": "Weak Randomness",
        "severity": "medium",
        "cwe": "CWE-338",
        "capec": "CAPEC-130"
    },
    "dos": {
        "name": "Denial of Service",
        "severity": "high",
        "cwe": "CWE-400",
        "capec": "CAPEC-128"
    },
    "centralization": {
        "name": "Centralization Risk",
        "severity": "medium",
        "cwe": "CWE-295",
        "capec": "CAPEC-112"
    }
}


# ============================================================================
# Security Analysis Functions
# ============================================================================

SECURITY_FUNCTIONS = {
    "analyze_reentrancy": {
        "description": "Check for reentrancy vulnerabilities",
        "checks": ["external_call_before_state_change", "untrusted_call", "missing_checks_effects_interactions"]
    },
    "check_access_control": {
        "description": "Verify access control mechanisms",
        "checks": ["only_modifier", "ownership", "role_based", "function_visibility"]
    },
    "analyze_arithmetic": {
        "description": "Check for arithmetic overflow/underflow",
        "checks": ["safemath_usage", "unchecked_low_level", "native_overflow"]
    },
    "check_oracle_safety": {
        "description": "Analyze oracle usage",
        "checks": ["chainlink_usage", "uniswap_twap", "price_manipulation"]
    },
    "analyze_gas": {
        "description": "Gas optimization analysis",
        "checks": ["loop_gas", "cache_storage", "unnecessary_storage"]
    },
    "check_standards": {
        "description": "Verify standard compliance",
        "checks": ["ERC20", "ERC721", "ERC1155", "ERC4626"]
    }
}


# ============================================================================
# Base Prompt Builder
# ============================================================================

class BasePromptBuilder:
    """
    Base prompt builder
    
    Features:
    - Template rendering
    - Variable substitution
    - Output parsing
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.templates: Dict[str, PromptTemplate] = {}
        self._register_default_templates()
    
    def _register_default_templates(self):
        self.templates["system_base"] = PromptTemplate(
            name="system_base",
            template=self._get_system_base_template(),
            prompt_type=PromptType.SYSTEM,
            style=PromptStyle.STANDARD,
            domain=SecurityDomain.SMART_CONTRACT,
            variables=["contract_code", "chain", "include_patches"]
        )
    
    def _get_system_base_template(self) -> str:
        return """You are SoliGuard, an expert smart contract security auditor specialized in blockchain security.

Your role is to analyze Solidity smart contracts for vulnerabilities, security risks, and potential exploits.

## Security Domains
- Smart Contracts (ERC20, ERC721, ERC1155, ERC4626)
- DeFi Protocols (Uniswap, Aave, Compound)
- Bridges (Cross-chain)
- Oracles (Chainlink, Uniswap)
- Governance (Governor, Timelock)

## Vulnerability Categories
{_vulnerability_categories}

## Analysis Functions
{security_functions}

## Output Format
Always output valid JSON in this format:
{{
    "vulnerabilities": [
        {{
            "title": "Vulnerability Title",
            "severity": "critical|high|medium|low|info",
            "description": "Detailed description",
            "location": "Line numbers or function name",
            "cwe": "CWE-ID",
            "cvss_score": 0.0-10.0,
            "impact": "Security impact description",
            "recommendation": "How to fix"
        }}
    ],
    "risk_score": 0.0-10.0,
    "summary": "Brief summary"
}}

## Guidelines
1. Always provide specific line numbers for vulnerabilities
2. Include CWE references when applicable
3. Provide actionable remediation recommendations
4. Consider DeFi-specific attack vectors
5. Check for common proxy patterns vulnerabilities"""

    def build_system_prompt(self, context: PromptContext) -> str:
        template = self.templates.get("system_base")
        if not template:
            return ""
        
        vuln_cats = self._format_vulnerability_categories()
        sec_funcs = self._format_security_functions()
        
        prompt = template.template.format(
            vulnerability_categories=vuln_cats,
            security_functions=sec_funcs
        )
        
        return prompt
    
    def _format_vulnerability_categories(self) -> str:
        lines = []
        for key, vuln in VULNERABILITY_CATEGORIES.items():
            lines.append(f"- {key}: {vuln['name']} ({vuln['severity']})")
        return "\n".join(lines)
    
    def _format_security_functions(self) -> str:
        lines = []
        for key, func in SECURITY_FUNCTIONS.items():
            lines.append(f"- {key}: {func['description']}")
        return "\n".join(lines)
    
    def build(self, context: PromptContext, template_name: str = "system_base") -> str:
        template = self.templates.get(template_name)
        if not template:
            return self.build_system_prompt(context)
        
        return self._render_template(template, context)
    
    def _render_template(self, template: PromptTemplate, context: PromptContext) -> str:
        result = template.template
        
        for var in template.variables:
            value = getattr(context, var, None)
            if value is not None:
                result = result.replace(f"{{{var}}}", str(value))
        
        return result


# ============================================================================
# Prompt Validator
# ============================================================================

class PromptValidator:
    """
    Validate prompt responses
    
    Features:
    - Schema validation
    - Confidence scoring
    - Error detection
    """
    
    def __init__(self):
        self.validation_rules: Dict[str, Callable] = {
            "valid_json": self._validate_json,
            "has_vulnerabilities": self._validate_vulnerabilities,
            "has_severity": self._validate_severity,
            "has_locations": self._validate_locations
        }
    
    def validate(self, response: str) -> PromptResponse:
        raw_response = response
        
        parsed_data = self._parse_json(response)
        
        confidence = self._calculate_confidence(parsed_data)
        
        return PromptResponse(
            content=response[:1000] if len(response) > 1000 else response,
            raw_response=response,
            parsed_data=parsed_data,
            confidence=confidence
        )
    
    def _parse_json(self, response: str) -> Optional[Dict[str, Any]]:
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        return None
    
    def _calculate_confidence(self, data: Optional[Dict[str, Any]]) -> float:
        if not data:
            return 0.0
        
        score = 0.0
        
        if "vulnerabilities" in data:
            score += 0.3
        if "risk_score" in data:
            score += 0.2
        if "summary" in data:
            score += 0.2
        
        vulns = data.get("vulnerabilities", [])
        if vulns:
            valid = sum(1 for v in vulns if all(k in v for k in ["title", "severity", "description"]))
            score += min(0.3, valid / len(vulns) * 0.3)
        
        return min(1.0, score)
    
    def _validate_json(self, response: str) -> bool:
        return self._parse_json(response) is not None
    
    def _validate_vulnerabilities(self, response: str) -> bool:
        data = self._parse_json(response)
        return data is not None and "vulnerabilities" in data
    
    def _validate_severity(self, response: str) -> bool:
        data = self._parse_json(response)
        if not data:
            return False
        vulns = data.get("vulnerabilities", [])
        return all(v.get("severity") for v in vulns)
    
    def _validate_locations(self, response: str) -> bool:
        data = self._parse_json(response)
        if not data:
            return False
        vulns = data.get("vulnerabilities", [])
        return all(v.get("location") for v in vulns)


# ============================================================================
# Prompt Parser
# ============================================================================

class PromptParser:
    """
    Parse and extract data from prompt responses
    
    Features:
    - Multi-format parsing
    - Fallback handling
    - Data extraction
    """
    
    def __init__(self):
        self.parsers: Dict[str, Callable] = {
            "json": self._parse_json,
            "markdown": self._parse_markdown,
            "text": self._parse_text
        }
    
    def parse(self, response: str, format_hint: Optional[str] = None) -> Dict[str, Any]:
        if format_hint and format_hint in self.parsers:
            return self.parsers[format_hint](response)
        
        for parser_name, parser in self.parsers.items():
            try:
                result = parser(response)
                if result:
                    return result
            except Exception:
                pass
        
        return self._parse_text(response)
    
    def _parse_json(self, response: str) -> Dict[str, Any]:
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        return {}
    
    def _parse_markdown(self, response: str) -> Dict[str, Any]:
        result = {"vulnerabilities": []}
        lines = response.split("\n")
        current_vuln = None
        
        for line in lines:
            line = line.strip()
            if line.startswith("##") or line.startswith("###"):
                if current_vuln:
                    result["vulnerabilities"].append(current_vuln)
                current_vuln = {"title": line.lstrip("#").strip(), "description": ""}
            elif line.startswith("**") and ":**" in line:
                key, value = line.replace("**", "").split(":**", 1)
                if current_vuln:
                    current_vuln[key.strip().lower()] = value.strip()
        
        if current_vuln:
            result["vulnerabilities"].append(current_vuln)
        
        return result
    
    def _parse_text(self, response: str) -> Dict[str, Any]:
        result = {"vulnerabilities": [], "summary": response[:200]}
        
        patterns = [
            r"(?i)critical[:\s]+(\d+)",
            r"(?i)high[:\s]+(\d+)",
            r"(?i)medium[:\s]+(\d+)",
            r"(?i)low[:\s]+(\d+)"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response)
            if matches:
                result["vulnerabilities"].extend([{"severity": "found"}] * len(matches))
        
        return result
    
    def extract_vulnerabilities(self, response: str) -> List[Dict[str, Any]]:
        data = self.parse(response)
        return data.get("vulnerabilities", [])
    
    def extract_summary(self, response: str) -> str:
        data = self.parse(response)
        return data.get("summary", response[:200])
    
    def extract_risk_score(self, response: str) -> float:
        data = self.parse(response)
        try:
            return float(data.get("risk_score", 0.0))
        except (ValueError, TypeError):
            return 0.0


# ============================================================================
# Prompt Chain
# ============================================================================

class PromptChain:
    """
    Chain multiple prompts together
    
    Features:
    - Sequential execution
    - Conditional branching
    - Result passing
    """
    
    def __init__(self):
        self.steps: List[Dict[str, Any]] = []
        self.results: Dict[str, Any] = {}
    
    def add_step(
        self,
        name: str,
        prompt_template: str,
        condition: Optional[Callable] = None,
        post_processor: Optional[Callable] = None
    ) -> "PromptChain":
        self.steps.append({
            "name": name,
            "template": prompt_template,
            "condition": condition,
            "post_processor": post_processor
        })
        return self
    
    async def execute(self, initial_context: Dict[str, Any]) -> Dict[str, Any]:
        current_data = initial_context.copy()
        
        for step in self.steps:
            if step["condition"] and not step["condition"](current_data):
                continue
            
            prompt = step["template"].format(**current_data)
            
            current_data["prompt"] = prompt
            
            if step["post_processor"]:
                current_data = step["post_processor"](current_data)
            
            self.results[step["name"]] = current_data
        
        return self.results
    
    def get_results(self) -> Dict[str, Any]:
        return self.results.copy()
    
    def clear_results(self) -> None:
        self.results.clear()


# ============================================================================
# Few-Shot Examples
# ============================================================================

FEW_SHOT_EXAMPLES = [
    {
        "input": """contract Test {{
    mapping(address => uint) balances;
    function withdraw() public {{
        require(balances[msg.sender] > 0);
        (bool success, ) = msg.sender.call.value(balances[msg.sender])("");
        balances[msg.sender] = 0;
    }}
}}""",
        "output": {
            "vulnerabilities": [
                {
                    "title": "Reentrancy Vulnerability",
                    "severity": "critical",
                    "description": "The withdraw function makes an external call before updating the state variable balances[msg.sender], allowing an attacker to recursively call withdraw() multiple times.",
                    "location": "withdraw():7-8",
                    "cwe": "CWE-362",
                    "cvss_score": 9.1,
                    "impact": "Attacker can drain all funds from the contract",
                    "recommendation": "Use Checks-Effects-Interactions pattern. Update state before external call."
                }
            ],
            "risk_score": 9.1,
            "summary": "1 critical vulnerability found"
        }
    },
    {
        "input": """contract Token {{
    mapping(address => uint) public balanceOf;
    function transfer(address to, uint amount) public {{
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }}
}}""",
        "output": {
            "vulnerabilities": [
                {
                    "title": "Integer Underflow",
                    "severity": "high",
                    "description": "No SafeMath used for arithmetic operations, potential underflow when amount > balanceOf[msg.sender].",
                    "location": "transfer():5",
                    "cwe": "CWE-190",
                    "cvss_score": 7.5,
                    "impact": "Can cause underflow allowing arbitrary value manipulation",
                    "recommendation": "Use OpenZeppelin SafeMath library"
                }
            ],
            "risk_score": 7.5,
            "summary": "1 high severity vulnerability found"
        }
    }
]


# ============================================================================
# Main Base Prompt
# ============================================================================

class BasePrompt:
    """
    Main base prompt manager
    
    Features:
    - Template management
    - Context building
    - Response parsing
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.builder = BasePromptBuilder(config)
        self.validator = PromptValidator()
        self.parser = PromptParser()
        self.chain = PromptChain()
        
        self._setup_default_chain()
        
        logger.info("✅ Base Prompt initialized")
    
    def _setup_default_chain(self):
        self.chain.add_step(
            "analyze",
            "Analyze this smart contract and identify vulnerabilities: {code}"
        )
    
    def build_audit_prompt(
        self,
        contract_code: str,
        contract_name: Optional[str] = None,
        chain: str = "ethereum",
        include_patches: bool = True,
        confidence_threshold: float = 0.5
    ) -> str:
        context = PromptContext(
            contract_code=contract_code,
            contract_name=contract_name,
            chain=chain,
            include_patches=include_patches,
            confidence_threshold=confidence_threshold
        )
        
        return self.builder.build(context)
    
    def build_system_prompt(self) -> str:
        context = PromptContext()
        return self.builder.build_system_prompt(context)
    
    def parse_response(self, response: str) -> PromptResponse:
        return self.validator.validate(response)
    
    def extract_vulnerabilities(self, response: str) -> List[Dict[str, Any]]:
        return self.parser.extract_vulnerabilities(response)
    
    def extract_summary(self, response: str) -> str:
        return self.parser.extract_summary(response)
    
    def get_few_shot_examples(self) -> List[Dict[str, Any]]:
        return FEW_SHOT_EXAMPLES
    
    def get_vulnerability_categories(self) -> Dict[str, Dict[str, str]]:
        return VULNERABILITY_CATEGORIES
    
    def get_security_functions(self) -> Dict[str, Dict[str, Any]]:
        return SECURITY_FUNCTIONS