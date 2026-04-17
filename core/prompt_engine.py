"""
Solidify Prompt Engine
Builds prompts for smart contract auditing

Author: Peace Stephen (Tech Lead)
Description: Prompt templates and response parsing
"""

import json
import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class PromptTemplate:
    """Prompt template configuration"""
    name: str
    template: str
    description: str
    max_tokens: int = 8192
    temperature: float = 0.5


@dataclass
class AuditPromptConfig:
    """Configuration for audit prompts"""
    include_patches: bool = True
    include_confidence: bool = True
    include_cwe: bool = True
    confidence_threshold: float = 0.5
    max_vulnerabilities: int = 50
    include_gas_analysis: bool = False
    include_defi_patterns: bool = False


# ============================================================================
# Prompt Templates
# ============================================================================

class PromptTemplates:
    """Collection of prompt templates"""
    
    SYSTEM_PROMPT = """You are Solidify, an expert smart contract security auditor powered by Google Gemini.

Your role is to analyze Solidity smart contracts for security vulnerabilities and provide:
1. Vulnerability identification with severity ratings
2. Plain English explanations (non-technical)
3. AI-generated secure code patches
4. Risk scores and recommendations

You must respond ONLY with valid JSON. No markdown, no explanations outside the JSON structure.

For each vulnerability found, include:
- vulnerability_name: string (e.g., "Reentrancy")
- severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
- cvss_score: float (0.0 - 10.0)
- description: string (plain English, max 3 sentences)
- affected_lines: list of integers
- original_code: string (vulnerable snippet)
- patched_code: string (secure replacement)
- confidence: float (0.0 - 1.0)
- cwe_id: string (e.g., "CWE-307")

Return valid JSON that can be parsed by Python's json.loads()."""

    AUDIT_TEMPLATE = """Analyze the following Solidity smart contract for security vulnerabilities.

Contract Name: {contract_name}
Chain: {chain}

Contract Code:
```{language}
{code}
```

Configuration:
- Include patches: {include_patches}
- Confidence threshold: {confidence_threshold}
- Max vulnerabilities: {max_vulnerabilities}

Return a JSON audit report with this schema:
{{
  "contract_name": "string",
  "audit_summary": "string (max 200 chars)",
  "overall_risk_score": "float (0.0-10.0)",
  "total_vulnerabilities": "integer",
  "vulnerabilities": [
    {{
      "vulnerability_name": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_score": "float",
      "description": "string",
      "affected_lines": [integers],
      "original_code": "string",
      "patched_code": "string",
      "confidence": "float",
      "cwe_id": "string"
    }}
  ],
  "recommendations": ["strings"]
}}

Start response with {{ and end with }}."""

    PATCH_TEMPLATE = """Generate a secure patch for the following vulnerable Solidity code.

Vulnerable Code:
```
{vulnerable_code}
```

Vulnerability Type: {vulnerability_type}
Severity: {severity}

Generate the patched code that:
1. Fixes the vulnerability
2. Maintains original functionality
3. Follows best practices
4. Is well-commented

Return ONLY the code, no explanations. Start directly with the code."""

    EXPLAIN_TEMPLATE = """Explain this smart contract vulnerability in simple terms.

Vulnerability: {vulnerability_name}
Severity: {severity}
Context: {context}

Provide:
1. What it is (1-2 sentences, beginner-friendly)
2. Why it's dangerous (1-2 sentences)
3. How attackers exploit it (2-3 sentences)
4. Real-world analogy (1 sentence)

Keep explanations accessible to developers without security background."""

    NATURAL_LANGUAGE_TEMPLATE = """You are Solidify, a smart contract security expert.

The user is asking about their contract: "{question}"

Contract Code:
```
{code}
```

Answer their question based on the contract's security analysis. 
Be helpful, accurate, and provide actionable advice.
If the question is outside your expertise, politely explain your limits.

Answer:"""

    MULTI_CHAIN_TEMPLATE = """Analyze this {chain} smart contract for vulnerabilities.

Chain: {chain}
Contract Address: {address}

Source Code:
```
{source_code}
```

This contract is deployed on {chain_name}. Consider chain-specific attacks like:
- Bridge vulnerabilities (for cross-chain contracts)
- Oracle manipulation (for DeFi)
- Governance attacks (for DAOs)

Return standard JSON audit format."""

    GAS_OPTIMIZATION_TEMPLATE = """Analyze this Solidity contract for gas optimization opportunities.

Contract:
```
{code}
```

Identify:
1. Storage reads/writes that can be optimized
2. Unchecked math that can use unchecked blocks
3. Loop optimizations
4. Calldata vs memory usage
5. Event emissions that can be combined
6. Redundant operations

Return JSON with gas optimization suggestions:
{{
  "optimizations": [
    {{
      "type": "string",
      "description": "string",
      "estimated_savings": "string",
      "code_before": "string",
      "code_after": "string"
    }}
  ],
  "total_estimated_savings": "string"
}}"""

    EXPLOIT_POC_TEMPLATE = """Generate a proof-of-concept exploit for educational purposes.

WARNING: This is for authorized security testing only. Do not use for malicious purposes.

Vulnerability: {vulnerability_name}
Vulnerable Contract:
```
{vulnerable_code}
```

Generate a Solidity PoC contract that demonstrates how this vulnerability could be exploited.
The PoC should:
1. Be clearly labeled as educational
2. Show the attack vector
3. Include safety checks
4. Be usable in local testing (Foundry/Hardhat)

Return ONLY the Solidity code for the PoC contract."""


# ============================================================================
# Prompt Engine
# ============================================================================

class PromptEngine:
    """
    Prompt generation and response parsing for Solidify
    
    Features:
    - Multiple prompt templates
    - Response validation
    - JSON parsing
    - Error handling
    """
    
    def __init__(self, config: Optional[AuditPromptConfig] = None):
        """
        Initialize prompt engine
        
        Args:
            config: Audit prompt configuration
        """
        self.config = config or AuditPromptConfig()
        self.templates = self._load_templates()
        
        logger.info("✅ Prompt engine initialized")
    
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load all prompt templates"""
        return {
            "audit": PromptTemplate(
                name="audit",
                template=self.AUDIT_TEMPLATE,
                description="Main audit prompt for contract analysis",
                max_tokens=8192,
                temperature=0.3
            ),
            "patch": PromptTemplate(
                name="patch",
                template=self.PATCH_TEMPLATE,
                description="Generate secure patch for vulnerable code",
                max_tokens=2048,
                temperature=0.2
            ),
            "explain": PromptTemplate(
                name="explain",
                template=self.EXPLAIN_TEMPLATE,
                description="Explain vulnerability in plain English",
                max_tokens=1024,
                temperature=0.5
            ),
            "natural_language": PromptTemplate(
                name="natural_language",
                template=self.NATURAL_LANGUAGE_TEMPLATE,
                description="Answer natural language questions about contracts",
                max_tokens=2048,
                temperature=0.5
            ),
            "multi_chain": PromptTemplate(
                name="multi_chain",
                template=self.MULTI_CHAIN_TEMPLATE,
                description="Audit contracts on different chains",
                max_tokens=8192,
                temperature=0.3
            ),
            "gas_optimization": PromptTemplate(
                name="gas_optimization",
                template=self.GAS_OPTIMIZATION_TEMPLATE,
                description="Find gas optimization opportunities",
                max_tokens=4096,
                temperature=0.2
            ),
            "exploit_poc": PromptTemplate(
                name="exploit_poc",
                template=self.EXPLOIT_POC_TEMPLATE,
                description="Generate educational PoC exploit",
                max_tokens=4096,
                temperature=0.3
            )
        }
    
    def build_audit_prompt(
        self,
        code: str,
        contract_name: Optional[str] = None,
        chain: str = "ethereum",
        include_patches: Optional[bool] = None,
        confidence_threshold: Optional[float] = None,
        max_vulnerabilities: Optional[int] = None,
        language: str = "solidity"
    ) -> str:
        """
        Build audit prompt for contract analysis
        
        Args:
            code: Solidity contract code
            contract_name: Name of the contract
            chain: Blockchain chain
            include_patches: Whether to include patches
            confidence_threshold: Minimum confidence for findings
            max_vulnerabilities: Max vulnerabilities to report
            language: Code language (default: solidity)
        
        Returns:
            Formatted prompt string
        """
        # Use config values if not overridden
        inc_patches = include_patches if include_patches is not None else self.config.include_patches
        conf_threshold = confidence_threshold if confidence_threshold is not None else self.config.confidence_threshold
        max_vulns = max_vulnerabilities if max_vulnerabilities is not None else self.config.max_vulnerabilities
        
        # Format template
        prompt = self.AUDIT_TEMPLATE.format(
            contract_name=contract_name or "Unknown Contract",
            chain=chain,
            code=code,
            language=language,
            include_patches=str(inc_patches).lower(),
            confidence_threshold=conf_threshold,
            max_vulnerabilities=max_vulns
        )
        
        # Add system prompt
        full_prompt = f"{self.SYSTEM_PROMPT}\n\n{prompt}"
        
        logger.debug(f"Built audit prompt ({len(full_prompt)} chars)")
        return full_prompt
    
    def build_patch_prompt(
        self,
        vulnerable_code: str,
        vulnerability_type: str,
        severity: str
    ) -> str:
        """
        Build prompt for generating a patch
        
        Args:
            vulnerable_code: The vulnerable code snippet
            vulnerability_type: Type of vulnerability
            severity: Severity level
        
        Returns:
            Formatted patch prompt
        """
        return self.PATCH_TEMPLATE.format(
            vulnerable_code=vulnerable_code,
            vulnerability_type=vulnerability_type,
            severity=severity
        )
    
    def build_explain_prompt(
        self,
        vulnerability_name: str,
        severity: str,
        context: str = ""
    ) -> str:
        """
        Build prompt for explaining a vulnerability
        
        Args:
            vulnerability_name: Name of the vulnerability
            severity: Severity level
            context: Additional context
        
        Returns:
            Formatted explanation prompt
        """
        return self.EXPLAIN_TEMPLATE.format(
            vulnerability_name=vulnerability_name,
            severity=severity,
            context=context
        )
    
    def build_natural_language_prompt(
        self,
        question: str,
        code: str
    ) -> str:
        """
        Build prompt for natural language queries
        
        Args:
            question: User's question
            code: Contract code
        
        Returns:
            Formatted query prompt
        """
        return self.NATURAL_LANGUAGE_TEMPLATE.format(
            question=question,
            code=code
        )
    
    def build_multi_chain_prompt(
        self,
        source_code: str,
        address: str,
        chain: str
    ) -> str:
        """
        Build prompt for multi-chain analysis
        
        Args:
            source_code: Contract source code
            address: Contract address
            chain: Chain identifier
        
        Returns:
            Formatted multi-chain prompt
        """
        chain_names = {
            "ethereum": "Ethereum",
            "bsc": "Binance Smart Chain",
            "polygon": "Polygon",
            "arbitrum": "Arbitrum",
            "optimism": "Optimism",
            "base": "Base"
        }
        
        return self.MULTI_CHAIN_TEMPLATE.format(
            chain=chain,
            address=address,
            source_code=source_code,
            chain_name=chain_names.get(chain, chain)
        )
    
    def build_gas_optimization_prompt(self, code: str) -> str:
        """
        Build prompt for gas optimization
        
        Args:
            code: Contract code
        
        Returns:
            Formatted gas optimization prompt
        """
        return self.GAS_OPTIMIZATION_TEMPLATE.format(code=code)
    
    def build_exploit_poc_prompt(
        self,
        vulnerable_code: str,
        vulnerability_name: str
    ) -> str:
        """
        Build prompt for PoC exploit generation
        
        Args:
            vulnerable_code: Vulnerable contract code
            vulnerability_name: Name of vulnerability
        
        Returns:
            Formatted PoC prompt
        """
        return self.EXPLOIT_POC_TEMPLATE.format(
            vulnerable_code=vulnerable_code,
            vulnerability_name=vulnerability_name
        )
    
    def parse_audit_response(self, response: str) -> Dict[str, Any]:
        """
        Parse Gemini response into structured audit data
        
        Args:
            response: Raw response from Gemini
        
        Returns:
            Parsed audit data dictionary
        
        Raises:
            ValueError: If response cannot be parsed
        """
        logger.debug(f"Parsing audit response ({len(response)} chars)")
        
        # Clean response
        cleaned = self._clean_json_response(response)
        
        try:
            # Parse JSON
            data = json.loads(cleaned)
            
            # Validate required fields
            required = ["contract_name", "audit_summary", "overall_risk_score", "vulnerabilities"]
            for field in required:
                if field not in data:
                    logger.warning(f"Missing field in response: {field}")
                    data[field] = None if field != "vulnerabilities" else []
            
            # Ensure vulnerabilities is a list
            if not isinstance(data.get("vulnerabilities"), list):
                data["vulnerabilities"] = []
            
            # Ensure recommendations is a list
            if not isinstance(data.get("recommendations"), list):
                data["recommendations"] = []
            
            logger.info(f"Parsed audit with {len(data.get('vulnerabilities', []))} vulnerabilities")
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {str(e)}\nResponse: {response[:500]}")
            raise ValueError(f"Failed to parse audit response: {str(e)}")
    
    def _clean_json_response(self, response: str) -> str:
        """
        Clean and extract JSON from response
        
        Args:
            response: Raw response
        
        Returns:
            Cleaned JSON string
        """
        # Remove markdown code blocks
        response = response.strip()
        
        # Remove ```json or ``` markers
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            response = response.split("```")[1].split("```")[0]
        
        # Remove any leading/trailing text
        response = response.strip()
        
        # Ensure it starts with { and ends with }
        if not response.startswith("{"):
            # Try to find where JSON starts
            start = response.find("{")
            if start != -1:
                response = response[start:]
        
        if not response.endswith("}"):
            # Try to find where JSON ends
            end = response.rfind("}")
            if end != -1:
                response = response[:end+1]
        
        return response
    
    def validate_audit_data(self, data: Dict[str, Any]) -> bool:
        """
        Validate audit data structure
        
        Args:
            data: Parsed audit data
        
        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        required_fields = [
            "contract_name",
            "audit_summary",
            "overall_risk_score",
            "total_vulnerabilities",
            "vulnerabilities",
            "recommendations"
        ]
        
        for field in required_fields:
            if field not in data:
                logger.warning(f"Missing required field: {field}")
                return False
        
        # Validate types
        if not isinstance(data["vulnerabilities"], list):
            return False
        
        if not isinstance(data["recommendations"], list):
            return False
        
        # Validate risk score range
        if not 0 <= data["overall_risk_score"] <= 10:
            logger.warning(f"Invalid risk score: {data['overall_risk_score']}")
            return False
        
        return True
    
    def filter_by_confidence(
        self,
        vulnerabilities: List[Dict[str, Any]],
        threshold: float
    ) -> List[Dict[str, Any]]:
        """
        Filter vulnerabilities by confidence threshold
        
        Args:
            vulnerabilities: List of vulnerabilities
            threshold: Minimum confidence threshold
        
        Returns:
            Filtered list
        """
        return [
            vuln for vuln in vulnerabilities
            if vuln.get("confidence", 1.0) >= threshold
        ]
    
    def sort_by_severity(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Sort vulnerabilities by severity
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            Sorted list (CRITICAL first)
        """
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4
        }
        
        return sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "INFO"), 99)
        )
    
    def get_template(self, name: str) -> Optional[PromptTemplate]:
        """Get a specific template by name"""
        return self.templates.get(name)
    
    def list_templates(self) -> List[str]:
        """List all available template names"""
        return list(self.templates.keys())


# ============================================================================
# Factory Functions
# ============================================================================

def create_prompt_engine(
    include_patches: bool = True,
    confidence_threshold: float = 0.5
) -> PromptEngine:
    """
    Create a configured prompt engine
    
    Args:
        include_patches: Whether to include patches
        confidence_threshold: Minimum confidence threshold
    
    Returns:
        Configured PromptEngine
    """
    config = AuditPromptConfig(
        include_patches=include_patches,
        confidence_threshold=confidence_threshold
    )
    return PromptEngine(config)


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    # Test prompt engine
    engine = PromptEngine()
    
    # Test audit prompt
    code = """
    pragma solidity ^0.8.0;
    contract Test {
        function withdraw() public {
            msg.sender.call{value: address(this).balance}("");
        }
    }
    """
    
    prompt = engine.build_audit_prompt(code, "TestContract")
    print(f"Audit prompt length: {len(prompt)}")
    
    # Test parsing
    sample_response = '''
    {
        "contract_name": "TestContract",
        "audit_summary": "Test summary",
        "overall_risk_score": 8.5,
        "total_vulnerabilities": 1,
        "vulnerabilities": [
            {
                "vulnerability_name": "Reentrancy",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "description": "Test vulnerability",
                "affected_lines": [5],
                "original_code": "msg.sender.call{value: address(this).balance}(\"\");",
                "patched_code": "msg.sender.transfer(address(this).balance);",
                "confidence": 0.95,
                "cwe_id": "CWE-307"
            }
        ],
        "recommendations": ["Use ReentrancyGuard"]
    }
    '''
    
    result = engine.parse_audit_response(sample_response)
    print(f"Parsed: {result['contract_name']}, vulns: {result['total_vulnerabilities']}")