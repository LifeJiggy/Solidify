"""
SoliGuard Audit System Prompt
Master system prompt for smart contract security auditing

Author: Peace Stephen (Tech Lead)
Description: System prompt for AI-powered security analysis
"""

import json
from typing import Dict, List, Optional, Any
from enum import Enum


class AuditMode(Enum):
    FULL = "full"
    QUICK = "quick"
    DEEP = "deep"
    TARGETED = "targeted"


class OutputFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    TEXT = "text"
    SARIF = "sarif"


AUDIT_SYSTEM_PROMPT = """You are SoliGuard, an AI-powered smart contract security auditor for the GDG Abuja × Build with AI Sprint Hackathon.

## Your Role

You are an expert smart contract security analyst specializing in:
- Static analysis of Solidity smart contracts
- Vulnerability detection and classification
- Exploit scenario generation
- Security best practice recommendations
- Comprehensive security reporting

## Analysis Capabilities

When given a Solidity smart contract to analyze, you should:

1. **Identify Vulnerabilities**
   - Reentrancy attacks
   - Access control issues
   - Integer overflow/underflow
   - Oracle manipulation
   - Front-running risks
   - Centralization risks
   - Denial of service vectors

2. **Classify by Severity**
   - Critical: Immediate exploitation risk, fund loss possible
   - High: Significant security risk
   - Medium: Moderate risk
   - Low: Minor issues

3. **Provide Actionable Recommendations**
   - Code fixes
   - Best practice suggestions
   - Mitigation strategies

4. **Generate Exploit Proof of Concepts**
   - Example attack scenarios
   - Step-by-step execution

5. **Produce Comprehensive Reports**
   - Executive summary
   - Vulnerability breakdown
   - Risk assessment
   - Remediation steps

## Output Format

Always provide output in the specified JSON format with:
- Finding type
- Severity level
- Line numbers
- Code snippets
- Recommendations

## Guidelines

- Prioritize security over functionality
- Provide detailed, actionable recommendations
- Include relevant CWE references
- Use CVSS scores when applicable
- Be thorough but concise
"""

SYSTEM_PROMPT = AUDIT_SYSTEM_PROMPT


DETAILED_ANALYSIS_GUIDE = """
## Detailed Analysis Guidelines

### Reentrancy Detection
1. Check for external calls (.call, .transfer, .send) before state changes
2. Look for callback functions (receive, fallback)
3. Identify any missing nonReentrant modifiers
4. Check CEI (Checks-Effects-Interactions) pattern usage
5. Look for state variable updates after external calls

### Access Control Detection
1. Identify all public/external functions
2. Check for missing access control modifiers (onlyOwner, onlyAdmin)
3. Look for tx.origin usage for authorization
4. Identify upgradeable functions
5. Check for missing role-based access control

### Arithmetic Detection
1. Find all arithmetic operations (+, -, *, /)
2. Check for SafeMath usage or Solidity 0.8+ checked arithmetic
3. Look for unchecked return values
4. Identify potential overflow/underflow scenarios

### Oracle Manipulation Detection
1. Check for price oracle usage
2. Identify swap-based price calculations
3. Look for flash loan attack vectors
4. Check for TWAP vs spot price usage
5. Verify staleness checks

### Front-Running Detection
1. Look for public mempool-visible transactions
2. Check for missing slippage protection in swaps
3. Identify batch transaction vulnerabilities
4. Check for linear pricing mechanisms

### Centralization Detection
1. Identify single owner patterns
2. Check for upgradeable contracts without timelocks
3. Look for admin pausable functionality
4. Find unlimited minting capabilities
5. Identify admin fee setters
"""

VULNERABILITY_PATTERNS = {
    "reentrancy": [
        "msg.sender.call{value:",
        ".call(abi.encodeWithSignature",
        "address(this).balance",
        "balanceOf[msg.sender]",
    ],
    "access_control": [
        "tx.origin ==",
        "require(owner =",
        "onlyOwner",
        "onlyAdmin",
        "AccessControl",
    ],
    "arithmetic": [
        "+=",
        "-=",
        "*=",
        "/=",
        "SafeMath",
    ],
    "oracle": [
        "latestRoundData",
        "getReserves",
        "swapExact",
        "twap",
    ],
    "front_running": [
        "minOutput",
        "minAmount",
        "slippage",
    ],
    "centralization": [
        "owner",
        "upgradeTo",
        "pause",
        "mint",
    ],
}


SEVERITY_GUIDE = """
## Severity Classification Guide

### Critical (CVSS 9.0-10.0)
- Direct fund theft possible
- Complete contract takeover
- Selfdestruct without access control
- Unlimited minting
- Reentrancy with funds at risk

### High (CVSS 7.0-8.9)
- Access control bypass
- Integer overflow/underflow
- Oracle manipulation
- Unchecked external calls

### Medium (CVSS 4.0-6.9)
- Front-running vulnerabilities
- Block timestamp dependence
- Weak randomness
- Missing events

### Low (CVSS 0.1-3.9)
- Code quality issues
- Style violations
- Missing documentation
- Unused variables
"""

CWE_REFERENCES = {
    "CWE-362": "Race Condition",
    "CWE-190": "Integer Overflow or Underflow",
    "CWE-862": "Missing Authorization",
    "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-707": "Improper Input Validation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-506": "Embedded Malicious Code",
    "CWE-337": "Use of Insufficiently Random Values",
    "CWE-386": "Race Condition (Time of Check Time of Use)",
}


def get_audit_system_prompt() -> str:
    return AUDIT_SYSTEM_PROMPT


def get_analysis_prompt(contract_code: str, mode: AuditMode = AuditMode.FULL) -> str:
    mode_instructions = {
        AuditMode.QUICK: "Perform a quick scan focusing on critical and high severity issues.",
        AuditMode.DEEP: "Perform a deep analysis with thorough examination of all vulnerability types.",
        AuditMode.TARGETED: "Focus on specific vulnerability types mentioned in the contract.",
        AuditMode.FULL: "Perform a comprehensive full audit covering all vulnerability categories.",
    }
    
    return f"""{AUDIT_SYSTEM_PROMPT}

## Contract to Analyze

```{contract_code}
```

## Analysis Mode

{mode_instructions.get(mode, mode_instructions[AuditMode.FULL])}

## Detailed Analysis Guidelines

{DETAILED_ANALYSIS_GUIDE}

Please analyze this contract and provide your findings in JSON format.
"""


def get_exploit_prompt(vulnerability: dict) -> str:
    return f"""{AUDIT_SYSTEM_PROMPT}

Generate a proof-of-concept exploit for this vulnerability:

{vulnerability}

Provide:
1. Attack contract in Solidity
2. Step-by-step execution
3. Required preconditions
4. Expected impact
"""


def get_report_prompt(findings: list, format: OutputFormat = OutputFormat.JSON) -> str:
    format_instructions = {
        OutputFormat.JSON: "Provide output in JSON format.",
        OutputFormat.MARKDOWN: "Provide output in Markdown format.",
        OutputFormat.TEXT: "Provide output in plain text format.",
        OutputFormat.SARIF: "Provide output in SARIF format.",
    }
    
    return f"""{AUDIT_SYSTEM_PROMPT}

Generate a comprehensive security report for these findings:

{findings}

## Report Requirements

- Executive summary
- Vulnerability breakdown by severity
- Risk assessment
- Detailed findings with line numbers
- Remediation steps
- CWE references

## Output Format

{format_instructions.get(format, format_instructions[OutputFormat.JSON])}
"""


def get_severity_guide() -> str:
    return SEVERITY_GUIDE


def get_cwe_references() -> Dict[str, str]:
    return CWE_REFERENCES


def get_vulnerability_patterns() -> Dict[str, List[str]]:
    return VULNERABILITY_PATTERNS


def get_detailed_analysis_guide() -> str:
    return DETAILED_ANALYSIS_GUIDE


class AuditConfig:
    def __init__(
        self,
        mode: AuditMode = AuditMode.FULL,
        output_format: OutputFormat = OutputFormat.JSON,
        include_exploits: bool = True,
        include_recommendations: bool = True,
    ):
        self.mode = mode
        self.output_format = output_format
        self.include_exploits = include_exploits
        self.include_recommendations = include_recommendations
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "output_format": self.output_format.value,
            "include_exploits": self.include_exploits,
            "include_recommendations": self.include_recommendations,
        }


def build_audit_prompt(contract_code: str, config: Optional[AuditConfig] = None) -> str:
    if config is None:
        config = AuditConfig()
    
    prompt = get_analysis_prompt(contract_code, config.mode)
    
    if config.include_exploits:
        prompt += "\n\nInclude exploit proof-of-concepts for critical findings."
    
    if config.include_recommendations:
        prompt += "\n\nProvide detailed remediation recommendations for each finding."
    
    return prompt


def parse_finding_response(response: str) -> Dict[str, Any]:
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        return {"error": "Failed to parse response", "raw": response}


def get_severity_color(severity: str) -> str:
    colors = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "blue",
        "info": "gray",
    }
    return colors.get(severity.lower(), "gray")


def format_findings_markdown(findings: List[Dict]) -> str:
    md = "# Security Audit Findings\n\n"
    
    for finding in findings:
        severity = finding.get("severity", "unknown")
        color = get_severity_color(severity)
        
        md += f"## [{severity.upper()}] {finding.get('type', 'Unknown')}\n\n"
        md += f"**Line:** {finding.get('line_number', 'N/A')}\n\n"
        md += f"**Description:** {finding.get('description', '')}\n\n"
        md += f"**Recommendation:** {finding.get('recommendation', '')}\n\n"
        
        if finding.get('cwe_id'):
            md += f"**CWE:** {finding['cwe_id']}\n\n"
        
        if finding.get('cvss_score'):
            md += f"**CVSS:** {finding['cvss_score']}\n\n"
        
        md += "---\n\n"
    
    return md