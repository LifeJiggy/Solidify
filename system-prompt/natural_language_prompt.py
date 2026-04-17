"""
Solidify Natural Language Prompt
Natural language query handling

Author: Peace Stephen (Tech Lead)
Description: Natural language prompt templates
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import re


class QueryIntent(Enum):
    ANALYZE = "analyze"
    AUDIT = "audit"
    FIND_VULNERABILITY = "find_vulnerability"
    EXPLOIT = "exploit"
    FIX = "fix"
    EXPLAIN = "explain"
    SCAN = "scan"
    HUNT = "hunt"
    REPORT = "report"
    COMPARE = "compare"
    METRICS = "metrics"
    UNKNOWN = "unknown"


class VulnerabilityFocus(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FRONT_RUNNING = "front_running"
    CENTRALIZATION = "centralization"
    DENIAL_OF_SERVICE = "denial_of_service"
    VALIDATION = "validation"
    PRIVACY = "privacy"
    UNSPECIFIED = "unspecified"


class SeverityFilter(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ALL = "all"


class OutputFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    TEXT = "text"
    VERBOSE = "verbose"


@dataclass
class QueryContext:
    contract_name: Optional[str] = None
    chain: Optional[str] = None
    solidity_version: Optional[str] = None
    contract_address: Optional[str] = None
    file_path: Optional[str] = None
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedQuery:
    intent: QueryIntent
    vulnerability_focus: VulnerabilityFocus
    severity_filter: SeverityFilter
    output_format: OutputFormat
    include_exploits: bool
    include_fixes: bool
    include_metrics: bool
    max_findings: int
    raw_query: str
    confidence: float


QUERY_TEMPLATES = {
    "analyze": "Analyze this smart contract for security vulnerabilities",
    "find_reentrancy": "Find reentrancy vulnerabilities in this contract",
    "check_access": "Check for access control issues",
    "audit": "Perform a comprehensive security audit",
    "exploit": "Generate an exploit proof-of-concept for this vulnerability",
    "fix": "Provide a fix for this vulnerability",
    "explain": "Explain this vulnerability in detail",
    "scan": "Scan for security vulnerabilities",
    "hunt": "Hunt for specific vulnerability patterns",
    "report": "Generate a security report",
    "compare": "Compare security findings",
    "metrics": "Generate security metrics",
}


KEYWORD_PATTERNS = {
    QueryIntent.ANALYZE: ["analyze", "check", "review", "test"],
    QueryIntent.AUDIT: ["audit", "security audit", "full audit", "comprehensive"],
    QueryIntent.FIND_VULNERABILITY: ["find", "detect", "vulnerability", "vulnerabilities", "bugs", "flaws"],
    QueryIntent.EXPLOIT: ["exploit", "poc", "proof of concept", "attack", "hack"],
    QueryIntent.FIX: ["fix", "repair", "patch", "mitigate", "remedy", "address"],
    QueryIntent.EXPLAIN: ["explain", "describe", "what is", "how does", "tell me about"],
    QueryIntent.SCAN: ["scan", "quick scan", "fast scan"],
    QueryIntent.HUNT: ["hunt", "hunting", "search for"],
    QueryIntent.REPORT: ["report", "generate report", "output"],
    QueryIntent.COMPARE: ["compare", "diff", "vs", "versus"],
    QueryIntent.METRICS: ["metrics", "statistics", "coverage", "score"],
}

VULN_KEYWORDS = {
    VulnerabilityFocus.REENTRANCY: ["reentrancy", "re-entrancy", "recursive", "callback"],
    VulnerabilityFocus.ACCESS_CONTROL: ["access control", "permission", "authorization", "auth", "owner", "admin"],
    VulnerabilityFocus.ARITHMETIC: ["arithmetic", "overflow", "underflow", "integer", "math"],
    VulnerabilityFocus.ORACLE_MANIPULATION: ["oracle", "price", "manipulation", "feed", "chainlink", "uniswap"],
    VulnerabilityFocus.FRONT_RUNNING: ["front running", "front-run", "mempool", "sandwich"],
    VulnerabilityFocus.CENTRALIZATION: ["centralization", "admin", "owner", "single point", "upgrade"],
    VulnerabilityFocus.DENIAL_OF_SERVICE: ["dos", "denial of service", "gas", "out of gas", "block"],
    VulnerabilityFocus.VALIDATION: ["validation", "input", "require", "assert", "check"],
}


@dataclass
class PromptBuilder:
    template: str = ""
    variables: Dict[str, Any] = field(default_factory=dict)
    instructions: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)

    def add_variable(self, key: str, value: Any) -> "PromptBuilder":
        self.variables[key] = value
        return self

    def add_instruction(self, instruction: str) -> "PromptBuilder":
        self.instructions.append(instruction)
        return self

    def add_constraint(self, constraint: str) -> "PromptBuilder":
        self.constraints.append(constraint)
        return self

    def build(self) -> str:
        result = self.template
        for key, value in self.variables.items():
            result = result.replace(f"{{{key}}}", str(value))
        if self.instructions:
            result += "\n## Instructions\n" + "\n".join(f"- {i}" for i in self.instructions)
        if self.constraints:
            result += "\n## Constraints\n" + "\n".join(f"- {c}" for c in self.constraints)
        return result


def get_query_template(query_type: str) -> str:
    return QUERY_TEMPLATES.get(query_type.lower(), "")


def detect_intent(user_input: str) -> QueryIntent:
    user_lower = user_input.lower()
    best_intent = QueryIntent.ANALYZE
    best_score = 0

    for intent, keywords in KEYWORD_PATTERNS.items():
        score = sum(1 for kw in keywords if kw in user_lower)
        if score > best_score:
            best_score = score
            best_intent = intent

    return best_intent


def detect_vulnerability_focus(user_input: str) -> VulnerabilityFocus:
    user_lower = user_input.lower()
    best_focus = VulnerabilityFocus.UNSPECIFIED
    best_score = 0

    for focus, keywords in VULN_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in user_lower)
        if score > best_score:
            best_score = score
            best_focus = focus

    return best_focus


def detect_severity(user_input: str) -> SeverityFilter:
    user_lower = user_input.lower()
    severity_map = {
        SeverityFilter.CRITICAL: ["critical", "crit", "severe"],
        SeverityFilter.HIGH: ["high", "serious", "important"],
        SeverityFilter.MEDIUM: ["medium", "moderate"],
        SeverityFilter.LOW: ["low", "minor"],
        SeverityFilter.ALL: ["all", "every", "everything"]
    }

    for severity, keywords in severity_map.items():
        if any(kw in user_lower for kw in keywords):
            return severity
    return SeverityFilter.ALL


def detect_output_format(user_input: str) -> OutputFormat:
    user_lower = user_input.lower()
    
    if "json" in user_lower:
        return OutputFormat.JSON
    elif "markdown" in user_lower or "md" in user_lower:
        return OutputFormat.MARKDOWN
    elif "verbose" in user_lower:
        return OutputFormat.VERBOSE
    return OutputFormat.TEXT


def parse_options_from_query(user_input: str) -> Dict[str, bool]:
    user_lower = user_input.lower() if isinstance(user_input, str) else str(user_input).lower()
    
    return {
        "include_exploits": "exploit" in user_lower or "poc" in user_lower,
        "include_fixes": "fix" in user_lower or "mitigation" in user_lower,
        "include_metrics": "metrics" in user_lower or "score" in user_lower,
    }


def extract_max_findings(user_input: str) -> int:
    patterns = [
        r"top\s+(\d+)",
        r"max\s+(\d+)",
        r"last\s+(\d+)",
        r"only\s+(\d+)",
        r"first\s+(\d+)"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, user_input.lower())
        if match:
            return int(match.group(1))
    return 50


def parse_natural_query(user_input: str) -> ParsedQuery:
    return ParsedQuery(
        intent=detect_intent(user_input),
        vulnerability_focus=detect_vulnerability_focus(user_input),
        severity_filter=detect_severity(user_input),
        output_format=detect_output_format(user_input),
        include_exploits="exploit" in user_input.lower() or "poc" in user_input.lower(),
        include_fixes="fix" in user_input.lower() or "mitigation" in user_input.lower(),
        include_metrics="metrics" in user_input.lower() or "score" in user_input.lower(),
        max_findings=extract_max_findings(user_input),
        raw_query=user_input,
        confidence=0.8
    )


def build_analysis_query(contract_code: str, options: Optional[Dict] = None) -> str:
    options = options or {}
    
    query = f"""Analyze the following Solidity smart contract for security vulnerabilities:

```{contract_code}
```

"""
    
    if options.get("include_exploits"):
        query += "Include exploit proof-of-concepts for critical findings.\n"
    
    if options.get("severity_filter"):
        query += f"Focus on {options['severity_filter']} severity issues.\n"
    
    if options.get("specific_vulns"):
        query += f"Check specifically for: {', '.join(options['specific_vulns'])}\n"
    
    if options.get("chain"):
        query += f"Chain: {options['chain']}\n"
    
    if options.get("solidity_version"):
        query += f"Solidity Version: {options['solidity_version']}\n"
    
    return query


def build_exploit_query(vulnerability: Dict, options: Optional[Dict] = None) -> str:
    options = options or {}
    
    query = f"""Generate a proof-of-concept exploit for this vulnerability:

Type: {vulnerability.get('type', 'unknown')}
Severity: {vulnerability.get('severity', 'unknown')}
Description: {vulnerability.get('description', '')}

"""
    
    if vulnerability.get("line_number"):
        query += f"Location: Line {vulnerability.get('line_number')}\n"
    
    query += """
Provide:
1. Attack contract in Solidity
2. Step-by-step execution
3. Required preconditions
4. Potential profit/loss estimation
5. Mitigation strategies
"""
    
    return query


def build_fix_query(
    vulnerability: Dict,
    contract_code: str,
    options: Optional[Dict] = None
) -> str:
    options = options or {}
    
    query = f"""Provide a secure fix for this vulnerability:

Vulnerability: {vulnerability.get('type', '')}
Description: {vulnerability.get('description', '')}

Current code:
```{contract_code}
```

"""
    
    query += "Provide:\n1. Fixed code with explanation\n2. Alternative approaches\n"
    
    if options.get("include_tests"):
        query += "3. Test cases\n"
    
    return query


def build_audit_query(contract_code: str, context: Optional[QueryContext] = None) -> str:
    context = context or QueryContext()
    
    query = """Perform a comprehensive security audit including:

"""
    
    if context.contract_name:
        query += f"- Contract Name: {context.contract_name}\n"
    if context.chain:
        query += f"- Chain: {context.chain}\n"
    if context.solidity_version:
        query += f"- Solidity Version: {context.solidity_version}\n"
    
    query += f"""
{contract_code}

Requirements:
1. Identify all vulnerabilities by severity (Critical, High, Medium, Low, Info)
2. For each vulnerability provide:
   - Description and root cause
   - Line numbers
   - CWE reference
   - CVSS score estimation
   - Exploit PoC (for Critical/High)
   - Recommended fix with code
3. Generate summary with risk score
"""
    
    return query


def build_hunt_query(
    vulnerability_type: str,
    contract_code: str,
    options: Optional[Dict] = None
) -> str:
    options = options or {}
    
    query = f"""Hunt for {vulnerability_type} vulnerabilities in this contract:

```{contract_code}
```

"""
    
    if options.get("include_false_positives"):
        query += "Also identify potential false positives and explain why they may not be exploitable.\n"
    
    if options.get("deep_analysis"):
        query += "Perform deep analysis including control flow and data flow.\n"
    
    return query


def build_scan_query(contract_code: str, options: Optional[Dict] = None) -> str:
    options = options or {}
    
    query = f"""Quickly scan for security vulnerabilities:

```{contract_code}
```

"""
    
    severity = options.get("severity_filter", "all")
    vuln_types = options.get("vuln_types", [])
    
    if severity != "all":
        query += f"Severity filter: {severity}\n"
    
    if vuln_types:
        query += f"Focus on: {', '.join(vuln_types)}\n"
    
    return query


def build_report_query(
    findings: List[Dict[str, Any]],
    options: Optional[Dict] = None
) -> str:
    options = options or {}
    format_type = options.get("format", "markdown")
    
    if format_type == "json":
        import json
        return json.dumps(findings, indent=2)
    
    query = "# Security Audit Report\n\n"
    
    for i, finding in enumerate(findings, 1):
        query += f"## {i}. {finding.get('type', 'Unknown')} ({finding.get('severity', 'unknown').upper()})\n\n"
        query += f"**Location**: Line {finding.get('line_number', 'N/A')}\n"
        query += f"**Description**: {finding.get('description', '')}\n\n"
        query += f"**Recommendation**: {finding.get('recommendation', '')}\n\n"
    
    return query


def build_explain_query(vulnerability_type: str, depth: str = "basic") -> str:
    depth_instructions = {
        "basic": "Provide a brief explanation suitable for developers.",
        "intermediate": "Include technical details and common patterns.",
        "advanced": "Provide in-depth analysis including edge cases and real-world examples."
    }
    
    query = f"""Explain {vulnerability_type} vulnerabilities in detail:

{depth_instructions.get(depth, depth_instructions['basic'])}

Include:
1. How the vulnerability works
2. Real-world examples of exploits
3. Detection methods
4. Mitigation strategies
5. Code examples (vulnerable and fixed)
"""
    
    return query


def build_compare_query(code_a: str, code_b: str) -> str:
    return f"""Compare the security of these two code snippets:

--- Code A ---
{code_a}

--- Code B ---
{code_b}

Provide:
1. Security differences
2. Vulnerability comparison
3. Which is more secure and why
"""


def build_metrics_query(findings: List[Dict[str, Any]]) -> str:
    import json
    return f"""Generate security metrics from these findings:

{json.dumps(findings, indent=2)}

Provide:
1. Risk score
2. Vulnerability distribution by severity
3. Vulnerability distribution by type
4. Code coverage metrics
5. Recommendations for improving security posture
"""


def build_query(
    user_input: str,
    contract_code: str,
    context: Optional[QueryContext] = None,
    options: Optional[Dict] = None
) -> str:
    parsed = parse_natural_query(user_input)
    options = options or {}
    context = context or QueryContext()

    if parsed.intent == QueryIntent.AUDIT:
        return build_audit_query(contract_code, context)
    elif parsed.intent == QueryIntent.EXPLOIT:
        vuln = options.get("vulnerability", {})
        return build_exploit_query(vuln, options)
    elif parsed.intent == QueryIntent.FIX:
        vuln = options.get("vulnerability", {})
        return build_fix_query(vuln, contract_code, options)
    elif parsed.intent == QueryIntent.HUNT:
        return build_hunt_query(
            parsed.vulnerability_focus.value,
            contract_code,
            options
        )
    elif parsed.intent == QueryIntent.SCAN:
        return build_scan_query(contract_code, options)
    elif parsed.intent == QueryIntent.REPORT:
        findings = options.get("findings", [])
        return build_report_query(findings, options)
    elif parsed.intent == QueryIntent.EXPLAIN:
        return build_explain_query(
            parsed.vulnerability_focus.value,
            options.get("depth", "basic")
        )
    elif parsed.intent == QueryIntent.COMPARE:
        code_b = options.get("code_b", "")
        return build_compare_query(contract_code, code_b)
    elif parsed.intent == QueryIntent.METRICS:
        findings = options.get("findings", [])
        return build_metrics_query(findings)
    else:
        return build_analysis_query(contract_code, options)


def optimize_for_llm(query: str, model: str = "gemini") -> str:
    optimizations = {
        "gemini": [
            "Add clear section headers",
            "Use code blocks for contract code",
            "Specify output format explicitly"
        ],
        "gpt": [
            "Use XML tags for structure",
            "Include examples of expected output"
        ]
    }
    
    model_lower = model.lower()
    for opt in optimizations.get(model_lower, []):
        query = f"{query}\n\n[{opt}]" if query else query
    
    return query


def create_batch_query(
    queries: List[str],
    contract_codes: List[str]
) -> List[str]:
    results = []
    for user_input, code in zip(queries, contract_codes):
        results.append(build_query(user_input, code))
    return results


def validate_query_requirements(query: str) -> Dict[str, Any]:
    checks = {
        "has_contract_code": "```" in query or "```solidity" in query,
        "has_severity": "critical" in query.lower() or "high" in query.lower(),
        "has_intent": any(k in query.lower() for k in ["analyze", "audit", "find"]),
    }
    
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "missing": [k for k, v in checks.items() if not v]
    }


def enhance_query_with_context(
    query: str,
    context: QueryContext
) -> str:
    enhancements = []
    
    if context.contract_name:
        enhancements.append(f"Analyzing contract: {context.contract_name}")
    if context.chain:
        enhancements.append(f"Chain: {context.chain}")
    if context.solidity_version:
        enhancements.append(f"Solidity version: {context.solidity_version}")
    
    if enhancements:
        query += "\n\n**Context:** " + "; ".join(enhancements)
    
    return query


def get_suggested_followups(intent: QueryIntent) -> List[str]:
    suggestions = {
        QueryIntent.ANALYZE: [
            "Show me the exploit for critical findings",
            "Generate a full report",
            "What is the overall risk score?"
        ],
        QueryIntent.EXPLOIT: [
            "Explain how this exploit works",
            "Provide mitigation strategies",
            "Show me the fixed code"
        ],
        QueryIntent.FIX: [
            "Are there alternative fixes?",
            "Generate tests for the fix",
            "What's the gas impact?"
        ],
        QueryIntent.AUDIT: [
            "Generate executive summary",
            "Show me all critical findings",
            "Compare with previous audit"
        ]
    }
    
    return suggestions.get(intent, ["Explain more", "Show details"])