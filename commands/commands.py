"""
Solidify CLI - Working command-line interface for smart contract security auditing

Usage:
    python -m commands.commands scan --file Contract.sol
    python -m commands.commands scan --address 0x... --chain ethereum
    python -m commands.commands audit --file Contract.sol --model nvidia/nvidia-nemotron-nano-9b-v2
"""

import os
import sys
import json
import re
import time
import asyncio
import argparse
import logging
from typing import Dict, List, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

VULNERABILITY_PATTERNS = [
    {"id": "REENTRANCY", "name": "Reentrancy Vulnerability", "severity": "CRITICAL", "cvss": 9.1,
     "check": lambda c: (".call(" in c or ".call{" in c or ".send(" in c) and ("value" in c or ".send(" in c) and "ReentrancyGuard" not in c and "nonReentrant" not in c,
     "desc": "External call without reentrancy guard", "fix": "Use ReentrancyGuard or checks-effects-interactions pattern"},
    {"id": "ACCESS_CONTROL", "name": "Missing Access Control", "severity": "CRITICAL", "cvss": 9.0,
     "check": lambda c: ("withdraw" in c or "transfer" in c or "mint" in c or "burn" in c) and "only" not in c.lower() and "require(msg.sender" not in c,
     "desc": "Critical function without access control", "fix": "Add require(msg.sender == owner) or use Ownable"},
    {"id": "INTEGER_OVERFLOW", "name": "Integer Overflow/Underflow", "severity": "HIGH", "cvss": 7.8,
     "check": lambda c: ("+" in c or "-" in c or "*" in c) and "unchecked" not in c.lower() and ("^0.7" in c or "^0.6" in c or "^0.5" in c) and "SafeMath" not in c,
     "desc": "Arithmetic without SafeMath", "fix": "Use SafeMath or solc ^0.8.0"},
    {"id": "TX_ORIGIN", "name": "tx.origin Vulnerability", "severity": "MEDIUM", "cvss": 5.3,
     "check": lambda c: "tx.origin" in c, "desc": "Using tx.origin for authorization", "fix": "Use msg.sender instead"},
    {"id": "UNCHECKED_CALL", "name": "Unchecked External Call", "severity": "HIGH", "cvss": 7.5,
     "check": lambda c: (".call(" in c or ".call{" in c) and "require(" not in c and "if " not in c,
     "desc": "External call return value not checked", "fix": "Check return value"},
    {"id": "TIMESTAMP_DEP", "name": "Timestamp Dependence", "severity": "MEDIUM", "cvss": 4.8,
     "check": lambda c: ("now" in c or "block.timestamp" in c) and ("lottery" in c or "random" in c or "winner" in c),
     "desc": "Using timestamp for critical logic", "fix": "Use Chainlink VRF"},
    {"id": "CONSTANT_PRAGMA", "name": "Floating Pragma", "severity": "INFO", "cvss": 0.5,
     "check": lambda c: bool(re.search(r"pragma\s+solidity\s+\^", c)),
     "desc": "Floating pragma version", "fix": "Lock pragma version e.g. 0.8.19"},
]


def scan_code(code: str) -> Dict[str, Any]:
    vulns = []
    lines = code.split("\n")
    code_lower = code.lower()

    for vuln in VULNERABILITY_PATTERNS:
        try:
            if vuln["id"] == "ACCESS_CONTROL":
                if "require(msg.sender" in code_lower or "onlyowner" in code_lower or "onlyRole(" in code_lower:
                    continue
            if vuln["id"] == "CONSTANT_PRAGMA":
                if re.search(r"pragma\s+solidity\s+\^0\.8", code_lower):
                    continue
            matches = [f"Line {i}" for i, line in enumerate(lines, 1) if vuln["check"](line)]
            if matches:
                loc = ", ".join(matches[:3])
                if len(matches) > 3:
                    loc += f" (+{len(matches)-3} more)"
                vulns.append({
                    "type": vuln["name"], "severity": vuln["severity"],
                    "location": loc, "description": vuln["desc"],
                    "recommendation": vuln["fix"], "cvss": vuln["cvss"], "vuln_id": vuln["id"]
                })
        except Exception:
            continue

    if re.search(r"selfdestruct\(|suicide\(", code):
        vulns.append({"type": "Deprecated Selfdestruct", "severity": "CRITICAL", "location": "selfdestruct",
                       "description": "Using deprecated selfdestruct", "recommendation": "Use custom destroy pattern",
                       "cvss": 9.0, "vuln_id": "SELFDESTRUCT"})
    if re.search(r"\.delegatecall\(", code):
        vulns.append({"type": "Unsafe Delegatecall", "severity": "HIGH", "location": "delegatecall",
                       "description": "Delegatecall executes external logic in caller context",
                       "recommendation": "Audit delegatecall target carefully", "cvss": 8.0, "vuln_id": "DELEGATECALL"})

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x["severity"], 4))

    score = max(0, round(10.0 - sum(
        3.0 if v["severity"] == "CRITICAL" else 2.0 if v["severity"] == "HIGH" else 1.0 if v["severity"] == "MEDIUM" else 0.5
        for v in vulns
    ), 1))

    critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulns if v["severity"] == "HIGH")
    medium = sum(1 for v in vulns if v["severity"] == "MEDIUM")

    return {
        "score": score,
        "vulnerabilities": vulns,
        "summary": f"Found {len(vulns)} vulnerabilities ({critical} critical, {high} high, {medium} medium)",
        "stats": {"critical": critical, "high": high, "medium": medium, "low": sum(1 for v in vulns if v["severity"] == "LOW")}
    }


async def ai_audit(code: str, model: str = "nvidia/nvidia-nemotron-nano-9b-v2", provider_name: str = "nvidia") -> Optional[Dict]:
    try:
        prompt = f"""Analyze this Solidity contract for security vulnerabilities. Return ONLY valid JSON.

```solidity
{code[:60000]}
```

Return JSON with this exact structure:
{{"score": 0-10, "vulnerabilities": [{{"type": "", "severity": "CRITICAL/HIGH/MEDIUM/LOW", "location": "", "description": "", "recommendation": "", "cvss": 0.0}}], "summary": ""}}

Check for: reentrancy, access control, overflow, unchecked calls, tx.origin, delegatecall, flash loans, oracles."""

        if provider_name == "google":
            from providers.google import GoogleProvider, GoogleConfig
            api_key = os.getenv("GEMINI_API_KEY", "")
            if not api_key:
                logger.warning("No GEMINI_API_KEY found")
                return None
            config = GoogleConfig(api_key=api_key, model=model, max_tokens=8192, temperature=0.3)
            provider = GoogleProvider(config)
        else:
            from providers.nvidia import NvidiaProvider, NvidiaConfig
            api_key = os.getenv("NVIDIA_API_KEY", "")
            if not api_key:
                logger.warning("No NVIDIA_API_KEY found")
                return None
            config = NvidiaConfig(api_key=api_key, model=model, max_tokens=16384, temperature=0.3)
            provider = NvidiaProvider(config)

        result = await provider.generate(prompt)
        await provider.close()

        if not result.content:
            return None

        start = result.content.find("{")
        end = result.content.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(result.content[start:end])
        return None
    except Exception as e:
        logger.error(f"AI audit failed: {e}")
        return None


def fetch_from_explorer(address: str, chain: str = "ethereum") -> Optional[str]:
    try:
        import urllib.request
        import urllib.parse

        chain_apis = {
            "ethereum": "api.etherscan.io",
            "bsc": "api.bscscan.com",
            "polygon": "api.polygonscan.com",
        }
        api_host = chain_apis.get(chain, "api.etherscan.io")
        api_key = os.getenv("ETHERSCAN_API_KEY", "")

        url = f"https://{api_host}/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "Solidify/1.0"})

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "1" and data.get("result"):
                return data["result"][0].get("SourceCode", "")
    except Exception as e:
        logger.error(f"Explorer fetch failed: {e}")
    return None


def print_results(result: Dict, code: str = ""):
    score = result.get("score", 0)
    vulns = result.get("vulnerabilities", [])
    summary = result.get("summary", "")

    if score >= 8:
        score_color = "\033[92m"
    elif score >= 5:
        score_color = "\033[93m"
    else:
        score_color = "\033[91m"

    print()
    print("=" * 70)
    print("  SOLIDIFY - Smart Contract Security Audit Report")
    print("=" * 70)
    print()
    print(f"  Security Score: {score_color}{score}/10\033[0m")
    print(f"  {summary}")
    print()

    if not vulns:
        print("  No vulnerabilities found.")
        print()
        return

    print("-" * 70)
    print(f"  {'#':<4} {'SEVERITY':<12} {'TYPE':<35} {'CVSS':<6}")
    print("-" * 70)

    severity_colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[92m",
        "INFO": "\033[94m",
    }

    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "INFO")
        color = severity_colors.get(sev, "")
        reset = "\033[0m" if color else ""
        vtype = v.get("type", "Unknown")[:35]
        cvss = v.get("cvss", 0)
        print(f"  {i:<4} {color}{sev:<12}{reset} {vtype:<35} {cvss:<6}")

    print("-" * 70)
    print()

    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "INFO")
        color = severity_colors.get(sev, "")
        reset = "\033[0m" if color else ""
        print(f"  [{color}{sev}{reset}] {v.get('type', 'Unknown')}")
        print(f"    Location:       {v.get('location', 'N/A')}")
        print(f"    Description:    {v.get('description', 'N/A')}")
        print(f"    Recommendation: {v.get('recommendation', 'N/A')}")
        print()

    print("=" * 70)


def cmd_scan(args):
    code = ""
    source = ""

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}")
            return 1
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        source = args.file
    elif args.code:
        code = args.code
        source = "command line"
    elif args.address:
        print(f"Fetching source from explorer for {args.address}...")
        code = fetch_from_explorer(args.address, args.chain)
        if not code:
            print(f"Error: Could not fetch source for {args.address}")
            return 1
        source = f"{args.address} ({args.chain})"
    else:
        print("Error: Provide --file, --code, or --address")
        return 1

    print(f"Scanning: {source}")
    print(f"Code size: {len(code)} bytes, {code.count(chr(10))+1} lines")

    result = scan_code(code)
    print_results(result)
    return 0


def cmd_audit(args):
    code = ""
    source = ""

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}")
            return 1
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        source = args.file
    elif args.address:
        print(f"Fetching source from explorer for {args.address}...")
        code = fetch_from_explorer(args.address, args.chain)
        if not code:
            print(f"Error: Could not fetch source for {args.address}")
            return 1
        source = f"{args.address} ({args.chain})"
    else:
        print("Error: Provide --file or --address")
        return 1

    provider_name = args.provider or "nvidia"
    model = args.model
    if not model:
        if provider_name == "google":
            model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        else:
            model = os.getenv("SOLIDIFY_MODEL", "nvidia/nvidia-nemotron-nano-9b-v2")

    print(f"Auditing: {source}")
    print(f"Code size: {len(code)} bytes")
    print(f"Provider: {provider_name} / {model}")
    print()

    print("[1/2] Running pattern scanner...")
    scan_result = scan_code(code)

    print("[2/2] Running AI analysis...")
    ai_result = asyncio.run(ai_audit(code, model, provider_name))

    if ai_result and ai_result.get("vulnerabilities"):
        ai_vulns = ai_result.get("vulnerabilities", [])
        existing_types = {v.get("type", "").lower() for v in scan_result["vulnerabilities"]}
        new_from_ai = [v for v in ai_vulns if v.get("type", "").lower() not in existing_types]

        scan_result["vulnerabilities"].extend(new_from_ai)
        scan_result["vulnerabilities"].sort(
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 4)
        )
        critical = sum(1 for v in scan_result["vulnerabilities"] if v["severity"] == "CRITICAL")
        high = sum(1 for v in scan_result["vulnerabilities"] if v["severity"] == "HIGH")
        scan_result["summary"] = f"Found {len(scan_result['vulnerabilities'])} vulnerabilities ({critical} critical, {high} high)"
        print(f"  AI found {len(new_from_ai)} additional findings")
    else:
        print("  AI analysis unavailable, using pattern scan only")

    print_results(scan_result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(scan_result, f, indent=2)
        print(f"\nReport saved to: {args.output}")

    return 0


def cmd_serve(args):
    import uvicorn
    host = args.host or "0.0.0.0"
    port = args.port or 8000
    print(f"Starting Solidify server on {host}:{port}")
    uvicorn.run("server:app", host=host, port=port, reload=args.reload)


def main():
    parser = argparse.ArgumentParser(description="Solidify - Smart Contract Security Auditor")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Quick security scan")
    scan_p.add_argument("--file", "-f", help="Solidity file path")
    scan_p.add_argument("--code", "-c", help="Solidity code string")
    scan_p.add_argument("--address", "-a", help="Contract address (requires explorer)")
    scan_p.add_argument("--chain", default="ethereum", help="Chain (ethereum/bsc/polygon)")

    audit_p = sub.add_parser("audit", help="Full AI-powered audit")
    audit_p.add_argument("--file", "-f", help="Solidity file path")
    audit_p.add_argument("--address", "-a", help="Contract address")
    audit_p.add_argument("--chain", default="ethereum", help="Chain")
    audit_p.add_argument("--model", "-m", help="AI model to use")
    audit_p.add_argument("--provider", "-p", choices=["nvidia", "google"], default="nvidia", help="AI provider")
    audit_p.add_argument("--output", "-o", help="Save report to file")

    serve_p = sub.add_parser("serve", help="Start API server")
    serve_p.add_argument("--host", default="0.0.0.0")
    serve_p.add_argument("--port", type=int, default=8000)
    serve_p.add_argument("--reload", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "audit":
        return cmd_audit(args)
    elif args.command == "serve":
        return cmd_serve(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
