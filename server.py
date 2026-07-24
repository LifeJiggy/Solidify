import asyncio
import uuid
import os
import re
import json
import logging
import time
import html
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

import aiohttp
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

load_dotenv()

DEFAULT_MODEL = os.getenv("SOLIDIFY_MODEL", "minimaxai/minimax-m2.5")
DEFAULT_PROVIDER = os.getenv("SOLIDIFY_PROVIDER", "nvidia")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "YourApiKeyToken")

MAX_CODE_SIZE = 100_000
MAX_CONCURRENT_TASKS = 20
TASK_TTL = timedelta(hours=1)
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

audit_tasks: Dict[str, Dict[str, Any]] = {}
rate_limits: Dict[str, list] = defaultdict(list)
active_task_count = 0
task_cleanup_running = False
cancelled_tasks = set()
paused_tasks = set()

CHAINS = {
    "ethereum": {"id": "ethereum", "name": "Ethereum", "chain_id": 1, "explorer": "etherscan.io", "api": "api.etherscan.io"},
    "bsc": {"id": "bsc", "name": "BNB Chain", "chain_id": 56, "explorer": "bscscan.com", "api": "api.bscscan.com"},
    "polygon": {"id": "polygon", "name": "Polygon", "chain_id": 137, "explorer": "polygonscan.com", "api": "api.polygonscan.com"},
    "arbitrum": {"id": "arbitrum", "name": "Arbitrum", "chain_id": 42161, "explorer": "arbiscan.io", "api": "api.arbiscan.io"},
    "optimism": {"id": "optimism", "name": "Optimism", "chain_id": 10, "explorer": "optimistic.etherscan.io", "api": "api-optimistic.etherscan.io"},
}
VALID_CHAIN_IDS = set(CHAINS.keys())


def sanitize_code(code: str) -> str:
    code = code.replace("\x00", "")
    code = "".join(c for c in code if c >= " " or c in "\n\r\t")
    return code[:MAX_CODE_SIZE]


def sanitize_error(msg: str) -> str:
    sanitized = html.escape(str(msg))
    secrets = [NVIDIA_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, ETHERSCAN_API_KEY]
    for secret in secrets:
        if secret and len(secret) > 8:
            sanitized = sanitized.replace(secret, secret[:4] + "****" + secret[-4:])
    if len(sanitized) > 500:
        sanitized = sanitized[:500] + "..."
    return sanitized


def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    rate_limits[client_ip] = [t for t in rate_limits[client_ip] if t > window_start]
    if len(rate_limits[client_ip]) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    rate_limits[client_ip].append(now)


async def cleanup_old_tasks():
    global task_cleanup_running
    if task_cleanup_running:
        return
    task_cleanup_running = True
    try:
        while True:
            now = datetime.now()
            expired = [tid for tid, task in audit_tasks.items()
                       if task.get("created_at") and now - task["created_at"] > TASK_TTL]
            for tid in expired:
                del audit_tasks[tid]
            if expired:
                logger.info(f"Cleaned up {len(expired)} expired tasks")
            await asyncio.sleep(300)
    finally:
        task_cleanup_running = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(cleanup_old_tasks())
    logger.info("Solidify API server started")
    yield
    cleanup_task.cancel()
    logger.info("Solidify API server shutting down")


app = FastAPI(title="Solidify API", version="1.0.0", lifespan=lifespan)

cors_origins_raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173")
cors_origins = cors_origins_raw.split(",") if cors_origins_raw != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    max_age=600,
)


class AuditRequest(BaseModel):
    code: Optional[str] = None
    address: Optional[str] = None
    chain: str = "ethereum"
    provider: Optional[str] = None
    model: Optional[str] = None
    command: str = "audit"

    @field_validator("chain")
    @classmethod
    def validate_chain(cls, v):
        if v and v not in VALID_CHAIN_IDS:
            raise ValueError(f"Unsupported chain: {v}. Supported: {', '.join(sorted(VALID_CHAIN_IDS))}")
        return v

    @field_validator("code")
    @classmethod
    def validate_code(cls, v):
        if v and len(v) > MAX_CODE_SIZE:
            raise ValueError(f"Code exceeds {MAX_CODE_SIZE} byte limit")
        return v

    @field_validator("address")
    @classmethod
    def validate_address(cls, v):
        if v and not re.match(r"^0x[a-fA-F0-9]{40}$", v):
            raise ValueError("Invalid contract address format")
        return v


class ChatRequest(BaseModel):
    message: str
    provider: Optional[str] = None
    model: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = []

    @field_validator("message")
    @classmethod
    def validate_message(cls, v):
        if v and len(v) > 5000:
            raise ValueError("Message too long (max 5000 chars)")
        return v


async def fetch_contract_source(address: str, chain: str) -> Optional[str]:
    chain_config = CHAINS.get(chain, CHAINS["ethereum"])
    api_url = f"https://{chain_config['api']}/api"
    params = {"module": "contract", "action": "getsourcecode", "address": address, "apikey": ETHERSCAN_API_KEY}
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(api_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "1" and data.get("result"):
                        source = data["result"][0].get("SourceCode", "")
                        if source:
                            return source
    except asyncio.TimeoutError:
        logger.warning(f"Etherscan timeout for {address}")
    except Exception as e:
        logger.error(f"Etherscan error for {address}: {sanitize_error(e)}")
    return None


VULNERABILITY_PATTERNS = [
    {"id": "REENTRANCY", "name": "Reentrancy Vulnerability", "severity": "CRITICAL", "cvss": 9.1,
     "check": lambda c: (".call(" in c or ".call{" in c or ".send(" in c) and ("value" in c or ".send(" in c) and "ReentrancyGuard" not in c and "checks-effects" not in c.lower() and "nonReentrant" not in c,
     "desc": "External call without reentrancy guard", "fix": "Use ReentrancyGuard modifier or checks-effects-interactions pattern"},
    {"id": "ACCESS_CONTROL", "name": "Missing Access Control", "severity": "CRITICAL", "cvss": 9.0,
     "check": lambda c: ("withdraw" in c or "transfer" in c or "mint" in c or "burn" in c) and "only" not in c.lower() and "require(msg.sender" not in c and "modifier" not in c.lower(),
     "desc": "Critical function without access control", "fix": "Add require(msg.sender == owner) or use OpenZeppelin Ownable"},
    {"id": "INTEGER_OVERFLOW", "name": "Integer Overflow/Underflow", "severity": "HIGH", "cvss": 7.8,
     "check": lambda c: ("+" in c or "-" in c or "*" in c) and "unchecked" not in c.lower() and ("^0.7" in c or "^0.6" in c or "^0.5" in c) and "SafeMath" not in c and "using SafeMath" not in c.lower(),
     "desc": "Arithmetic without SafeMath", "fix": "Use OpenZeppelin SafeMath or solc ^0.8.0"},
    {"id": "TX_ORIGIN", "name": "tx.origin Vulnerability", "severity": "MEDIUM", "cvss": 5.3,
     "check": lambda c: "tx.origin" in c, "desc": "Using tx.origin for authorization", "fix": "Use msg.sender instead of tx.origin"},
    {"id": "UNCHECKED_CALL", "name": "Unchecked External Call", "severity": "HIGH", "cvss": 7.5,
     "check": lambda c: (".call(" in c or ".call{" in c) and "require(" not in c and "if not" not in c.lower() and "if(" not in c and "return" not in c.lower().split("#")[0].split("//")[0],
     "desc": "External call return value not checked", "fix": "Check return value or use SafeERC20"},
    {"id": "TIMESTAMP_DEP", "name": "Timestamp Dependence", "severity": "MEDIUM", "cvss": 4.8,
     "check": lambda c: ("now" in c or "block.timestamp" in c) and ("lottery" in c or "draw" in c or "random" in c or "winner" in c),
     "desc": "Using timestamp for critical logic", "fix": "Use block number or Chainlink oracle"},
    {"id": "CONSTANT_PRAGMA", "name": "Floating Pragma", "severity": "INFO", "cvss": 0.5,
     "check": lambda c: bool(re.search(r"pragma\s+solidity\s+\^", c)),
     "desc": "Floating pragma version (informational)", "fix": "Lock pragma version e.g. 0.8.19"},
    {"id": "MISSING_ZERO_CHECK", "name": "Missing Zero Address Check", "severity": "MEDIUM", "cvss": 5.5,
     "check": lambda c: "address(" in c and ("constructor" in c.split("\n")[0] if c.split("\n") else False) and "require" not in c.split("{")[0] if "{" in c else False,
     "desc": "No zero address validation in constructor args", "fix": "Add require(addr != address(0))"},
    {"id": "GAS_LIMIT_LOOP", "name": "Unbounded Loop", "severity": "MEDIUM", "cvss": 4.8,
     "check": lambda c: bool(re.search(r"for\s*\(.*\.\s*length", c)) and "gasleft()" not in c.lower(),
     "desc": "Unbounded loop could hit gas limit", "fix": "Check gasleft() or limit iterations"},
]


def parse_solidity(code: str) -> Dict[str, Any]:
    vulns = []
    lines = code.split("\n")
    code_lower = code.lower()

    for vuln in VULNERABILITY_PATTERNS:
        try:
            if vuln["id"] == "ACCESS_CONTROL":
                if "require(msg.sender" in code_lower or "onlyowner" in code_lower or "onlyRole(" in code_lower or "modifier " in code_lower and "auth" in code_lower:
                    continue
            if vuln["id"] == "CONSTANT_PRAGMA":
                if re.search(r"pragma\s+solidity\s+\^0\.(?:8|[9-9]|\d{2})", code_lower) and not any(v["vuln_id"] in ("REENTRANCY", "ACCESS_CONTROL", "INTEGER_OVERFLOW") for v in vulns):
                    continue
            matches = [f"Line {i}" for i, line in enumerate(lines, 1) if vuln["check"](line)]
            if matches:
                location = ", ".join(matches[:3])
                if len(matches) > 3:
                    location += f" (+{len(matches) - 3} more)"
                vulns.append({"type": vuln["name"], "severity": vuln["severity"], "location": location,
                               "description": vuln["desc"], "recommendation": vuln["fix"], "cvss": vuln["cvss"], "vuln_id": vuln["id"]})
        except Exception:
            continue

    if re.search(r"selfdestruct\(|suicide\(", code):
        vulns.append({"type": "Deprecated Selfdestruct", "severity": "CRITICAL", "location": "selfdestruct/suicide",
                       "description": "Using deprecated selfdestruct may break contract upgradeability",
                       "recommendation": "Use custom withdraw/destroy pattern", "cvss": 9.0, "vuln_id": "SELFDESTRUCT"})
    if re.search(r"\.delegatecall\(", code):
        vulns.append({"type": "Unsafe Delegatecall", "severity": "HIGH", "location": "delegatecall",
                       "description": "Delegatecall executes external logic in caller context",
                       "recommendation": "Audit delegatecall target carefully; avoid if possible", "cvss": 8.0, "vuln_id": "DELEGATECALL"})
    if "block.blockhash" in code and "random" in code_lower:
        vulns.append({"type": "Weak Randomness", "severity": "HIGH", "location": "block.blockhash",
                       "description": "Block hash is predictable for miners", "recommendation": "Use Chainlink VRF",
                       "cvss": 8.5, "vuln_id": "WEAK_RANDOM"})

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x["severity"], 4))

    score = max(0, round(10.0 - sum(
        3.0 if v["severity"] == "CRITICAL" else 2.0 if v["severity"] == "HIGH" else 1.0 if v["severity"] == "MEDIUM" else 0.5
        for v in vulns if v["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ), 1))

    critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulns if v["severity"] == "HIGH")
    summary = f"Found {len(vulns)} vulnerabilities. "
    if critical:
        summary += f"{critical} CRITICAL, "
    if high:
        summary += f"{high} HIGH, "
    summary = summary.rstrip(", ") + " require attention." if (critical or high) else "Review each item below."

    return {"score": score, "vulnerabilities": vulns, "summary": summary,
            "stats": {"critical": critical, "high": high,
                       "medium": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
                       "low": sum(1 for v in vulns if v["severity"] == "LOW")}}


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method == "POST":
        try:
            check_rate_limit(request)
        except HTTPException:
            return PlainTextResponse("Rate limit exceeded", status_code=429)
    return await call_next(request)


@app.get("/api/chains")
async def get_chains():
    return list(CHAINS.values())


@app.post("/api/chat")
async def chat(request: ChatRequest):
    start = time.time()
    try:
        from providers.provider_factory import create_provider

        provider_name = request.provider or DEFAULT_PROVIDER
        model_name = request.model or DEFAULT_MODEL

        history_text = "".join(f"{m.get('role', 'user')}: {m.get('content', '')}\n" for m in (request.history or [])[-5:])
        prompt = f"""You are Solidify, a smart contract security expert. Answer concisely and technically.

{history_text}
user: {request.message}

expert:"""

        provider = create_provider(provider_name, model_name)
        if not provider:
            logger.warning(f"Chat: provider {provider_name} unavailable")
            return {"message": "AI provider not available. Check API key configuration.", "role": "assistant"}

        response = await provider.generate(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        logger.info(f"Chat OK ({time.time() - start:.1f}s)")
        return {"message": content, "role": "assistant"}

    except Exception as e:
        logger.error(f"Chat error: {sanitize_error(e)}")
        return {"message": "Sorry, I encountered an error.", "error": sanitize_error(e)}


@app.post("/api/audit/start")
async def start_audit(request: AuditRequest, req: Request):
    global active_task_count

    if active_task_count >= MAX_CONCURRENT_TASKS:
        raise HTTPException(status_code=503, detail="Server busy. Try again later.")

    task_id = str(uuid.uuid4())[:8]

    code = request.code
    if request.address:
        code = await fetch_contract_source(request.address, request.chain)
        if not code:
            raise HTTPException(status_code=404, detail="Contract not found or not verified on explorer")

    if not code:
        raise HTTPException(status_code=400, detail="Code or address required")

    code = sanitize_code(code)

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
        "created_at": datetime.now(),
    }

    active_task_count += 1
    asyncio.create_task(_run_audit(task_id))
    logger.info(f"Task {task_id} started (active: {active_task_count})")
    return {"task_id": task_id, "status": "started"}


async def _run_audit(task_id: str):
    global active_task_count
    task = audit_tasks[task_id]
    code = task["code"]

    if task_id in cancelled_tasks:
        return

    try:
        _push_event(task, "queued", 5)
        await asyncio.sleep(0.2)

        from providers.provider_factory import create_provider

        _push_event(task, "connecting", 10)
        await asyncio.sleep(0.1)

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
            try:
                async for chunk in provider_instance.generate_stream(prompt):
                    if task_id in cancelled_tasks:
                        logger.info(f"Task {task_id}: cancelled during stream")
                        return
                    while task_id in paused_tasks:
                        await asyncio.sleep(0.5)
                        if task_id in cancelled_tasks:
                            return
                    chunk_str = chunk if isinstance(chunk, str) else chunk.decode()
                    full_response += chunk_str
                    _push_chunk(task, chunk_str)
            except asyncio.TimeoutError:
                logger.warning(f"Task {task_id}: AI streaming timed out, falling back to scanner")
            except Exception as e:
                logger.warning(f"Task {task_id}: AI error ({sanitize_error(e)}), falling back to scanner")

            try:
                start_idx = full_response.find("{")
                end_idx = full_response.rfind("}") + 1
                if start_idx >= 0 and end_idx > start_idx:
                    result = json.loads(full_response[start_idx:end_idx])
                    result = _validate_report(result)
                else:
                    result = parse_solidity(code)
            except (json.JSONDecodeError, ValueError):
                result = parse_solidity(code)
        else:
            _push_event(task, "scanning", 50)
            await asyncio.sleep(0.5)
            result = parse_solidity(code)

        _complete_task(task, result)
        logger.info(f"Task {task_id} completed: score={result.get('score')}, vulns={len(result.get('vulnerabilities', []))}")

    except Exception as e:
        logger.error(f"Task {task_id} failed: {sanitize_error(e)}")
        _complete_task(task, parse_solidity(code))
    finally:
        active_task_count = max(0, active_task_count - 1)


def _validate_report(result: dict) -> dict:
    if not isinstance(result.get("score"), (int, float)):
        result["score"] = 5
    if not isinstance(result.get("vulnerabilities"), list):
        result["vulnerabilities"] = []
    for v in result["vulnerabilities"]:
        if not isinstance(v.get("type"), str):
            v["type"] = "Unknown"
        if v.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            v["severity"] = "INFO"
        if not isinstance(v.get("description"), str):
            v["description"] = ""
        if not isinstance(v.get("recommendation"), str):
            v["recommendation"] = ""
    return result


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
                if event.get("status") in ("completed", "cancelled", "failed"):
                    return
            if task["status"] == "failed":
                yield f"data: {json.dumps({'status': 'failed', 'error': 'Audit processing failed'})}\n\n"
                return
            if task_id in cancelled_tasks:
                yield f"data: {json.dumps({'status': 'cancelled'})}\n\n"
                return
            await asyncio.sleep(0.2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/audit/stop/{task_id}")
async def stop_audit(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    cancelled_tasks.add(task_id)
    paused_tasks.discard(task_id)
    audit_tasks[task_id]["status"] = "cancelled"
    audit_tasks[task_id]["events"].append({"status": "cancelled", "progress": 0})
    logger.info(f"Task {task_id} cancelled by user")
    return {"task_id": task_id, "status": "cancelled"}


@app.post("/api/audit/pause/{task_id}")
async def pause_audit(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    if audit_tasks[task_id]["status"] in ("completed", "cancelled", "failed"):
        raise HTTPException(status_code=400, detail="Task already finished")
    paused_tasks.add(task_id)
    audit_tasks[task_id]["status"] = "paused"
    audit_tasks[task_id]["events"].append({"status": "paused", "progress": audit_tasks[task_id].get("progress", 0)})
    logger.info(f"Task {task_id} paused by user")
    return {"task_id": task_id, "status": "paused"}


@app.post("/api/audit/resume/{task_id}")
async def resume_audit(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    if audit_tasks[task_id]["status"] != "paused":
        raise HTTPException(status_code=400, detail="Task is not paused")
    paused_tasks.discard(task_id)
    audit_tasks[task_id]["status"] = "queued"
    audit_tasks[task_id]["events"].append({"status": "resumed", "progress": audit_tasks[task_id].get("progress", 0)})
    logger.info(f"Task {task_id} resumed by user")
    return {"task_id": task_id, "status": "resumed"}


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
    lines = ["# Solidify Security Audit Report\n",
             f"## Summary\n- **Security Score**: {result.get('score', 'N/A')}/10\n- **Vulnerabilities Found**: {len(result.get('vulnerabilities', []))}\n",
             f"{result.get('summary', '')}\n---\n"]
    for v in result.get("vulnerabilities", []):
        lines.append(f"\n### [{v.get('severity', 'INFO')}] {v.get('type', 'Unknown')}\n- **Location**: `{v.get('location', 'N/A')}`\n- **CVSS**: {v.get('cvss', 'N/A')}\n- **Description**: {v.get('description', '')}\n")
        if v.get("recommendation"):
            lines.append(f"- **Recommendation**: {v.get('recommendation')}\n")
        if v.get("patch"):
            lines.append(f"**Secure Patch:**\n```solidity\n{v.get('patch')}\n```\n")
    return "".join(lines)


def generate_poc_exploit(vuln: dict, target: str) -> str:
    t = vuln.get("type", "").lower()
    if "reentrancy" in t:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ReentrancyAttacker {
    address public victim;
    constructor(address _victim) { victim = _victim; }
    function attack() external payable {
        (bool ok,) = victim.call{value: msg.value}("withdraw");
        require(ok, "call failed");
    }
    receive() external payable {
        if (victim.balance >= 1 ether) {
            (bool ok,) = victim.call{value: 0}("withdraw");
        }
    }
}"""
    if "access control" in t:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract AccessControlBypass {
    function exploit(address target) external {
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "Access bypassed if no revert");
    }
}"""
    if "overflow" in t:
        return "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract OverflowExploit {\n    function exploit() external pure returns (uint256) {\n        unchecked { return type(uint256).max + 1; }\n    }\n}"
    if "tx.origin" in t:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract TxOriginExploit {
    address public attacker;
    constructor(address _attacker) { attacker = _attacker; }
    function exploit(address target) external {
        (bool ok,) = target.call(abi.encodeWithSignature("withdrawTo(address)", attacker));
    }
}"""
    return f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract GenericExploit {{ string public vulnType = \"{vuln.get('type', 'Unknown')}\"; }}"


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
    lines = [f"Solidify Security Audit Report\n{'='*40}\nScore: {result.get('score', 'N/A')}/10\nVulnerabilities: {len(result.get('vulnerabilities', []))}\n\nSummary:\n{result.get('summary', '')}\n"]
    for v in result.get("vulnerabilities", []):
        lines.append(f"\n[{v.get('severity', 'INFO')}] {v.get('type', 'Unknown')}\n  Location: {v.get('location', 'N/A')}\n  CVSS: {v.get('cvss', 'N/A')}\n  Description: {v.get('description', '')}\n  Fix: {v.get('recommendation', 'N/A')}")
    return PlainTextResponse(content="".join(lines), media_type="text/plain; charset=utf-8",
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
    pocs = [{"vulnerability": v.get("type"), "severity": v.get("severity"),
              "exploit_code": generate_poc_exploit(v, target),
              "test_case": f"// Foundry test for {v.get('type')}\n// pragma solidity ^0.8.0;\n// import 'forge-std/Test.sol';"}
            for v in result.get("vulnerabilities", []) if v.get("severity") in ("CRITICAL", "HIGH")]
    return {"pocs": pocs}


@app.post("/api/detect/gas")
async def detect_gas(code: str = Body(..., embed=True)):
    if not code or len(code) > MAX_CODE_SIZE:
        raise HTTPException(status_code=400, detail="Invalid code")
    issues = []
    lines = code.split("\n")
    storage_reads = [i + 1 for i, line in enumerate(lines) if ".balance" in line and "storage" not in line]
    if len(storage_reads) > 1:
        issues.append({"type": "Multiple Storage Reads", "location": f"Lines {storage_reads[:3]}",
                        "issue": f"Reading storage {len(storage_reads)} times",
                        "recommendation": "Cache in local variable", "savings": f"~{2100 * (len(storage_reads) - 1)} gas"})
    for i, line in enumerate(lines):
        if "for" in line and "length" in line and "i++" in line:
            issues.append({"type": "Unbounded Loop", "location": f"Line {i + 1}",
                            "issue": "Dynamic loop without gas check",
                            "recommendation": "Check gasleft() inside loop", "savings": "Prevents OOG revert"})
    if code.count(".balance") > 2:
        issues.append({"type": "Repeated SLOAD", "location": ".balance access",
                        "issue": "Multiple storage reads for same variable",
                        "recommendation": "Use local variable", "savings": "~2100 gas each"})
    return {"optimizations": issues}


@app.post("/api/detect/frontrun")
async def detect_frontrun(code: str = Body(..., embed=True)):
    if not code or len(code) > MAX_CODE_SIZE:
        raise HTTPException(status_code=400, detail="Invalid code")
    issues = []
    cl = code.lower()
    if ("swap" in cl or "exchange" in cl) and "minAmount" not in cl and "slippage" not in cl:
        issues.append({"type": "No Slippage Protection", "location": "swap function",
                        "issue": "Swap can be sandwiched for profit",
                        "recommendation": "Add minimum amount out check", "severity": "HIGH"})
    if "uint256(-1)" in code or "type(uint256).max" in code:
        issues.append({"type": "Unlimited Token Approval", "location": "approve",
                        "issue": "Infinite approval allows draining tokens",
                        "recommendation": "Set specific allowance", "severity": "MEDIUM"})
    if not any(kw in cl for kw in ["onlyowner", "onlyowner()", "msg.sender == owner", "msg.sender == address(this)", "auth"]):
        if ("withdraw" in cl or "transfer" in cl) and "constructor" not in cl:
            issues.append({"type": "Missing Access Control", "location": "withdraw/transfer",
                            "issue": "No owner modifier on critical function",
                            "recommendation": "Add onlyOwner modifier", "severity": "MEDIUM"})
    return {"vulnerabilities": issues}


@app.post("/api/detect/oracle")
async def detect_oracle(code: str = Body(..., embed=True)):
    if not code or len(code) > MAX_CODE_SIZE:
        raise HTTPException(status_code=400, detail="Invalid code")
    issues = []
    for pattern, desc in [("block.timestamp", "Block timestamp can be manipulated by miner"),
                           ("block.blockhash", "Block hash is not unpredictable"),
                           ("now", "now() is deprecated and manipulable")]:
        if pattern in code:
            issues.append({"type": "On-Chain Price Oracle", "location": pattern, "issue": desc,
                            "recommendation": "Use Chainlink price feed",
                            "severity": "HIGH" if "price" in desc else "MEDIUM"})
    if "blockhash" in code and "random" in code.lower():
        issues.append({"type": "Predictable Randomness", "location": "blockhash",
                        "issue": "Miner can predict randomness",
                        "recommendation": "Use Chainlink VRF", "severity": "CRITICAL"})
    return {"vulnerabilities": issues}


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Solidify API on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, timeout_keep_alive=30)
