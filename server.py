#!/usr/bin/env python3
"""
Solidify API Server
FastAPI backend with AI streaming and Etherscan integration
"""

import asyncio
import uuid
import os
import json
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import aiohttp

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Solidify API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
audit_tasks: Dict[str, Dict[str, Any]] = {}

# Chain configurations
CHAINS = {
    "ethereum": {
        "id": "ethereum",
        "name": "Ethereum",
        "chain_id": 1,
        "explorer": "etherscan.io",
        "api": "api.etherscan.io",
    },
    "bsc": {
        "id": "bsc",
        "name": "BNB Chain",
        "chain_id": 56,
        "explorer": "bscscan.com",
        "api": "api.bscscan.com",
    },
    "polygon": {
        "id": "polygon",
        "name": "Polygon",
        "chain_id": 137,
        "explorer": "polygonscan.com",
        "api": "api.polygonscan.com",
    },
    "arbitrum": {
        "id": "arbitrum",
        "name": "Arbitrum",
        "chain_id": 42161,
        "explorer": "arbiscan.io",
        "api": "api.arbiscan.io",
    },
    "optimism": {
        "id": "optimism",
        "name": "Optimism",
        "chain_id": 10,
        "explorer": "optimistic.etherscan.io",
        "api": "api-optimistic.etherscan.io",
    },
}

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "YourApiKeyToken")


class AuditRequest(BaseModel):
    code: Optional[str] = None
    address: Optional[str] = None
    chain: str = "ethereum"
    provider: str = "nvidia"
    model: str = "minimaxai/minimax-m2.5"
    command: str = "audit"


# ============================================================================
# ETHERSCAN API
# ============================================================================


async def fetch_contract_source(address: str, chain: str) -> Optional[str]:
    """Fetch verified contract source from Etherscan"""
    chain_config = CHAINS.get(chain, CHAINS["ethereum"])
    api_url = f"https://{chain_config['api']}/api"

    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY,
    }

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


# ============================================================================
# AI PROVIDER INTEGRATION
# ============================================================================


async def generate_audit_stream(
    task_id: str, code: str, chain: str, provider: str, model: str
):
    """Run AI-powered audit with streaming"""
    try:
        from providers.provider_factory import create_provider

        # Update status
        audit_tasks[task_id]["status"] = "connecting"
        audit_tasks[task_id]["progress"] = 10
        yield f"data: {json.dumps({'status': 'connecting', 'progress': 10})}\n\n"

        # Create provider
        providerInstance = create_provider(
            provider or "nvidia", model=model or "minimaxai/minimax-m2.5"
        )
        if not providerInstance:
            raise Exception("Failed to create AI provider")

        audit_tasks[task_id]["status"] = "analyzing"
        audit_tasks[task_id]["progress"] = 30
        yield f"data: {json.dumps({'status': 'analyzing', 'progress': 30})}\n\n"

        # Build audit prompt
        prompt = f"""You are a smart contract security auditor. Analyze this {chain} Solidity code for vulnerabilities.

Provide a JSON audit report with:
1. "score" - Security score 0-10
2. "vulnerabilities" - Array of issues with:
   - "type": Vulnerability name
   - "severity": CRITICAL/HIGH/MEDIUM/LOW/INFO
   - "location": Code location
   - "description": Plain English explanation
   - "recommendation": How to fix
   - "cvss": CVSS score 0-10
3. "summary": Brief executive summary

Consider these common vulnerabilities:
- Reentrancy attacks
- Access control issues  
- Integer overflow/underflow
- Unchecked external calls
- Timestamp dependency
- tx.origin usage
- Unprotected Ether withdrawals
- Flash loan vulnerabilities

Contract:
```{code}```

Return ONLY valid JSON, no explanation:"""

        # Stream AI response
        full_response = ""
        async for chunk in providerInstance.generate_stream(prompt):
            full_response += chunk
            yield f"data: {json.dumps({'status': 'streaming', 'chunk': chunk})}\n\n"

        # Parse response
        audit_tasks[task_id]["status"] = "completed"
        audit_tasks[task_id]["progress"] = 100

        # Try to parse JSON from response
        try:
            # Find JSON in response
            start = full_response.find("{")
            end = full_response.rfind("}") + 1
            if start >= 0 and end > start:
                json_str = full_response[start:end]
                result = json.loads(json_str)
            else:
                result = generate_mock_audit(code)
        except:
            result = generate_mock_audit(code)

        audit_tasks[task_id]["result"] = result
        yield f"data: {json.dumps({'status': 'completed', 'result': result})}\n\n"

    except Exception as e:
        logger.error(f"Audit error: {e}")
        audit_tasks[task_id]["status"] = "failed"
        audit_tasks[task_id]["error"] = str(e)
        yield f"data: {json.dumps({'status': 'failed', 'error': str(e)})}\n\n"


def generate_mock_audit(code: str) -> Dict[str, Any]:
    """Fallback mock audit"""
    vulns = []
    code_lower = code.lower()

    if "withdraw" in code_lower:
        if (
            "onlyowner" not in code_lower
            and "require(msg.sender == owner)" not in code_lower
        ):
            vulns.append(
                {
                    "type": "Missing Access Control",
                    "severity": "CRITICAL",
                    "location": "withdraw()",
                    "description": "No owner check on withdraw",
                    "recommendation": "Add require(msg.sender == owner)",
                    "cvss": 9.1,
                }
            )
    if "transfer(" in code_lower:
        vulns.append(
            {
                "type": "Insecure External Call",
                "severity": "HIGH",
                "location": "transfer",
                "description": "Using legacy transfer",
                "recommendation": "Use SafeERC20",
                "cvss": 7.5,
            }
        )
    if "tx.origin" in code_lower:
        vulns.append(
            {
                "type": "tx.origin Vulnerability",
                "severity": "MEDIUM",
                "location": "global",
                "description": "tx.origin is vulnerable to phishing",
                "recommendation": "Use msg.sender",
                "cvss": 5.0,
            }
        )
    if "now" in code_lower:
        vulns.append(
            {
                "type": "Timestamp Dependency",
                "severity": "LOW",
                "location": "timestamp",
                "description": "now() is unreliable",
                "recommendation": "Use block.timestamp",
                "cvss": 2.5,
            }
        )
    if not vulns:
        vulns.append(
            {
                "type": "No Issues",
                "severity": "INFO",
                "location": "N/A",
                "description": "Code looks good",
                "cvss": 0.0,
            }
        )

    score = 10.0
    for v in vulns:
        if v["severity"] == "CRITICAL":
            score -= 3.0
        elif v["severity"] == "HIGH":
            score -= 2.0
        elif v["severity"] == "MEDIUM":
            score -= 1.0
        elif v["severity"] == "LOW":
            score -= 0.5

    return {
        "score": max(0, round(score, 1)),
        "vulnerabilities": vulns,
        "summary": f"Found {len(vulns)} issues",
    }


# ============================================================================
# API ENDPOINTS
# ============================================================================


@app.get("/api/chains")
async def get_chains():
    return list(CHAINS.values())


@app.post("/api/audit/start")
async def start_audit(request: AuditRequest):
    task_id = str(uuid.uuid4())[:8]

    # Get code - either direct or from on-chain
    code = request.code
    if request.address:
        code = await fetch_contract_source(request.address, request.chain)
        if not code:
            raise HTTPException(
                status_code=404, detail="Contract not found or not verified"
            )

    if not code:
        raise HTTPException(status_code=400, detail="Code or address required")

    audit_tasks[task_id] = {
        "task_id": task_id,
        "type": "address" if request.address else "code",
        "input": request.address or "direct code",
        "code": code,
        "chain": request.chain,
        "provider": request.provider,
        "model": request.model,
        "status": "queued",
        "progress": 0,
        "result": None,
    }

    return {"task_id": task_id, "status": "started"}


@app.get("/api/audit/stream/{task_id}")
async def stream_audit(task_id: str):
    """Streaming AI audit response"""
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    task = audit_tasks[task_id]

    async def event_generator():
        # Get stored input
        code = task.get("code", "")
        chain = task.get("chain", "ethereum")
        provider = task.get("provider", "nvidia")
        model = task.get("model", "minimaxai/minimax-m2.5")

        async for chunk in generate_audit_stream(task_id, code, chain, provider, model):
            yield chunk

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/audit/status/{task_id}")
async def get_status(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    return {
        "task_id": task_id,
        "status": task["status"],
        "progress": task.get("progress", 0),
    }


@app.get("/api/audit/report/{task_id}")
async def get_report(task_id: str):
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task["status"] != "completed":
        return {"status": task["status"], "progress": task.get("progress", 0)}
    return task.get("result", {})


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Solidify API server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8001)
