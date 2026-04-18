#!/usr/bin/env python3
"""
Solidify API Server
FastAPI backend for web interface
"""

import asyncio
import uuid
import time
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Solidify API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for audit tasks
audit_tasks: Dict[str, Dict[str, Any]] = {}


class AuditRequest(BaseModel):
    code: Optional[str] = None
    address: Optional[str] = None
    chain: str = "ethereum"


class ChainInfo(BaseModel):
    id: str
    name: str
    rpc: str


CHAINS = [
    ChainInfo(id="ethereum", name="Ethereum", rpc="https://eth.llamarpc.com"),
    ChainInfo(id="bsc", name="BNB Chain", rpc="https://bsc-dataseed.binance.org"),
    ChainInfo(id="polygon", name="Polygon", rpc="https://polygon-rpc.com"),
    ChainInfo(id="arbitrum", name="Arbitrum", rpc="https://arb1.arbitrum.io/rpc"),
    ChainInfo(id="optimism", name="Optimism", rpc="https://mainnet.optimism.io"),
]


@app.get("/api/chains")
async def get_chains():
    return [{"id": c.id, "name": c.name, "rpc": c.rpc} for c in CHAINS]


@app.post("/api/audit/start")
async def start_audit(request: AuditRequest):
    task_id = str(uuid.uuid4())[:8]

    if request.code:
        audit_type = "code"
        input_data = request.code
    elif request.address:
        audit_type = "address"
        input_data = request.address
    else:
        raise HTTPException(status_code=400, detail="Either code or address required")

    audit_tasks[task_id] = {
        "task_id": task_id,
        "type": audit_type,
        "input": input_data,
        "chain": request.chain,
        "status": "queued",
        "progress": 0,
        "result": None,
    }

    # Run audit in background
    asyncio.create_task(run_audit(task_id, input_data, request.chain, audit_type))

    return {"task_id": task_id, "status": "queued"}


async def run_audit(task_id: str, input_data: str, chain: str, audit_type: str):
    try:
        # Update status to scanning
        audit_tasks[task_id]["status"] = "scanning"
        audit_tasks[task_id]["progress"] = 25
        await asyncio.sleep(1)

        # Update status to analyzing
        audit_tasks[task_id]["status"] = "analyzing"
        audit_tasks[task_id]["progress"] = 50
        await asyncio.sleep(1)

        # Update status to patching
        audit_tasks[task_id]["status"] = "patching"
        audit_tasks[task_id]["progress"] = 75
        await asyncio.sleep(1)

        # Generate mock audit result
        vulns = generate_mock_audit(input_data, chain)

        # Complete
        audit_tasks[task_id]["status"] = "completed"
        audit_tasks[task_id]["progress"] = 100
        audit_tasks[task_id]["result"] = {
            "score": calculate_score(vulns),
            "vulnerabilities": vulns,
            "summary": f"Found {len(vulns)} potential vulnerabilities in {audit_type} audit",
        }

    except Exception as e:
        audit_tasks[task_id]["status"] = "failed"
        audit_tasks[task_id]["error"] = str(e)


def generate_mock_audit(code: str, chain: str) -> List[Dict[str, Any]]:
    vulns = []
    code_lower = code.lower()

    # Check for common vulnerabilities
    if "withdraw" in code_lower and "payable(owner)" in code_lower:
        if (
            "onlyowner" not in code_lower
            and "require(msg.sender == owner)" not in code_lower
        ):
            vulns.append(
                {
                    "type": "Missing Access Control",
                    "severity": "CRITICAL",
                    "location": "withdraw() function",
                    "description": "The withdraw function lacks access control, allowing anyone to drain funds.",
                    "recommendation": "Add require(msg.sender == owner) or use OpenZeppelin Ownable.",
                    "cvss": 9.1,
                }
            )

    if "transfer(" in code_lower and "call(" not in code_lower:
        vulns.append(
            {
                "type": "Insecure External Call",
                "severity": "HIGH",
                "location": "transfer/call",
                "description": "Using transfer/call instead of safeTransferFrom pattern.",
                "recommendation": "Use OpenZeppelin's SafeERC20.",
                "cvss": 7.5,
            }
        )

    if "tx.origin" in code_lower:
        vulns.append(
            {
                "type": "tx.origin Vulnerability",
                "severity": "MEDIUM",
                "location": "global variable",
                "description": "Using tx.origin for authorization is vulnerable to phishing.",
                "recommendation": "Use msg.sender instead.",
                "cvss": 5.0,
            }
        )

    if "now" in code_lower:
        vulns.append(
            {
                "type": "Timestamp Dependency",
                "severity": "LOW",
                "location": "timestamp",
                "description": "Using now() for critical timing is unreliable.",
                "recommendation": "Use block.timestamp with care.",
                "cvss": 2.5,
            }
        )

    if not vulns:
        vulns.append(
            {
                "type": "No Critical Issues",
                "severity": "INFO",
                "location": "N/A",
                "description": "No obvious vulnerabilities detected in this contract.",
                "cvss": 0.0,
            }
        )

    return vulns


def calculate_score(vulns: List[Dict[str, Any]]) -> float:
    score = 10.0
    for v in vulns:
        sev = v.get("severity", "INFO")
        if sev == "CRITICAL":
            score -= 3.0
        elif sev == "HIGH":
            score -= 2.0
        elif sev == "MEDIUM":
            score -= 1.0
        elif sev == "LOW":
            score -= 0.5
    return max(0.0, round(score, 1))


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
    uvicorn.run(app, host="0.0.0.0", port=8000)
