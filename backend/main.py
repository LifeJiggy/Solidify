"""
Solidify Backend - FastAPI Application Entry Point
Web3 Smart Contract Security Auditor

Author: Peace Stephen (Tech Lead)
Description: Main FastAPI application with all audit endpoints
"""

import os
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from chains.full_audit import FullAuditChain
from exploitation.exploit_engine import ExploitEngine
from blockchain.etherscan_client import EtherscanClient
from solidity_analysis.gas_analysis import GasAnalyzer

from fastapi import FastAPI, HTTPException, File, UploadFile, Form, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import core modules
from Solidify.core.gemini_client import GeminiClient
from Solidify.core.prompt_engine import PromptEngine
from Solidify.core.pdf_generator import PDFGenerator
from Solidify.core.cvss_scorer import CVSSScorer
from Solidify.core.vuln_taxonomy import VulnTaxonomy


# ============================================================================
# Pydantic Models
# ============================================================================

class AuditCodeRequest(BaseModel):
    """Request model for code audit"""
    code: str = Field(..., description="Solidity contract code")
    contract_name: Optional[str] = Field(None, description="Contract name")
    chain: Optional[str] = Field("ethereum", description="Blockchain chain")
    model: Optional[str] = Field("gemini-pro", description="AI model to use")
    include_patches: bool = Field(True, description="Include patched code")
    confidence_threshold: Optional[float] = Field(0.5, ge=0.0, le=1.0)


class AuditChainRequest(BaseModel):
    """Request model for on-chain audit"""
    address: str = Field(..., description="Contract address")
    chain: str = Field(..., description="Blockchain chain (ethereum, bsc, polygon, etc.)")
    model: Optional[str] = Field("gemini-pro", description="AI model to use")


class AuditResponse(BaseModel):
    """Response model for audit results"""
    contract_name: str
    audit_summary: str
    overall_risk_score: float
    total_vulnerabilities: int
    vulnerabilities: List[Dict[str, Any]]
    recommendations: List[str]
    scan_timestamp: str
    model_used: str
    chain: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    environment: str
    providers: Dict[str, bool]


class ProviderStatus(BaseModel):
    """Provider status response"""
    gemini: bool
    anthropic: bool
    openai: bool
    ollama: bool
    groq: bool


# ============================================================================
# Application State
# ============================================================================

class AppState:
    """Application state manager"""
    
    def __init__(self):
        self.gemini_client: Optional[GeminiClient] = None
        self.prompt_engine: PromptEngine = PromptEngine()
        self.pdf_generator: Optional[PDFGenerator] = None
        self.cvss_scorer: CVSSScorer = CVSSScorer()
        self.vuln_taxonomy: VulnTaxonomy = VulnTaxonomy()
        self.providers: Dict[str, Any] = {}
        
    async def initialize(self):
        """Initialize all services"""
        logger.info("Initializing Solidify services...")
        
        # Initialize Gemini client
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            self.gemini_client = GeminiClient(api_key)
            logger.info("✅ Gemini client initialized")
        else:
            logger.warning("⚠️ GEMINI_API_KEY not found")
        
        # Initialize PDF generator
        try:
            self.pdf_generator = PDFGenerator()
            logger.info("✅ PDF generator initialized")
        except Exception as e:
            logger.warning(f"⚠️ PDF generator initialization failed: {e}")
        
        # Load providers
        await self._load_providers()
        
    async def _load_providers(self):
        """Load all available AI providers"""
        from integrations import provider_bridge
        
        # Check and load each provider
        providers_config = {
            "gemini": os.getenv("GEMINI_API_KEY"),
            "anthropic": os.getenv("ANTHROPIC_API_KEY"),
            "openai": os.getenv("OPENAI_API_KEY"),
            "ollama": os.getenv("OLLAMA_BASE_URL"),
            "groq": os.getenv("GROQ_API_KEY"),
        }
        
        for name, key in providers_config.items():
            if key:
                self.providers[name] = True
            else:
                self.providers[name] = False
        
        logger.info(f"Providers loaded: {self.providers}")


# ============================================================================
# FastAPI Application
# ============================================================================

# Create application state
state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    await state.initialize()
    logger.info("🚀 Solidify API started")
    yield
    # Shutdown
    logger.info("🛑 Solidify API stopped")


# Create FastAPI app
app = FastAPI(
    title="Solidify API",
    description="AI-Powered Smart Contract Security Auditor",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# ============================================================================
# CORS Middleware
# ============================================================================

# Get CORS origins from environment
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
origins = [origin.strip() for origin in cors_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Root Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Solidify API",
        "version": "1.0.0",
        "description": "AI-Powered Smart Contract Security Auditor",
        "docs": "/docs",
        "endpoints": {
            "audit_code": "/audit/code",
            "audit_file": "/audit/file",
            "audit_chain": "/audit/chain",
            "health": "/health",
            "providers": "/providers"
        }
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    environment = os.getenv("ENVIRONMENT", "development")
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        environment=environment,
        providers={
            "gemini": state.providers.get("gemini", False),
            "anthropic": state.providers.get("anthropic", False),
            "openai": state.providers.get("openai", False),
            "ollama": state.providers.get("ollama", False),
            "groq": state.providers.get("groq", False)
        }
    )


@app.get("/providers", response_model=ProviderStatus)
async def get_providers():
    """Get provider status"""
    return ProviderStatus(
        gemini=state.providers.get("gemini", False),
        anthropic=state.providers.get("anthropic", False),
        openai=state.providers.get("openai", False),
        ollama=state.providers.get("ollama", False),
        groq=state.providers.get("groq", False)
    )


# ============================================================================
# Audit Endpoints
# ============================================================================

@app.post("/audit/code", response_model=AuditResponse)
async def audit_code(request: AuditCodeRequest):
    """
    Audit Solidity code directly
    
    Args:
        request: AuditCodeRequest with code and options
    
    Returns:
        AuditResponse with vulnerabilities and patches
    """
    logger.info(f"Auditing code: {request.contract_name or 'unnamed'}")
    
    # Check if Gemini client is initialized
    if not state.gemini_client:
        raise HTTPException(
            status_code=503,
            detail="Gemini client not initialized. Please set GEMINI_API_KEY."
        )
    
    try:
        # Build audit prompt
        prompt = state.prompt_engine.build_audit_prompt(
            code=request.code,
            contract_name=request.contract_name,
            include_patches=request.include_patches,
            confidence_threshold=request.confidence_threshold
        )
        
        # Call Gemini API
        response = await state.gemini_client.generate(
            prompt=prompt,
            model=request.model
        )
        
        # Parse and validate response
        audit_data = state.prompt_engine.parse_audit_response(response)
        
        # Apply CVSS scoring
        for vuln in audit_data.get("vulnerabilities", []):
            cvss_score = state.cvss_scorer.calculate_score(vuln)
            vuln["cvss_score"] = cvss_score
            vuln["severity"] = state.cvss_scorer.get_severity(cvss_score)
        
        # Get current timestamp
        from datetime import datetime
        timestamp = datetime.utcnow().isoformat()
        
        # Build response
        return AuditResponse(
            contract_name=audit_data.get("contract_name", request.contract_name or "Unknown"),
            audit_summary=audit_data.get("audit_summary", "No summary available"),
            overall_risk_score=audit_data.get("overall_risk_score", 0.0),
            total_vulnerabilities=len(audit_data.get("vulnerabilities", [])),
            vulnerabilities=audit_data.get("vulnerabilities", []),
            recommendations=audit_data.get("recommendations", []),
            scan_timestamp=timestamp,
            model_used=request.model,
            chain=request.chain
        )
        
    except Exception as e:
        logger.error(f"Error during code audit: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Audit failed: {str(e)}"
        )


@app.post("/audit/file")
async def audit_file(
    file: UploadFile = File(...),
    include_patches: bool = Form(True),
    confidence_threshold: float = Form(0.5),
    model: str = Form("gemini-pro")
):
    """
    Audit a Solidity file upload
    
    Args:
        file: .sol file upload
        include_patches: Include patched code in response
        confidence_threshold: Minimum confidence for findings
        model: AI model to use
    
    Returns:
        AuditResponse with vulnerabilities
    """
    logger.info(f"Processing file upload: {file.filename}")
    
    # Validate file type
    if not file.filename.endswith(".sol"):
        raise HTTPException(
            status_code=400,
            detail="Only .sol files are supported"
        )
    
    # Read file content
    try:
        content = await file.read()
        code = content.decode("utf-8")
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to read file: {str(e)}"
        )
    
    # Get contract name from filename
    contract_name = file.filename.replace(".sol", "")
    
    # Create audit request
    request = AuditCodeRequest(
        code=code,
        contract_name=contract_name,
        include_patches=include_patches,
        confidence_threshold=confidence_threshold,
        model=model
    )
    
    # Call audit endpoint
    return await audit_code(request)


@app.post("/audit/chain", response_model=AuditResponse)
async def audit_chain(request: AuditChainRequest):
    """
    Audit a live contract from blockchain
    
    Args:
        request: AuditChainRequest with contract address and chain
    
    Returns:
        AuditResponse with audit results
    """
    logger.info(f"Auditing contract on chain: {request.address} ({request.chain})")
    
    # Import chain fetcher
    from utils.chain_fetcher import ChainFetcher
    
    # Initialize chain fetcher
    chain_fetcher = ChainFetcher()
    
    try:
        # Fetch contract source
        contract_data = await chain_fetcher.fetch_contract(
            address=request.address,
            chain=request.chain
        )
        
        if not contract_data:
            raise HTTPException(
                status_code=404,
                detail=f"Contract not found or not verified on {request.chain}"
            )
        
        # Extract source code
        source_code = contract_data.get("source_code")
        contract_name = contract_data.get("contract_name", "Unknown")
        
        # Create audit request
        audit_request = AuditCodeRequest(
            code=source_code,
            contract_name=contract_name,
            chain=request.chain,
            model=request.model
        )
        
        # Perform audit
        result = await audit_code(audit_request)
        
        # Add chain info
        result.chain = request.chain
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during chain audit: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Chain audit failed: {str(e)}"
        )


# ============================================================================
# PDF Export Endpoint
# ============================================================================

@app.post("/export/pdf")
async def export_pdf(background_tasks: BackgroundTasks, request: AuditResponse):
    """
    Export audit results as PDF
    
    Args:
        request: AuditResponse to export
    
    Returns:
        PDF file stream
    """
    logger.info("Generating PDF export...")
    
    if not state.pdf_generator:
        raise HTTPException(
            status_code=503,
            detail="PDF generator not initialized"
        )
    
    try:
        # Generate PDF
        pdf_bytes = state.pdf_generator.generate(audit_data=request.dict())
        
        # Return as streaming response
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=audit_{request.contract_name}.pdf"
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {str(e)}"
        )


# ============================================================================
# Streaming Audit Endpoint
# ============================================================================

@app.post("/audit/stream")
async def audit_code_stream(request: AuditCodeRequest):
    """
    Stream audit results in real-time using SSE
    
    Args:
        request: AuditCodeRequest
    
    Returns:
        Server-Sent Events stream
    """
    logger.info(f"Starting streaming audit: {request.contract_name or 'unnamed'}")
    
    if not state.gemini_client:
        raise HTTPException(
            status_code=503,
            detail="Gemini client not initialized"
        )
    
    async def event_generator():
        """Generate SSE events"""
        try:
            # Send initial message
            yield "data: {\"status\": \"starting\", \"message\": \"Initializing audit...\"}\n\n"
            
            # Build prompt
            prompt = state.prompt_engine.build_audit_prompt(
                code=request.code,
                contract_name=request.contract_name,
                include_patches=request.include_patches
            )
            
            yield "data: {\"status\": \"analyzing\", \"message\": \"Analyzing contract...\"}\n\n"
            
            # Stream response from Gemini
            async for chunk in state.gemini_client.generate_stream(prompt):
                yield f"data: {chunk}\n\n"
            
            yield "data: {\"status\": \"complete\", \"message\": \"Audit complete\"}\n\n"
            
        except Exception as e:
            yield f"data: {{\"status\": \"error\", \"message\": \"{str(e)}\"}}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


# ============================================================================
# Vulnerability Taxonomy Endpoint
# ============================================================================

@app.get("/vuln/taxonomy")
async def get_vuln_taxonomy():
    """
    Get vulnerability taxonomy
    
    Returns:
        List of all vulnerability categories
    """
    return JSONResponse(
        content=state.vuln_taxonomy.get_all_vulnerabilities()
    )


@app.get("/vuln/taxonomy/{category}")
async def get_vuln_category(category: str):
    """
    Get specific vulnerability category
    
    Args:
        category: Vulnerability category name
    
    Returns:
        Category details
    """
    vuln = state.vuln_taxonomy.get_vulnerability(category)
    if not vuln:
        raise HTTPException(
            status_code=404,
            detail=f"Vulnerability category '{category}' not found"
        )
    return JSONResponse(content=vuln)


# ============================================================================
# Configuration Endpoints
# ============================================================================

@app.get("/config/chains")
async def get_supported_chains():
    """Get list of supported blockchain chains"""
    from utils.chain_fetcher import SUPPORTED_CHAINS
    return JSONResponse(content=SUPPORTED_CHAINS)


@app.get("/config/models")
async def get_available_models():
    """Get list of available AI models"""
    return JSONResponse(content={
        "default": "gemini-pro",
        "available": [
            "gemini-pro",
            "gemini-pro-vision",
            "claude-3-opus",
            "gpt-4",
            "gpt-3.5-turbo"
        ]
    })


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "message": str(exc)
        }
    )


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    reload = os.getenv("DEBUG", "true").lower() == "true"
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )
# --- 1. IMPORTS (Always at the very top) ---
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import google.generativeai as genai
import os
import json
import requests

# --- 2. SETUP & CONFIGURATION ---
# Load environment variables (your Gemini API Key)
load_dotenv()

# Configure the AI model
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash') 

# Initialize the server
app = FastAPI(title="Solidify AI Audit Engine")

# Allow the frontend to talk to this backend safely
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define what the frontend will send us (a string of code)
class AuditRequest(BaseModel):
    contract_code: str

# --- 3. ROUTES (The endpoints we can actually visit or send data to) ---

@app.get("/")
def health_check():
    """Basic health check to ensure the server is running."""
    api_key = os.getenv("GEMINI_API_KEY")
    return {
        "status": "Solidify Backend is ONLINE 🚀", 
        "gemini_key_loaded": bool(api_key)
    }

@app.post("/audit")
async def audit_contract(request: AuditRequest):
    """Takes Solidity code, sends it to Gemini, and returns structured JSON."""
    
    system_prompt = """
    You are an elite Web3 Security Auditor. Analyze the provided Solidity smart contract for vulnerabilities. 
    
    CRITICAL INSTRUCTIONS:
    1. Only flag actual security vulnerabilities (e.g., Reentrancy, Access Control, Overflow, Logic Bugs).
    2. DO NOT flag missing architectural best practices (like missing receive/fallback functions, or missing event emissions) as vulnerabilities unless they directly lead to a severe exploit.
    3. If no high/medium/critical vulnerabilities exist, you MUST set "is_secure" to true and return an empty [] for "vulnerabilities".

    You MUST return ONLY a valid JSON object matching this exact schema:
    {
      "contract_name": "Name of the analyzed contract",
      "audit_summary": "A 2-sentence executive summary.",
      "is_secure": true or false,
      "vulnerabilities": [
        {
          "title": "Vulnerability Name",
          "severity": "CRITICAL, HIGH, or MEDIUM",
          "cvss_score": 9.8,
          "swc_id": "SWC-XXX",
          "line_numbers": "12-15",
          "description": "Clear explanation of the exploit.",
          "remediation": "How to fix it.",
          "patched_code_snippet": "The secure code replacing the vulnerable lines."
        }
      ]
    }
    """
    
    full_prompt = f"{system_prompt}\n\nHere is the contract to audit:\n{request.contract_code}"
    
    try:
        # Ask Gemini to generate the audit in strict JSON format
        response = model.generate_content(
            full_prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json"
            )
        )
        
        # Parse the text back into actual JSON for FastAPI to send to the frontend
        return json.loads(response.text)
        
    except Exception as e:
        return {"error": str(e), "message": "The AI engine encountered an error."}

        # --- 4. EXPLOIT GENERATOR (Feature #23) ---

class ExploitRequest(BaseModel):
    contract_code: str
    vulnerability_title: str

@app.post("/generate-exploit")
async def generate_poc(request: ExploitRequest):
    """Generates a Hardhat/Ethers.js Proof of Concept script to exploit a vulnerability."""
    
    exploit_prompt = f"""
    You are an elite Web3 Security Researcher (Red Team). 
    Write a complete Hardhat (Ethers.js) Proof of Concept (PoC) exploit script to demonstrate the '{request.vulnerability_title}' vulnerability in the following smart contract.
    
    CRITICAL INSTRUCTIONS:
    1. Write ONLY the raw, executable JavaScript/TypeScript code. 
    2. Include comments explaining how the attack works step-by-step.
    3. Do NOT use markdown code blocks (like ```javascript). Just return the raw code.
    
    Target Contract:
    {request.contract_code}
    """
    
    try:
        # We don't force JSON here, we want raw code
        response = model.generate_content(exploit_prompt)
        
        # Clean up any accidental markdown the AI might try to sneak in
        clean_code = response.text.replace("```javascript", "").replace("```typescript", "").replace("```", "").strip()
        
        return {
            "status": "success",
            "vulnerability_targeted": request.vulnerability_title,
            "exploit_code": clean_code
        }
        
    except Exception as e:
        return {"error": str(e), "message": "Failed to generate exploit PoC."}

        # --- 5. BLOCKCHAIN INTEGRATION (Feature #5) ---

class AddressAuditRequest(BaseModel):
    contract_address: str

@app.post("/audit-address")
async def audit_live_contract(request: AddressAuditRequest):
    """Fetches verified code from Etherscan and audits it."""
    
    etherscan_key = os.getenv("ETHERSCAN_API_KEY")
    if not etherscan_key:
        return {"error": "Etherscan API key not configured in .env"}

       # 1. Fetch the code from Etherscan (V2 API)
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={request.contract_address}&apikey={etherscan_key}"

    try:
        response = requests.get(url)
        data = response.json()
        
        if data['status'] == '0':
            return {"error": "Failed to fetch contract", "message": data['result']}
            
        source_code = data['result'][0]['SourceCode']
        contract_name = data['result'][0]['ContractName']
        
        if not source_code:
            return {"error": "Contract source code is not verified on Etherscan."}
            
    except Exception as e:
        return {"error": "Etherscan API error", "message": str(e)}

    # 2. Feed the fetched code to our AI Audit Engine
    prompt = f"""
    Analyze the following live smart contract ({contract_name}) for vulnerabilities.
    Apply the exact same strict JSON schema and vulnerability rules as standard audits.
    
    Contract Code:
    {source_code[:100000]} # Truncating slightly just in case it's a massive file
    """
    
    try:
        # We reuse the same system_prompt and schema from Feature 01!
        ai_response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
            )
        )
        return ai_response.text
        
    except Exception as e:
        return {"error": str(e), "message": "AI failed to audit the fetched code."}

    # --- 6. GAS OPTIMIZER (Feature #19) ---

class GasRequest(BaseModel):
    contract_code: str

@app.post("/analyze-gas")
async def analyze_gas(request: GasRequest):
    """Analyzes a smart contract for EVM gas optimizations."""
    
    prompt = f"""
    You are an elite EVM Gas Optimizer. Analyze the provided Solidity code for gas inefficiencies.
    Focus strictly on:
    1. Caching state variables in memory (especially inside loops).
    2. Using `calldata` instead of `memory` for read-only external/public function arguments.
    3. Replacing long `require` strings with Custom Errors (you MUST use the 'if (!condition) revert CustomError();' syntax).
    4. Variable packing in structs/storage.
    
    Return ONLY a valid JSON object matching this schema:
    {{
        "optimization_score": "A, B, C, D, or F",
        "gas_summary": "A 2-sentence summary of the main inefficiencies.",
        "optimizations": [
            {{
                "title": "Cache State Variable",
                "line_numbers": "4-8",
                "description": "Explanation of why the current code wastes gas.",
                "optimized_code_snippet": "The cheaper way to write it"
            }}
        ]
    }}
    
    Contract Code:
    {request.contract_code}
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
            )
        )
        return response.text
        
    except Exception as e:
        return {"error": str(e), "message": "Gas analysis failed."}

        # --- 7. DEFI SECURITY: FLASH LOAN DETECTOR (Feature #15) ---

class DeFiRequest(BaseModel):
    contract_code: str

@app.post("/analyze-defi")
async def analyze_defi_patterns(request: DeFiRequest):
    """Analyzes contracts for DeFi-specific risks like Flash Loan price manipulation."""
    
    prompt = f"""
    You are a DeFi Security Specialist. Analyze this code for high-level DeFi attack vectors.
    Focus on:
    1. **Price Oracle Manipulation**: Is the contract using `balanceOf(address(this))` or a spot price that can be moved by a flash loan?
    2. **Flash Loan Sensitivity**: Does a function allow a large influx of capital to influence a logic outcome (e.g., reward calculation)?
    3. **Slippage Control**: Are swap functions missing `minAmountOut` or equivalent protection?

    Return ONLY a JSON object:
    {{
        "is_defi_risk": true/false,
        "risk_level": "Critical/High/Medium/Low",
        "attack_vector": "Name of the potential attack (e.g., Oracle Manipulation)",
        "explanation": "Briefly explain how an attacker would use a flash loan here.",
        "fix": "How to secure the protocol."
    }}

    Contract Code:
    {request.contract_code}
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(response_mime_type="application/json")
        )
        return response.text
    except Exception as e:
        return {"error": str(e)}

        # --- 8. MASTER AUDIT: ALL CHAINS (Priority 5) ---

class MasterAuditRequest(BaseModel):
    contract_code: str

@app.post("/master-audit")
async def run_master_audit(request: MasterAuditRequest):
    """Runs all vulnerability detectors and aggregates the results into one massive report."""
    report_json = FullAuditChain.run_all(request.contract_code)
    # Convert string back to dict so FastAPI returns clean JSON, not an escaped string
    import json
    return json.loads(report_json)

    # --- 9. EXPLOITATION ENGINE (Priority 6) ---

class ExploitRequest(BaseModel):
    contract_code: str
    vulnerability_type: str

@app.post("/generate-exploit")
async def create_exploit(request: ExploitRequest):
    """Generates a Hardhat PoC script to exploit a specific vulnerability."""
    poc_code = ExploitEngine.generate_poc(request.contract_code, request.vulnerability_type)
    return {"poc_script": poc_code}

    # --- 10. BLOCKCHAIN INTEGRATION (Priority 2) ---

class AddressRequest(BaseModel):
    chain_id: int
    contract_address: str

@app.post("/audit-address")
async def fetch_and_audit_address(request: AddressRequest):
    """Fetches verified contract code from Etherscan and runs the Master Audit."""
    client = EtherscanClient()
    contract_code = client.fetch_contract(request.chain_id, request.contract_address)
    
    if contract_code.startswith("Error"):
        return {"error": contract_code}
        
    # Automatically run the master audit on the fetched code
    from chains.full_audit import FullAuditChain
    report_json = FullAuditChain.run_all(contract_code)
    import json
    return {"source_code_fetched": True, "audit_report": json.loads(report_json)}

# --- 11. SOLIDITY ANALYSIS: GAS (Priority 3) ---

class GasRequest(BaseModel):
    contract_code: str

@app.post("/analyze-gas")
async def optimize_gas(request: GasRequest):
    """Analyzes EVM bytecode and Solidity logic for gas inefficiencies."""
    gas_report = GasAnalyzer.analyze(request.contract_code)
    import json
    try:
        return json.loads(gas_report)
    except:
        return {"raw_report": gas_report}
