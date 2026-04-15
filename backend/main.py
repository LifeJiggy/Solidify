"""
SoliGuard Backend - FastAPI Application Entry Point
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
from core.gemini_client import GeminiClient
from core.prompt_engine import PromptEngine
from core.pdf_generator import PDFGenerator
from core.cvss_scorer import CVSSScorer
from core.vuln_taxonomy import VulnTaxonomy


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
        logger.info("Initializing SoliGuard services...")
        
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
    logger.info("🚀 SoliGuard API started")
    yield
    # Shutdown
    logger.info("🛑 SoliGuard API stopped")


# Create FastAPI app
app = FastAPI(
    title="SoliGuard API",
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
        "name": "SoliGuard API",
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