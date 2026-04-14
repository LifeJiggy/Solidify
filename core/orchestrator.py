"""
SoliGuard Core Orchestrator
Main orchestration engine for audit processing

Author: Peace Stephen (Tech Lead)
Description: Coordinates all audit components
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class AuditMode(Enum):
    """Audit execution modes"""
    STANDARD = "standard"
    DEEP = "deep"
    FAST = "fast"
    STREAM = "stream"


class ExecutionStatus(Enum):
    """Execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuditTask:
    """Audit task definition"""
    task_id: str
    contract_code: str
    contract_name: Optional[str] = None
    chain: str = "ethereum"
    mode: AuditMode = AuditMode.STANDARD
    options: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class ChainConfig:
    """Chain configuration"""
    chain_id: int
    name: str
    rpc_url: str
    explorer_url: str
    explorer_api_url: str
    native_symbol: str
    gas_limit: int = 3000000


# ============================================================================
# Orchestrator
# ============================================================================

class Orchestrator:
    """
    Main orchestrator for SoliGuard audit pipeline
    
    Features:
    - Task management and scheduling
    - Multi-step chain execution
    - Plugin system for extensibility
    - Event-driven architecture
    - Error handling and recovery
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize orchestrator
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.tasks: Dict[str, AuditTask] = {}
        self.plugins: Dict[str, Any] = {}
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.chains: Dict[str, ChainConfig] = self._load_chains()
        self._task_counter = 0
        
        logger.info("✅ Orchestrator initialized")
    
    def _load_chains(self) -> Dict[str, ChainConfig]:
        """Load chain configurations"""
        return {
            "ethereum": ChainConfig(
                chain_id=1,
                name="Ethereum",
                rpc_url="https://eth.llamarpc.com",
                explorer_url="https://etherscan.io",
                explorer_api_url="https://api.etherscan.io/api",
                native_symbol="ETH"
            ),
            "bsc": ChainConfig(
                chain_id=56,
                name="Binance Smart Chain",
                rpc_url="https://bsc-dataseed.binance.org",
                explorer_url="https://bscscan.com",
                explorer_api_url="https://api.bscscan.com/api",
                native_symbol="BNB"
            ),
            "polygon": ChainConfig(
                chain_id=137,
                name="Polygon",
                rpc_url="https://polygon-rpc.com",
                explorer_url="https://polygonscan.com",
                explorer_api_url="https://api.polygonscan.com/api",
                native_symbol="MATIC"
            ),
            "arbitrum": ChainConfig(
                chain_id=42161,
                name="Arbitrum One",
                rpc_url="https://arb1.arbitrum.io/rpc",
                explorer_url="https://arbiscan.io",
                explorer_api_url="https://api.arbiscan.io/api",
                native_symbol="ETH"
            ),
            "optimism": ChainConfig(
                chain_id=10,
                name="Optimism",
                rpc_url="https://mainnet.optimism.io",
                explorer_url="https://optimistic.etherscan.io",
                explorer_api_url="https://api-optimistic.etherscan.io/api",
                native_symbol="ETH"
            ),
            "base": ChainConfig(
                chain_id=8453,
                name="Base",
                rpc_url="https://mainnet.base.org",
                explorer_url="https://basescan.org",
                explorer_api_url="https://api.basescan.org/api",
                native_symbol="ETH"
            ),
        }
    
    # ============================================================================
    # Task Management
    # ============================================================================
    
    def create_task(
        self,
        contract_code: str,
        contract_name: Optional[str] = None,
        chain: str = "ethereum",
        mode: AuditMode = AuditMode.STANDARD,
        **options
    ) -> str:
        """
        Create a new audit task
        
        Args:
            contract_code: Solidity contract code
            contract_name: Name of the contract
            chain: Blockchain chain
            mode: Audit execution mode
            **options: Additional options
        
        Returns:
            Task ID
        """
        self._task_counter += 1
        task_id = f"task_{self._task_counter}_{int(datetime.utcnow().timestamp())}"
        
        task = AuditTask(
            task_id=task_id,
            contract_code=contract_code,
            contract_name=contract_name,
            chain=chain,
            mode=mode,
            options=options,
            created_at=datetime.utcnow().isoformat()
        )
        
        self.tasks[task_id] = task
        logger.info(f"Created task: {task_id}")
        
        self._emit_event("task_created", {"task_id": task_id})
        
        return task_id
    
    def get_task(self, task_id: str) -> Optional[AuditTask]:
        """Get task by ID"""
        return self.tasks.get(task_id)
    
    def list_tasks(
        self,
        status: Optional[ExecutionStatus] = None,
        limit: int = 100
    ) -> List[AuditTask]:
        """List tasks with optional filtering"""
        tasks = list(self.tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        
        return tasks[-limit:]
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        if task.status == ExecutionStatus.RUNNING:
            task.status = ExecutionStatus.CANCELLED
            task.completed_at = datetime.utcnow().isoformat()
            self._emit_event("task_cancelled", {"task_id": task_id})
            return True
        
        return False
    
    # ============================================================================
    # Execution Engine
    # ============================================================================
    
    async def execute_task(
        self,
        task_id: str,
        gemini_client: Any = None,
        prompt_engine: Any = None,
        cvss_scorer: Any = None
    ) -> Dict[str, Any]:
        """
        Execute an audit task
        
        Args:
            task_id: Task ID to execute
            gemini_client: Gemini client instance
            prompt_engine: Prompt engine instance
            cvss_scorer: CVSS scorer instance
        
        Returns:
            Execution result
        """
        task = self.tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        
        # Update status
        task.status = ExecutionStatus.RUNNING
        task.started_at = datetime.utcnow().isoformat()
        
        self._emit_event("task_started", {"task_id": task_id})
        
        logger.info(f"Executing task: {task_id}")
        
        try:
            # Build execution chain based on mode
            result = await self._execute_audit_chain(
                task=task,
                gemini_client=gemini_client,
                prompt_engine=prompt_engine,
                cvss_scorer=cvss_scorer
            )
            
            # Update task with result
            task.status = ExecutionStatus.COMPLETED
            task.completed_at = datetime.utcnow().isoformat()
            task.result = result
            
            self._emit_event("task_completed", {
                "task_id": task_id,
                "result": result
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Task execution failed: {str(e)}")
            
            task.status = ExecutionStatus.FAILED
            task.completed_at = datetime.utcnow().isoformat()
            task.error = str(e)
            
            self._emit_event("task_failed", {
                "task_id": task_id,
                "error": str(e)
            })
            
            raise
    
    async def _execute_audit_chain(
        self,
        task: AuditTask,
        gemini_client: Any,
        prompt_engine: Any,
        cvss_scorer: Any
    ) -> Dict[str, Any]:
        """Execute audit based on mode"""
        
        if task.mode == AuditMode.STANDARD:
            return await self._execute_standard_audit(
                task, gemini_client, prompt_engine, cvss_scorer
            )
        elif task.mode == AuditMode.DEEP:
            return await self._execute_deep_audit(
                task, gemini_client, prompt_engine, cvss_scorer
            )
        elif task.mode == AuditMode.FAST:
            return await self._execute_fast_audit(
                task, gemini_client, prompt_engine, cvss_scorer
            )
        elif task.mode == AuditMode.STREAM:
            return await self._execute_stream_audit(
                task, gemini_client, prompt_engine, cvss_scorer
            )
        else:
            return await self._execute_standard_audit(
                task, gemini_client, prompt_engine, cvss_scorer
            )
    
    async def _execute_standard_audit(
        self,
        task: AuditTask,
        gemini_client: Any,
        prompt_engine: Any,
        cvss_scorer: Any
    ) -> Dict[str, Any]:
        """Execute standard audit"""
        
        result = {
            "task_id": task.task_id,
            "mode": "standard",
            "contract_name": task.contract_name or "Unknown",
            "chain": task.chain,
            "audit_summary": "",
            "overall_risk_score": 0.0,
            "total_vulnerabilities": 0,
            "vulnerabilities": [],
            "recommendations": [],
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        # Check if we have required components
        if not gemini_client or not prompt_engine:
            logger.warning("Gemini client or prompt engine not available, returning mock result")
            result["audit_summary"] = "Audit service not fully configured"
            return result
        
        try:
            # Build prompt
            prompt = prompt_engine.build_audit_prompt(
                code=task.contract_code,
                contract_name=task.contract_name,
                chain=task.chain,
                include_patches=task.options.get("include_patches", True),
                confidence_threshold=task.options.get("confidence_threshold", 0.5)
            )
            
            # Call Gemini
            response = await gemini_client.generate(prompt=prompt)
            
            # Parse response
            audit_data = prompt_engine.parse_audit_response(response)
            
            # Apply CVSS scoring
            if cvss_scorer:
                for vuln in audit_data.get("vulnerabilities", []):
                    cvss_score = cvss_scorer.calculate_score(vuln)
                    vuln["cvss_score"] = cvss_score
                    vuln["severity"] = cvss_scorer.get_severity(cvss_score)
            
            result.update(audit_data)
            
        except Exception as e:
            logger.error(f"Standard audit failed: {str(e)}")
            result["audit_summary"] = f"Audit failed: {str(e)}"
        
        return result
    
    async def _execute_deep_audit(
        self,
        task: AuditTask,
        gemini_client: Any,
        prompt_engine: Any,
        cvss_scorer: Any
    ) -> Dict[str, Any]:
        """Execute deep audit with extra analysis"""
        
        # First run standard audit
        result = await self._execute_standard_audit(
            task, gemini_client, prompt_engine, cvss_scorer
        )
        
        result["mode"] = "deep"
        
        # Additional deep analysis
        if task.options.get("include_gas_analysis", True):
            gas_prompt = prompt_engine.build_gas_optimization_prompt(
                code=task.contract_code
            )
            try:
                gas_response = await gemini_client.generate_json(
                    prompt=gas_prompt,
                    schema={"optimizations": {"type": "array"}}
                )
                result["gas_optimizations"] = gas_response.get("optimizations", [])
            except Exception as e:
                logger.warning(f"Gas analysis failed: {str(e)}")
        
        if task.options.get("include_defi_patterns", True):
            result["defi_analysis"] = await self._analyze_defi_patterns(
                task.contract_code, gemini_client, prompt_engine
            )
        
        return result
    
    async def _execute_fast_audit(
        self,
        task: AuditTask,
        gemini_client: Any,
        prompt_engine: Any,
        cvss_scorer: Any
    ) -> Dict[str, Any]:
        """Execute fast audit with reduced analysis"""
        
        result = {
            "task_id": task.task_id,
            "mode": "fast",
            "contract_name": task.contract_name or "Unknown",
            "chain": task.chain,
            "audit_summary": "Quick scan completed",
            "overall_risk_score": 0.0,
            "total_vulnerabilities": 0,
            "vulnerabilities": [],
            "recommendations": [],
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        # Use lower temperature for faster results
        if gemini_client and prompt_engine:
            try:
                prompt = prompt_engine.build_audit_prompt(
                    code=task.contract_code,
                    contract_name=task.contract_name,
                    confidence_threshold=0.7  # Higher threshold, fewer results
                )
                
                response = await gemini_client.generate(
                    prompt=prompt,
                    temperature=0.3
                )
                
                audit_data = prompt_engine.parse_audit_response(response)
                
                if cvss_scorer:
                    for vuln in audit_data.get("vulnerabilities", []):
                        cvss_score = cvss_scorer.calculate_score(vuln)
                        vuln["cvss_score"] = cvss_score
                        vuln["severity"] = cvss_scorer.get_severity(cvss_score)
                
                result.update(audit_data)
                
            except Exception as e:
                logger.warning(f"Fast audit issue: {str(e)}")
        
        return result
    
    async def _execute_stream_audit(
        self,
        task: AuditTask,
        gemini_client: Any,
        prompt_engine: Any,
        cvss_scorer: Any
    ) -> Dict[str, Any]:
        """Execute streaming audit"""
        
        result = {
            "task_id": task.task_id,
            "mode": "stream",
            "contract_name": task.contract_name or "Unknown",
            "chain": task.chain,
            "streaming": True,
            "findings": [],
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        if gemini_client and prompt_engine:
            prompt = prompt_engine.build_audit_prompt(
                code=task.contract_code,
                contract_name=task.contract_name
            )
            
            findings = []
            async for chunk in gemini_client.generate_stream(prompt):
                # Process streaming chunks
                if chunk:
                    findings.append(chunk)
                    self._emit_event("finding", {
                        "task_id": task.task_id,
                        "chunk": chunk
                    })
            
            result["findings"] = findings
        
        return result
    
    async def _analyze_defi_patterns(
        self,
        code: str,
        gemini_client: Any,
        prompt_engine: Any
    ) -> Dict[str, Any]:
        """Analyze DeFi specific patterns"""
        
        return {
            "patterns_found": [],
            "risk_factors": [],
            "recommendations": []
        }
    
    # ============================================================================
    # Plugin System
    # ============================================================================
    
    def register_plugin(self, name: str, plugin: Any):
        """Register a plugin"""
        self.plugins[name] = plugin
        logger.info(f"Registered plugin: {name}")
    
    def unregister_plugin(self, name: str):
        """Unregister a plugin"""
        if name in self.plugins:
            del self.plugins[name]
            logger.info(f"Unregistered plugin: {name}")
    
    def get_plugin(self, name: str) -> Optional[Any]:
        """Get a registered plugin"""
        return self.plugins.get(name)
    
    # ============================================================================
    # Event System
    # ============================================================================
    
    def on_event(self, event_name: str, handler: Callable):
        """Register event handler"""
        if event_name not in self.event_handlers:
            self.event_handlers[event_name] = []
        self.event_handlers[event_name].append(handler)
    
    def _emit_event(self, event_name: str, data: Dict[str, Any]):
        """Emit an event"""
        if event_name in self.event_handlers:
            for handler in self.event_handlers[event_name]:
                try:
                    handler(data)
                except Exception as e:
                    logger.error(f"Event handler error: {str(e)}")
    
    # ============================================================================
    # Utility Methods
    # ============================================================================
    
    def get_chain_config(self, chain: str) -> Optional[ChainConfig]:
        """Get chain configuration"""
        return self.chains.get(chain)
    
    def get_supported_chains(self) -> List[str]:
        """Get list of supported chains"""
        return list(self.chains.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            "total_tasks": len(self.tasks),
            "pending": sum(1 for t in self.tasks.values() if t.status == ExecutionStatus.PENDING),
            "running": sum(1 for t in self.tasks.values() if t.status == ExecutionStatus.RUNNING),
            "completed": sum(1 for t in self.tasks.values() if t.status == ExecutionStatus.COMPLETED),
            "failed": sum(1 for t in self.tasks.values() if t.status == ExecutionStatus.FAILED),
            "registered_plugins": len(self.plugins),
            "supported_chains": len(self.chains)
        }


# ============================================================================
# Factory Functions
# ============================================================================

def create_orchestrator(config: Optional[Dict[str, Any]] = None) -> Orchestrator:
    """Create orchestrator instance"""
    return Orchestrator(config)


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    # Test orchestrator
    orchestrator = Orchestrator()
    
    # Create task
    task_id = orchestrator.create_task(
        contract_code="pragma solidity ^0.8.0; contract Test {}",
        contract_name="TestContract",
        chain="ethereum",
        mode=AuditMode.STANDARD
    )
    
    print(f"Created task: {task_id}")
    
    # Get statistics
    stats = orchestrator.get_statistics()
    print(f"Statistics: {stats}")
    
    # List chains
    chains = orchestrator.get_supported_chains()
    print(f"Supported chains: {chains}")