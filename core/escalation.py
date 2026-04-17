"""
Solidify Core Escalation
Escalation handling and priority management

Author: Peace Stephen (Tech Lead)
Description: Escalation engine
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class EscalationLevel(Enum):
    """Escalation levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    BLOCKING = 5


class EscalationStatus(Enum):
    """Escalation status"""
    ACTIVE = "active"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    CANCELLED = "cancelled"


@dataclass
class Escalation:
    """Escalation definition"""
    id: str
    level: EscalationLevel
    title: str
    description: str
    source: str
    target: Optional[str] = None
    status: EscalationStatus = EscalationStatus.ACTIVE
    created_at: str = ""
    resolved_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class EscalationEngine:
    """Escalation handling engine"""
    
    def __init__(self):
        self.escalations: Dict[str, Escalation] = {}
        self.handlers: Dict[EscalationLevel, List[Callable]] = {
            level: [] for level in EscalationLevel
        }
        self._counter = 0
    
    def register_handler(self, level: EscalationLevel, handler: Callable):
        self.handlers[level].append(handler)
    
    async def create_escalation(
        self,
        level: EscalationLevel,
        title: str,
        description: str,
        source: str,
        **metadata
    ) -> str:
        self._counter += 1
        esc_id = f"esc_{self._counter}"
        
        escalation = Escalation(
            id=esc_id,
            level=level,
            title=title,
            description=description,
            source=source,
            created_at=datetime.utcnow().isoformat(),
            metadata=metadata
        )
        
        self.escalations[esc_id] = escalation
        logger.info(f"Escalation created: {esc_id} ({level.name})")
        
        # Trigger handlers
        for handler in self.handlers.get(level, []):
            await handler(escalation)
        
        return esc_id
    
    def get_escalation(self, esc_id: str) -> Optional[Escalation]:
        return self.escalations.get(esc_id)
    
    def resolve(self, esc_id: str) -> bool:
        esc = self.escalations.get(esc_id)
        if esc:
            esc.status = EscalationStatus.RESOLVED
            esc.resolved_at = datetime.utcnow().isoformat()
            return True
        return False
    
    def get_active(self) -> List[Escalation]:
        return [e for e in self.escalations.values() 
                if e.status == EscalationStatus.ACTIVE]


def create_escalation_engine() -> EscalationEngine:
    return EscalationEngine()


if __name__ == "__main__":
    engine = create_escalation_engine()
    
    async def handler(esc: Escalation):
        print(f"Handling escalation: {esc.title}")
    
    engine.register_handler(EscalationLevel.CRITICAL, handler)
    
    esc_id = asyncio.run(engine.create_escalation(
        EscalationLevel.CRITICAL,
        "Critical Issue",
        "System failure",
        "system"
    ))
    print(f"Created: {esc_id}")