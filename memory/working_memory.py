"""
SoliGuard Working Memory
Working memory for current analysis context

Author: Peace Stephen (Tech Lead)
Description: Working memory for holding current analysis state
"""

import re
import logging
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict


class BufferType(Enum):
    STACK = "stack"
    QUEUE = "queue"
    PRIORITY = "priority"


@dataclass
class WorkingBuffer:
    buffer_id: str
    buffer_type: BufferType
    data: List[Any] = field(default_factory=list)
    max_size: int = 100


class WorkingMemoryManager:
    def __init__(self):
        self.buffers: Dict[str, WorkingBuffer] = {}
        self.variables: Dict[str, Any] = {}
        self.locks: Dict[str, threading.Lock] = {}
        
    def create_buffer(self, buffer_id: str, buffer_type: BufferType = BufferType.STACK) -> WorkingBuffer:
        if buffer_id in self.buffers:
            return self.buffers[buffer_id]
            
        buffer = WorkingBuffer(buffer_id=buffer_id, buffer_type=buffer_type)
        self.buffers[buffer_id] = buffer
        self.locks[buffer_id] = threading.Lock()
        return buffer
    
    def push(self, buffer_id: str, value: Any) -> bool:
        if buffer_id not in self.buffers:
            self.create_buffer(buffer_id)
            
        buffer = self.buffers[buffer_id]
        
        with self.locks[buffer_id]:
            if len(buffer.data) >= buffer.max_size:
                if buffer.buffer_type == BufferType.STACK:
                    buffer.data.pop(0)
                else:
                    buffer.data.pop(0)
                    
            buffer.data.append(value)
            
        return True
    
    def pop(self, buffer_id: str) -> Optional[Any]:
        if buffer_id not in self.buffers:
            return None
            
        buffer = self.buffers[buffer_id]
        
        with self.locks[buffer_id]:
            if not buffer.data:
                return None
                
            if buffer.buffer_type == BufferType.STACK:
                return buffer.data.pop()
            else:
                return buffer.data.pop(0)
    
    def set_variable(self, key: str, value: Any) -> None:
        self.variables[key] = value
    
    def get_variable(self, key: str) -> Optional[Any]:
        return self.variables.get(key)
    
    def get_stats(self) -> Dict[str, Any]:
        return {"buffers": len(self.buffers), "variables": len(self.variables)}


def set_working_variable(key: str, value: Any) -> None:
    get_default_working_memory().set_variable(key, value)


def get_working_variable(key: str) -> Optional[Any]:
    return get_default_working_memory().get_variable(key)


_default_working_memory: Optional[WorkingMemoryManager] = None


def get_default_working_memory() -> WorkingMemoryManager:
    global _default_working_memory
    
    if _default_working_memory is None:
        _default_working_memory = WorkingMemoryManager()
        
    return _default_working_memory