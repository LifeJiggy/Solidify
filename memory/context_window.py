"""
SoliGuard Context Window
Context window management for token limits

Author: Peace Stephen (Tech Lead)
Description: Context window for managing conversation context within token limits
"""

import re
import logging
import json
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque, defaultdict

logger = logging.getLogger(__name__)


class WindowStrategy(Enum):
    FIXED = "fixed"
    SLIDING = "sliding"
    PRIORITY = "priority"
    IMPORTANCE = "importance"


class MessageRole(Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    role: MessageRole
    content: str
    token_count: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContextWindow:
    window_id: str
    max_tokens: int = 8000
    max_messages: int = 100
    strategy: WindowStrategy = WindowStrategy.SLIDING
    messages: deque = field(default_factory=deque)
    total_tokens: int = 0


class TokenCounter:
    def __init__(self, model: str = "gemini"):
        self.model = model
        self.avg_token_per_char = 0.25
        
    def count_tokens(self, text: str) -> int:
        return int(len(text) * self.avg_token_per_char)
    
    def estimate_messages_tokens(self, messages: List[Message]) -> int:
        return sum(msg.token_count for msg in messages)


class ContextWindowManager:
    def __init__(self, max_tokens: int = 8000, strategy: WindowStrategy = WindowStrategy.SLIDING):
        self.max_tokens = max_tokens
        self.strategy = strategy
        self.windows: Dict[str, ContextWindow] = {}
        self.counter = TokenCounter()
        self.active_window: Optional[ContextWindow] = None
        
    def create_window(self, window_id: str) -> ContextWindow:
        window = ContextWindow(
            window_id=window_id,
            max_tokens=self.max_tokens,
            strategy=self.strategy
        )
        self.windows[window_id] = window
        return window
    
    def add_message(self, window_id: str, message: Message) -> bool:
        if window_id not in self.windows:
            self.create_window(window_id)
            
        window = self.windows[window_id]
        
        if message.token_count == 0:
            message.token_count = self.counter.count_tokens(message.content)
            
        if window.total_tokens + message.token_count > window.max_tokens:
            self._evict_messages(window)
            
        if window.total_tokens + message.token_count > window.max_tokens:
            return False
            
        window.messages.append(message)
        window.total_tokens += message.token_count
        
        while len(window.messages) > window.max_messages:
            removed = window.messages.popleft()
            window.total_tokens -= removed.token_count
            
        return True
    
    def get_messages(self, window_id: str) -> List[Message]:
        if window_id not in self.windows:
            return []
        return list(self.windows[window_id].messages)
    
    def get_context(self, window_id: str) -> str:
        messages = self.get_messages(window_id)
        return "\n".join([f"{msg.role.value}: {msg.content}" for msg in messages])
    
    def clear_window(self, window_id: str) -> bool:
        if window_id in self.windows:
            window = self.windows[window_id]
            window.messages.clear()
            window.total_tokens = 0
            return True
        return False
    
    def delete_window(self, window_id: str) -> bool:
        if window_id in self.windows:
            del self.windows[window_id]
            return True
        return False
    
    def _evict_messages(self, window: ContextWindow) -> None:
        if self.strategy == WindowStrategy.SLIDING:
            while window.total_tokens + sum(m.token_count for m in window.messages) > window.max_tokens and window.messages:
                removed = window.messages.popleft()
                window.total_tokens -= removed.token_count
                
        elif self.strategy == WindowStrategy.PRIORITY:
            by_priority = defaultdict(list)
            for i, msg in enumerate(window.messages):
                priority = msg.metadata.get("priority", 0)
                by_priority[priority].append(i)
            
            for priority in sorted(by_priority.keys()):
                for idx in by_priority[priority]:
                    if window.total_tokens > window.max_tokens:
                        removed = window.messages[idx]
                        window.total_tokens -= removed.token_count
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "windows": len(self.windows),
            "max_tokens": self.max_tokens,
            "strategy": self.strategy.value
        }


class MessageBuilder:
    def __init__(self):
        self.role: Optional[MessageRole] = None
        self.content: str = ""
        self.metadata: Dict[str, Any] = {}
        
    def set_role(self, role: MessageRole) -> "MessageBuilder":
        self.role = role
        return self
        
    def set_content(self, content: str) -> "MessageBuilder":
        self.content = content
        return self
        
    def add_metadata(self, key: str, value: Any) -> "MessageBuilder":
        self.metadata[key] = value
        return self
        
    def build(self) -> Message:
        if not self.role:
            raise ValueError("Role not set")
            
        return Message(
            role=self.role,
            content=self.content,
            metadata=self.metadata
        )


class WindowSerializer:
    def __init__(self):
        pass
    
    def serialize(self, window: ContextWindow) -> str:
        return json.dumps({
            "window_id": window.window_id,
            "max_tokens": window.max_tokens,
            "max_messages": window.max_messages,
            "strategy": window.strategy.value,
            "messages": [
                {
                    "role": msg.role.value,
                    "content": msg.content,
                    "token_count": msg.token_count,
                    "timestamp": msg.timestamp.isoformat(),
                    "metadata": msg.metadata
                }
                for msg in window.messages
            ],
            "total_tokens": window.total_tokens
        }, indent=2)
    
    def deserialize(self, data: str) -> Optional[ContextWindow]:
        try:
            parsed = json.loads(data)
            
            messages = deque()
            for msg_data in parsed.get("messages", []):
                msg = Message(
                    role=MessageRole[msg_data["role"].upper()],
                    content=msg_data["content"],
                    token_count=msg_data.get("token_count", 0),
                    timestamp=datetime.fromisoformat(msg_data["timestamp"]),
                    metadata=msg_data.get("metadata", {})
                )
                messages.append(msg)
            
            return ContextWindow(
                window_id=parsed["window_id"],
                max_tokens=parsed["max_tokens"],
                max_messages=parsed["max_messages"],
                strategy=WindowStrategy[parsed["strategy"].upper()],
                messages=messages,
                total_tokens=parsed.get("total_tokens", 0)
            )
        except Exception as e:
            logger.error(f"Deserialization error: {e}")
            return None


def create_message(role: MessageRole, content: str, metadata: Optional[Dict[str, Any]] = None) -> Message:
    return Message(role=role, content=content, metadata=metadata or {})


_default_window_manager: Optional[ContextWindowManager] = None


def get_default_window_manager() -> ContextWindowManager:
    global _default_window_manager
    
    if _default_window_manager is None:
        _default_window_manager = ContextWindowManager()
        
    return _default_window_manager


def add_message_to_window(window_id: str, role: MessageRole, content: str) -> bool:
    message = create_message(role, content)
    return get_default_window_manager().add_message(window_id, message)


def get_window_context(window_id: str) -> str:
    return get_default_window_manager().get_context(window_id)


def get_window_stats() -> Dict[str, Any]:
    return get_default_window_manager().get_stats()