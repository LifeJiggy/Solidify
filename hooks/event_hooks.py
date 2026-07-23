"""
Solidify Event Hooks
Event-driven hooks for smart contract security analysis pipeline

Author: Peace Stephen (Tech Lead)
Description: Event hooks for security analysis events
"""

import re
import logging
import json
import asyncio
import traceback
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
from copy import deepcopy

logger = logging.getLogger(__name__)


class EventType(Enum):
    ANALYSIS_START = "analysis_start"
    ANALYSIS_COMPLETE = "analysis_complete"
    ANALYSIS_ERROR = "analysis_error"
    FINDING_DETECTED = "finding_detected"
    FINDING_RESOLVED = "finding_resolved"
    TRANSFORMATION_START = "transformation_start"
    TRANSFORMATION_COMPLETE = "transformation_complete"
    TRANSFORMATION_ERROR = "transformation_error"
    HOOK_REGISTERED = "hook_registered"
    HOOK_EXECUTED = "hook_executed"
    HOOK_FAILED = "hook_failed"
    VALIDATION_START = "validation_start"
    VALIDATION_COMPLETE = "validation_complete"
    VALIDATION_FAILED = "validation_failed"
    REPORT_GENERATED = "report_generated"
    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    CONFIG_LOADED = "config_loaded"
    CONFIG_UPDATED = "config_updated"
    SOURCE_PARSED = "source_parsed"
    SOURCE_LOADED = "source_loaded"


class EventPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class EventStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Event:
    event_type: EventType
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    priority: EventPriority = EventPriority.NORMAL
    status: EventStatus = EventStatus.PENDING
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EventHandler:
    name: str
    handler_func: Callable
    event_types: Set[EventType] = field(default_factory=set)
    priority: int = 0
    enabled: bool = True
    filter_func: Optional[Callable] = None
    max_retries: int = 3
    timeout: float = 30.0


@dataclass
class EventSubscription:
    handler: EventHandler
    events_received: int = 0
    events_processed: int = 0
    last_event: Optional[Event] = None
    last_error: Optional[str] = None


class BaseEventHandler(ABC):
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.events_received = 0
        self.events_processed = 0
        self.events_failed = 0
        
    @abstractmethod
    async def handle(self, event: Event) -> None:
        pass
    
    def validate(self, event: Event) -> bool:
        return True
        
    def before_handle(self, event: Event) -> None:
        self.events_received += 1
        
    def after_handle(self, event: Event, success: bool) -> None:
        if success:
            self.events_processed += 1
        else:
            self.events_failed += 1
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "events_failed": self.events_failed,
            "success_rate": self.events_processed / max(1, self.events_received)
        }


class LoggingEventHandler(BaseEventHandler):
    def __init__(self, name: str = "logging_handler"):
        super().__init__(name)
        self.logs: List[Dict[str, Any]] = []
        
    async def handle(self, event: Event) -> None:
        log_entry = {
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "data": event.data,
            "priority": event.priority.value
        }
        
        self.logs.append(log_entry)
        logger.info(f"Event: {event.event_type.value} from {event.source}")


class AnalysisEventHandler(BaseEventHandler):
    def __init__(self, name: str = "analysis_handler"):
        super().__init__(name)
        self.findings: List[Dict[str, Any]] = []
        
    async def handle(self, event: Event) -> None:
        if event.event_type == EventType.FINDING_DETECTED:
            self.findings.append(event.data)
            logger.info(f"Finding detected: {event.data.get('description', 'unknown')}")


class TransformEventHandler(BaseEventHandler):
    def __init__(self, name: str = "transform_handler"):
        super().__init__(name)
        self.transformations: List[Dict[str, Any]] = []
        
    async def handle(self, event: Event) -> None:
        if event.event_type == EventType.TRANSFORMATION_COMPLETE:
            self.transformations.append(event.data)
            logger.info(f"Transformation complete: {event.data.get('transform_type', 'unknown')}")


class ValidationEventHandler(BaseEventHandler):
    def __init__(self, name: str = "validation_handler"):
        super().__init__(name)
        self.validation_results: Dict[str, Any] = {}
        
    async def handle(self, event: Event) -> None:
        if event.event_type == EventType.VALIDATION_COMPLETE:
            self.validation_results.update(event.data)


class ReportEventHandler(BaseEventHandler):
    def __init__(self, name: str = "report_handler"):
        super().__init__(name)
        self.reports: List[Dict[str, Any]] = []
        
    async def handle(self, event: Event) -> None:
        if event.event_type == EventType.REPORT_GENERATED:
            self.reports.append(event.data)


class ErrorEventHandler(BaseEventHandler):
    def __init__(self, name: str = "error_handler"):
        super().__init__(name)
        self.errors: List[Dict[str, Any]] = []
        
    async def handle(self, event: Event) -> None:
        if event.event_type in [EventType.ANALYSIS_ERROR, EventType.TRANSFORMATION_ERROR]:
            error_entry = {
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "error": event.data.get("error"),
                "stack_trace": event.data.get("stack_trace")
            }
            self.errors.append(error_entry)
            logger.error(f"Error event: {event.data.get('error')}")


class EventBus:
    def __init__(self):
        self.handlers: Dict[str, EventHandler] = {}
        self.subscriptions: Dict[EventType, List[EventSubscription]] = defaultdict(list)
        self.event_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.event_history: List[Event] = []
        self.max_history = 1000
        
    def subscribe(
        self,
        handler_func: Callable,
        event_types: List[EventType],
        name: Optional[str] = None,
        priority: int = 0,
        filter_func: Optional[Callable] = None
    ) -> str:
        handler_name = name or f"handler_{len(self.handlers)}"
        
        handler = EventHandler(
            name=handler_name,
            handler_func=handler_func,
            event_types=set(event_types),
            priority=priority,
            filter_func=filter_func
        )
        
        self.handlers[handler_name] = handler
        
        for event_type in event_types:
            self.subscriptions[event_type].append(
                EventSubscription(handler=handler)
            )
            
        logger.info(f"Subscribed {handler_name} to {[e.value for e in event_types]}")
        
        return handler_name
        
    def unsubscribe(self, handler_name: str) -> bool:
        if handler_name not in self.handlers:
            return False
            
        handler = self.handlers[handler_name]
        
        for event_type in handler.event_types:
            if event_type in self.subscriptions:
                self.subscriptions[event_type] = [
                    sub for sub in self.subscriptions[event_type]
                    if sub.handler.name != handler_name
                ]
                
        del self.handlers[handler_name]
        
        return True
        
    async def emit(self, event: Event) -> None:
        self.event_history.append(event)
        
        if len(self.event_history) > self.max_history:
            self.event_history.pop(0)
            
        if event.event_type in self.subscriptions:
            for subscription in self.subscriptions[event.event_type]:
                if not subscription.handler.enabled:
                    continue
                    
                if subscription.handler.filter_func:
                    if not subscription.handler.filter_func(event):
                        continue
                        
                subscription.events_received += 1
                
                try:
                    if asyncio.iscoroutinefunction(subscription.handler.handler_func):
                        await subscription.handler.handler_func(event)
                    else:
                        subscription.handler.handler_func(event)
                        
                    subscription.events_processed += 1
                    subscription.last_event = event
                    
                except Exception as e:
                    subscription.events_failed += 1
                    subscription.last_error = str(e)
                    logger.error(f"Handler error: {e}")
                    
    def emit_sync(self, event: Event) -> None:
        self.event_history.append(event)
        
        if event.event_type in self.subscriptions:
            for subscription in self.subscriptions[event.event_type]:
                if not subscription.handler.enabled:
                    continue
                    
                try:
                    subscription.handler.handler_func(event)
                    subscription.events_processed += 1
                    subscription.last_event = event
                    
                except Exception as e:
                    subscription.events_failed += 1
                    subscription.last_error = str(e)
                    
    def get_handlers(self, event_type: EventType) -> List[EventHandler]:
        if event_type not in self.subscriptions:
            return []
            
        return [sub.handler for sub in self.subscriptions[event_type]]
        
    def get_stats(self) -> Dict[str, Any]:
        handler_stats = []
        
        for handler in self.handlers.values():
            events_for_handler = sum(
                len([s for s in self.subscriptions[et] if s.handler.name == handler.name])
                for et in self.subscriptions
            )
            
            handler_stats.append({
                "name": handler.name,
                "event_types": [e.value for e in handler.event_types],
                "enabled": handler.enabled,
                "priority": handler.priority
            })
            
        return {
            "total_handlers": len(self.handlers),
            "total_subscriptions": sum(len(subs) for subs in self.subscriptions.values()),
            "handlers": handler_stats
        }


class EventEmitter:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.session_events: Dict[str, List[Event]] = defaultdict(list)
        
    def emit_analysis_start(
        self,
        file_path: str,
        session_id: Optional[str] = None
    ) -> Event:
        event = Event(
            event_type=EventType.ANALYSIS_START,
            source=file_path,
            data={"file_path": file_path},
            session_id=session_id
        )
        
        self.event_bus.emit_sync(event)
        
        if session_id:
            self.session_events[session_id].append(event)
            
        return event
        
    def emit_analysis_complete(
        self,
        file_path: str,
        findings: List[Dict[str, Any]],
        session_id: Optional[str] = None
    ) -> Event:
        event = Event(
            event_type=EventType.ANALYSIS_COMPLETE,
            source=file_path,
            data={
                "file_path": file_path,
                "findings_count": len(findings),
                "findings": findings
            },
            session_id=session_id
        )
        
        self.event_bus.emit_sync(event)
        
        if session_id:
            self.session_events[session_id].append(event)
            
        return event
        
    def emit_finding_detected(
        self,
        finding: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> Event:
        event = Event(
            event_type=EventType.FINDING_DETECTED,
            source=finding.get("file", ""),
            data=finding,
            session_id=session_id
        )
        
        self.event_bus.emit_sync(event)
        
        if session_id:
            self.session_events[session_id].append(event)
            
        return event
        
    def emit_transformation_start(
        self,
        transform_type: str,
        input_data: Any,
        session_id: Optional[str] = None
    ) -> Event:
        event = Event(
            event_type=EventType.TRANSFORMATION_START,
            source=transform_type,
            data={
                "transform_type": transform_type,
                "input": str(input_data)[:100]
            },
            session_id=session_id
        )
        
        self.event_bus.emit_sync(event)
        
        if session_id:
            self.session_events[session_id].append(event)
            
        return event
        
    def emit_transformation_complete(
        self,
        transform_type: str,
        output_data: Any,
        session_id: Optional[str] = None
    ) -> Event:
        event = Event(
            event_type=EventType.TRANSFORMATION_COMPLETE,
            source=transform_type,
            data={
                "transform_type": transform_type,
                "output": str(output_data)[:100]
            },
            session_id=session_id
        )
        
        self.event_bus.emit_sync(event)
        
        if session_id:
            self.session_events[session_id].append(event)
            
        return event
        
    def emit_error(
        self,
        error: Exception,
        context: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> Event:
        event = Event(
            event_type=EventType.ANALYSIS_ERROR,
            source=context.get("file_path", "unknown"),
            data={
                "error": str(error),
                "stack_trace": traceback.format_exc(),
                "context": context
            },
            session_id=session_id
        )
        
        self.event_bus.emit_sync(event)
        
        if session_id:
            self.session_events[session_id].append(event)
            
        return event
        
    def get_session_events(self, session_id: str) -> List[Event]:
        return self.session_events.get(session_id, [])


class EventProcessor:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.processors: Dict[EventType, Callable] = {}
        self.running = False
        
    def register_processor(
        self,
        event_type: EventType,
        processor: Callable
    ) -> None:
        self.processors[event_type] = processor
        logger.info(f"Registered processor for {event_type.value}")
        
    async def process_events(self) -> None:
        self.running = True
        
        while self.running:
            try:
                event = await asyncio.wait_for(
                    self.event_bus.event_queue.get(),
                    timeout=1.0
                )
                
                if event.event_type in self.processors:
                    processor = self.processors[event.event_type]
                    
                    if asyncio.iscoroutinefunction(processor):
                        await processor(event)
                    else:
                        processor(event)
                        
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Event processing error: {e}")
                
    def stop(self) -> None:
        self.running = False
        
    def enqueue(self, event: Event) -> None:
        priority = event.priority.value
        self.event_bus.event_queue.put_nowait((priority, event))


class EventAggregator:
    def __init__(self):
        self.aggregates: Dict[str, List[Event]] = defaultdict(list)
        
    def add(self, event: Event) -> None:
        key = f"{event.event_type.value}:{event.session_id or 'global'}"
        self.aggregates[key].append(event)
        
    def get_events(
        self,
        event_type: Optional[EventType] = None,
        session_id: Optional[str] = None
    ) -> List[Event]:
        if event_type and session_id:
            key = f"{event_type.value}:{session_id}"
            return self.aggregates.get(key, [])
        elif event_type:
            return [
                event for key, events in self.aggregates.items()
                for event in events
                if event.event_type == event_type
            ]
        elif session_id:
            return self.aggregates.get(f"*:{session_id}", [])
        else:
            return [event for events in self.aggregates.values() for event in events]
            
    def get_stats(self) -> Dict[str, Any]:
        event_counts = Counter(
            event.event_type.value for events in self.aggregates.values()
            for event in events
        )
        
        return {
            "total_events": sum(len(events) for events in self.aggregates.values()),
            "event_types": dict(event_counts),
            "sessions": len(set(k.split(":")[1] for k in self.aggregates.keys() if ":" in k))
        }


def create_event_handler(
    name: str,
    handler_func: Callable,
    event_types: List[EventType]
) -> EventHandler:
    return EventHandler(
        name=name,
        handler_func=handler_func,
        event_types=set(event_types)
    )


_default_event_bus: Optional[EventBus] = None
_default_emitter: Optional[EventEmitter] = None


def get_default_event_bus() -> EventBus:
    global _default_event_bus
    
    if _default_event_bus is None:
        _default_event_bus = EventBus()
        
    return _default_event_bus


def get_default_emitter() -> EventEmitter:
    global _default_emitter
    
    if _default_emitter is None:
        _default_emitter = EventEmitter(get_default_event_bus())
        
    return _default_emitter


def emit_finding(finding: Dict[str, Any], session_id: Optional[str] = None) -> Event:
    emitter = get_default_emitter()
    return emitter.emit_finding_detected(finding, session_id)


def emit_analysis(
    file_path: str,
    findings: List[Dict[str, Any]],
    session_id: Optional[str] = None
) -> Event:
    emitter = get_default_emitter()
    return emitter.emit_analysis_complete(file_path, findings, session_id)


def emit_error(
    error: Exception,
    context: Dict[str, Any],
    session_id: Optional[str] = None
) -> Event:
    emitter = get_default_emitter()
    return emitter.emit_error(error, context, session_id)


def subscribe_handler(
    handler_func: Callable,
    event_types: List[EventType],
    name: Optional[str] = None
) -> str:
    event_bus = get_default_event_bus()
    return event_bus.subscribe(handler_func, event_types, name)


def unsubscribe_handler(handler_name: str) -> bool:
    event_bus = get_default_event_bus()
    return event_bus.unsubscribe(handler_name)


def handle_logging(event: Event) -> None:
    logger.info(f"Event: {event.event_type.value} - {event.data}")


def handle_analysis(event: Event) -> None:
    if event.event_type == EventType.ANALYSIS_COMPLETE:
        findings = event.data.get("findings", [])
        logger.info(f"Analysis complete: {len(findings)} findings")


def handle_error(event: Event) -> None:
    if event.event_type in [EventType.ANALYSIS_ERROR]:
        logger.error(f"Error: {event.data.get('error')}")


def initialize_event_handlers() -> None:
    event_bus = get_default_event_bus()
    
    event_bus.subscribe(handle_logging, [EventType.ANALYSIS_START], "logging")
    event_bus.subscribe(handle_logging, [EventType.ANALYSIS_COMPLETE], "logging")
    event_bus.subscribe(handle_analysis, [EventType.FINDING_DETECTED], "analysis")
    event_bus.subscribe(handle_error, [EventType.ANALYSIS_ERROR], "error")