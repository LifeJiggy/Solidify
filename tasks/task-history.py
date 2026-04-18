"""
Task History Module for Solidify Security Scanner

This module provides comprehensive task history tracking, persistence, and analytics
for the security scanning workflow. Maintains complete audit trail of all scan
operations, results, and state changes for compliance and debugging purposes.

Author: Solidify Security Team
Version: 1.0.0
"""

import json
import sqlite3
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, deque
from pathlib import Path
import logging
import pickle
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    PAUSED = "paused"
    RETRY = "retry"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    IDLE = 1


class HistoryEventType(Enum):
    """Types of history events"""
    TASK_CREATED = "task_created"
    TASK_STARTED = "task_started"
    TASK_PROGRESS = "task_progress"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    TASK_RETRY = "task_retry"
    TASK_PAUSED = "task_paused"
    TASK_RESUMED = "task_resumed"
    RESULT_GENERATED = "result_generated"
    SCAN_PERFORMED = "scan_performed"
    VULNERABILITY_FOUND = "vulnerability_found"
    RULE_TRIGGERED = "rule_triggerED"
    STATE_CHANGED = "state_changed"
    USER_ACTION = "user_action"


class TaskState(Enum):
    """Task lifecycle states"""
    CREATED = "created"
    QUEUED = "queued"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskHistoryEntry:
    """Represents a single task history entry"""
    entry_id: str
    task_id: str
    event_type: HistoryEventType
    timestamp: float
    status: TaskStatus
    progress: float
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration: Optional[float] = None
    error: Optional[str] = None
    stack_trace: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'entry_id': self.entry_id,
            'task_id': self.task_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp,
            'status': self.status.value,
            'progress': self.progress,
            'message': self.message,
            'metadata': self.metadata,
            'duration': self.duration,
            'error': self.error,
            'stack_trace': self.stack_trace
        }


@dataclass
class TaskSnapshot:
    """Represents a point-in-time task snapshot"""
    snapshot_id: str
    task_id: str
    task_type: str
    task_name: str
    status: TaskStatus
    priority: TaskPriority
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress: float = 0.0
    result: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'snapshot_id': self.snapshot_id,
            'task_id': self.task_id,
            'task_type': self.task_type,
            'task_name': self.task_name,
            'status': self.status.value,
            'priority': self.priority.value,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'progress': self.progress,
            'result': self.result,
            'error': self.error,
            'metadata': self.metadata,
            'tags': self.tags,
            'dependencies': self.dependencies
        }
    
    def duration(self) -> Optional[float]:
        """Calculate task duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        elif self.started_at:
            return time.time() - self.started_at
        return None


@dataclass
class ScanRecord:
    """Record of a security scan operation"""
    scan_id: str
    task_id: str
    contract_name: str
    contract_address: Optional[str]
    scan_type: str
    rules_applied: List[str]
    vulnerabilities_found: int
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    scan_duration: float
    timestamp: float
    result_hash: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'task_id': self.task_id,
            'contract_name': self.contract_name,
            'contract_address': self.contract_address,
            'scan_type': self.scan_type,
            'rules_applied': self.rules_applied,
            'vulnerabilities_found': self.vulnerabilities_found,
            'severity_breakdown': self.severity_breakdown,
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp,
            'result_hash': self.result_hash,
            'metadata': self.metadata
        }


@dataclass
class VulnerabilityRecord:
    """Record of a detected vulnerability"""
    vuln_id: str
    scan_id: str
    task_id: str
    rule_id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    cwe_id: str
    timestamp: float
    line_number: Optional[int] = field(default=None)
    code_snippet: Optional[str] = field(default=None)
    recommendation: Optional[str] = field(default=None)
    false_positive: bool = field(default=False)
    verified: bool = field(default=False)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'scan_id': self.scan_id,
            'task_id': self.task_id,
            'rule_id': self.rule_id,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'cwe_id': self.cwe_id,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'recommendation': self.recommendation,
            'false_positive': self.false_positive,
            'verified': self.verified,
            'timestamp': self.timestamp
        }


class DatabaseManager:
    """Manages SQLite database for task history"""
    
    def __init__(self, db_path: str = "task_history.db"):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.lock = threading.Lock()
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Initialize database schema"""
        with self.lock:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS task_history (
                    entry_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    progress REAL DEFAULT 0,
                    message TEXT,
                    metadata TEXT,
                    duration REAL,
                    error TEXT,
                    stack_trace TEXT
                )
            ''')
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS task_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    task_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL,
                    progress REAL DEFAULT 0,
                    result TEXT,
                    error TEXT,
                    metadata TEXT,
                    tags TEXT,
                    dependencies TEXT
                )
            ''')
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS scan_records (
                    scan_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    contract_address TEXT,
                    scan_type TEXT NOT NULL,
                    rules_applied TEXT NOT NULL,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    severity_breakdown TEXT,
                    scan_duration REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    result_hash TEXT NOT NULL,
                    metadata TEXT
                )
            ''')
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_records (
                    vuln_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    cwe_id TEXT,
                    line_number INTEGER,
                    code_snippet TEXT,
                    recommendation TEXT,
                    false_positive INTEGER DEFAULT 0,
                    verified INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            ''')
            self.connection.execute('CREATE INDEX IF NOT EXISTS idx_task_id ON task_history(task_id)')
            self.connection.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON task_history(timestamp)')
            self.connection.execute('CREATE INDEX IF NOT EXISTS idx_status ON task_snapshots(status)')
            self.connection.execute('CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_records(scan_id)')
            self.connection.commit()
    
    def insert_history_entry(self, entry: TaskHistoryEntry) -> bool:
        """Insert a history entry"""
        try:
            with self.lock:
                self.connection.execute('''
                    INSERT OR REPLACE INTO task_history 
                    (entry_id, task_id, event_type, timestamp, status, progress, message, metadata, duration, error, stack_trace)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.entry_id,
                    entry.task_id,
                    entry.event_type.value,
                    entry.timestamp,
                    entry.status.value,
                    entry.progress,
                    entry.message,
                    json.dumps(entry.metadata),
                    entry.duration,
                    entry.error,
                    entry.stack_trace
                ))
                self.connection.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to insert history entry: {e}")
            return False
    
    def insert_snapshot(self, snapshot: TaskSnapshot) -> bool:
        """Insert a task snapshot"""
        try:
            with self.lock:
                self.connection.execute('''
                    INSERT OR REPLACE INTO task_snapshots
                    (snapshot_id, task_id, task_type, task_name, status, priority, 
                     created_at, started_at, completed_at, progress, result, error, metadata, tags, dependencies)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    snapshot.snapshot_id,
                    snapshot.task_id,
                    snapshot.task_type,
                    snapshot.task_name,
                    snapshot.status.value,
                    snapshot.priority.value,
                    snapshot.created_at,
                    snapshot.started_at,
                    snapshot.completed_at,
                    snapshot.progress,
                    snapshot.result,
                    snapshot.error,
                    json.dumps(snapshot.metadata),
                    json.dumps(snapshot.tags),
                    json.dumps(snapshot.dependencies)
                ))
                self.connection.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to insert snapshot: {e}")
            return False
    
    def insert_scan_record(self, record: ScanRecord) -> bool:
        """Insert a scan record"""
        try:
            with self.lock:
                self.connection.execute('''
                    INSERT OR REPLACE INTO scan_records
                    (scan_id, task_id, contract_name, contract_address, scan_type, rules_applied,
                     vulnerabilities_found, severity_breakdown, scan_duration, timestamp, result_hash, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.scan_id,
                    record.task_id,
                    record.contract_name,
                    record.contract_address,
                    record.scan_type,
                    json.dumps(record.rules_applied),
                    record.vulnerabilities_found,
                    json.dumps(record.severity_breakdown),
                    record.scan_duration,
                    record.timestamp,
                    record.result_hash,
                    json.dumps(record.metadata)
                ))
                self.connection.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to insert scan record: {e}")
            return False
    
    def insert_vulnerability(self, vuln: VulnerabilityRecord) -> bool:
        """Insert a vulnerability record"""
        try:
            with self.lock:
                self.connection.execute('''
                    INSERT OR REPLACE INTO vulnerability_records
                    (vuln_id, scan_id, task_id, rule_id, vulnerability_type, severity,
                     title, description, cwe_id, line_number, code_snippet, recommendation,
                     false_positive, verified, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln.vuln_id,
                    vuln.scan_id,
                    vuln.task_id,
                    vuln.rule_id,
                    vuln.vulnerability_type,
                    vuln.severity,
                    vuln.title,
                    vuln.description,
                    vuln.cwe_id,
                    vuln.line_number,
                    vuln.code_snippet,
                    vuln.recommendation,
                    1 if vuln.false_positive else 0,
                    1 if vuln.verified else 0,
                    vuln.timestamp
                ))
                self.connection.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to insert vulnerability: {e}")
            return False
    
    def get_task_history(self, task_id: str, limit: int = 100) -> List[TaskHistoryEntry]:
        """Get history for a specific task"""
        try:
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT * FROM task_history 
                    WHERE task_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (task_id, limit))
                rows = cursor.fetchall()
                return [self._row_to_history_entry(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get task history: {e}")
            return []
    
    def get_task_snapshots(self, task_id: str) -> List[TaskSnapshot]:
        """Get snapshots for a task"""
        try:
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT * FROM task_snapshots 
                    WHERE task_id = ? 
                    ORDER BY created_at DESC
                ''', (task_id,))
                rows = cursor.fetchall()
                return [self._row_to_snapshot(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get snapshots: {e}")
            return []
    
    def get_scan_records(self, task_id: str) -> List[ScanRecord]:
        """Get scan records for a task"""
        try:
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT * FROM scan_records 
                    WHERE task_id = ? 
                    ORDER BY timestamp DESC
                ''', (task_id,))
                rows = cursor.fetchall()
                return [self._row_to_scan_record(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get scan records: {e}")
            return []
    
    def get_vulnerabilities(self, scan_id: str) -> List[VulnerabilityRecord]:
        """Get vulnerabilities for a scan"""
        try:
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT * FROM vulnerability_records 
                    WHERE scan_id = ?
                    ORDER BY severity DESC, timestamp DESC
                ''', (scan_id,))
                rows = cursor.fetchall()
                return [self._row_to_vulnerability(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []
    
    def get_recent_tasks(self, hours: int = 24, limit: int = 100) -> List[TaskSnapshot]:
        """Get recent tasks"""
        try:
            cutoff = time.time() - (hours * 3600)
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT * FROM task_snapshots 
                    WHERE created_at > ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (cutoff, limit))
                rows = cursor.fetchall()
                return [self._row_to_snapshot(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get recent tasks: {e}")
            return []
    
    def get_failed_tasks(self, hours: int = 24) -> List[TaskSnapshot]:
        """Get failed tasks"""
        try:
            cutoff = time.time() - (hours * 3600)
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT * FROM task_snapshots 
                    WHERE status = ? AND created_at > ?
                    ORDER BY created_at DESC
                ''', ('failed', cutoff))
                rows = cursor.fetchall()
                return [self._row_to_snapshot(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get failed tasks: {e}")
            return []
    
    def get_task_statistics(self) -> Dict[str, Any]:
        """Get task statistics"""
        try:
            with self.lock:
                cursor = self.connection.execute('''
                    SELECT status, COUNT(*) as count 
                    FROM task_snapshots 
                    GROUP BY status
                ''')
                status_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                cursor = self.connection.execute('''
                    SELECT COUNT(*) FROM vulnerability_records 
                    WHERE false_positive = 0
                ''')
                total_vulns = cursor.fetchone()[0]
                
                cursor = self.connection.execute('''
                    SELECT severity, COUNT(*) 
                    FROM vulnerability_records 
                    WHERE false_positive = 0
                    GROUP BY severity
                ''')
                severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                return {
                    'status_counts': status_counts,
                    'total_vulnerabilities': total_vulns,
                    'severity_breakdown': severity_counts
                }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _row_to_history_entry(self, row: tuple) -> TaskHistoryEntry:
        """Convert database row to history entry"""
        return TaskHistoryEntry(
            entry_id=row[0],
            task_id=row[1],
            event_type=HistoryEventType(row[2]),
            timestamp=row[3],
            status=TaskStatus(row[4]),
            progress=row[5],
            message=row[6],
            metadata=json.loads(row[7]) if row[7] else {},
            duration=row[8],
            error=row[9],
            stack_trace=row[10]
        )
    
    def _row_to_snapshot(self, row: tuple) -> TaskSnapshot:
        """Convert database row to snapshot"""
        return TaskSnapshot(
            snapshot_id=row[0],
            task_id=row[1],
            task_type=row[2],
            task_name=row[3],
            status=TaskStatus(row[4]),
            priority=TaskPriority(row[5]),
            created_at=row[6],
            started_at=row[7],
            completed_at=row[8],
            progress=row[9],
            result=row[10],
            error=row[11],
            metadata=json.loads(row[12]) if row[12] else {},
            tags=json.loads(row[13]) if row[13] else [],
            dependencies=json.loads(row[14]) if row[14] else []
        )
    
    def _row_to_scan_record(self, row: tuple) -> ScanRecord:
        """Convert database row to scan record"""
        return ScanRecord(
            scan_id=row[0],
            task_id=row[1],
            contract_name=row[2],
            contract_address=row[3],
            scan_type=row[4],
            rules_applied=json.loads(row[5]),
            vulnerabilities_found=row[6],
            severity_breakdown=json.loads(row[7]) if row[7] else {},
            scan_duration=row[8],
            timestamp=row[9],
            result_hash=row[10],
            metadata=json.loads(row[11]) if row[11] else {}
        )
    
    def _row_to_vulnerability(self, row: tuple) -> VulnerabilityRecord:
        """Convert database row to vulnerability"""
        return VulnerabilityRecord(
            vuln_id=row[0],
            scan_id=row[1],
            task_id=row[2],
            rule_id=row[3],
            vulnerability_type=row[4],
            severity=row[5],
            title=row[6],
            description=row[7],
            cwe_id=row[8],
            line_number=row[9],
            code_snippet=row[10],
            recommendation=row[11],
            false_positive=bool(row[12]),
            verified=bool(row[13]),
            timestamp=row[14]
        )
    
    def close(self) -> None:
        """Close database connection"""
        if self.connection:
            self.connection.close()
    
    def export_to_json(self, filepath: str) -> bool:
        """Export all history to JSON file"""
        try:
            data = {
                'snapshots': self.get_task_snapshots(''),
                'statistics': self.get_task_statistics()
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export: {e}")
            return False


class TaskHistoryManager:
    """Manages task history tracking"""
    
    def __init__(self, db_path: str = "task_history.db"):
        self.db = DatabaseManager(db_path)
        self.current_task_id: Optional[str] = None
        self.entry_counter = 0
    
    def start_task(self, task_id: str, task_type: str, task_name: str,
                priority: TaskPriority = TaskPriority.MEDIUM) -> None:
        """Record task start"""
        self.current_task_id = task_id
        snapshot = TaskSnapshot(
            snapshot_id=self._generate_id(),
            task_id=task_id,
            task_type=task_type,
            task_name=task_name,
            status=TaskStatus.PENDING,
            priority=priority,
            created_at=time.time()
        )
        self.db.insert_snapshot(snapshot)
        self._add_entry(task_id, HistoryEventType.TASK_CREATED, 
                      TaskStatus.PENDING, 0, f"Task {task_name} created")
    
    def start_execution(self, task_id: str) -> None:
        """Record execution start"""
        self._update_snapshot(task_id, TaskStatus.RUNNING, started_at=time.time())
        self._add_entry(task_id, HistoryEventType.TASK_STARTED,
                      TaskStatus.RUNNING, 0, "Task execution started")
    
    def update_progress(self, task_id: str, progress: float, message: str = "") -> None:
        """Update task progress"""
        self._add_entry(task_id, HistoryEventType.TASK_PROGRESS,
                      TaskStatus.RUNNING, progress, message)
    
    def complete_task(self, task_id: str, result: Optional[str] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> None:
        """Record task completion"""
        self._update_snapshot(task_id, TaskStatus.COMPLETED,
                          completed_at=time.time(), progress=100.0)
        self._add_entry(task_id, HistoryEventType.TASK_COMPLETED,
                      TaskStatus.COMPLETED, 100.0, "Task completed successfully")
    
    def fail_task(self, task_id: str, error: str,
                stack_trace: Optional[str] = None) -> None:
        """Record task failure"""
        self._update_snapshot(task_id, TaskStatus.FAILED,
                          error=error)
        self._add_entry(task_id, HistoryEventType.TASK_FAILED,
                      TaskStatus.FAILED, 0, "Task failed", error, stack_trace)
    
    def cancel_task(self, task_id: str) -> None:
        """Record task cancellation"""
        self._update_snapshot(task_id, TaskStatus.CANCELLED)
        self._add_entry(task_id, HistoryEventType.TASK_CANCELLED,
                      TaskStatus.CANCELLED, 0, "Task cancelled")
    
    def retry_task(self, task_id: str, attempt: int) -> None:
        """Record task retry"""
        self._add_entry(task_id, HistoryEventType.TASK_RETRY,
                      TaskStatus.RETRY, 0, f"Retry attempt {attempt}")
    
    def record_scan(self, scan: ScanRecord) -> None:
        """Record a scan operation"""
        self.db.insert_scan_record(scan)
        self._add_entry(scan.task_id, HistoryEventType.SCAN_PERFORMED,
                      TaskStatus.COMPLETED, 100.0,
                      f"Found {scan.vulnerabilities_found} vulnerabilities")
    
    def record_vulnerability(self, vuln: VulnerabilityRecord) -> None:
        """Record a detected vulnerability"""
        self.db.insert_vulnerability(vuln)
    
    def get_task_history(self, task_id: str) -> List[Dict[str, Any]]:
        """Get task history"""
        entries = self.db.get_task_history(task_id)
        return [e.to_dict() for e in entries]
    
    def get_task_timeline(self, task_id: str) -> List[Dict[str, Any]]:
        """Get task timeline"""
        snapshots = self.db.get_task_snapshots(task_id)
        return [s.to_dict() for s in snapshots]
    
    def get_scan_results(self, task_id: str) -> List[Dict[str, Any]]:
        """Get scan results"""
        records = self.db.get_scan_records(task_id)
        return [r.to_dict() for r in records]
    
    def get_vulnerability_history(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get vulnerability history"""
        vulns = self.db.get_vulnerabilities(scan_id)
        return [v.to_dict() for v in vulns]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        return self.db.get_task_statistics()
    
    def get_failed_scans(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get failed scans"""
        tasks = self.db.get_failed_tasks(hours)
        return [t.to_dict() for t in tasks]
    
    def _add_entry(self, task_id: str, event_type: HistoryEventType,
                  status: TaskStatus, progress: float, message: str,
                  error: Optional[str] = None,
                  stack_trace: Optional[str] = None) -> None:
        """Add a history entry"""
        self.entry_counter += 1
        entry = TaskHistoryEntry(
            entry_id=f"{task_id}_{self.entry_counter}",
            task_id=task_id,
            event_type=event_type,
            timestamp=time.time(),
            status=status,
            progress=progress,
            message=message,
            error=error,
            stack_trace=stack_trace
        )
        self.db.insert_history_entry(entry)
    
    def _update_snapshot(self, task_id: str, status: TaskStatus,
                      started_at: Optional[float] = None,
                      completed_at: Optional[float] = None,
                      progress: float = 0.0,
                      error: Optional[str] = None) -> None:
        """Update task snapshot"""
        snapshots = self.db.get_task_snapshots(task_id)
        if snapshots:
            snapshot = snapshots[0]
            snapshot.status = status
            if started_at:
                snapshot.started_at = started_at
            if completed_at:
                snapshot.completed_at = completed_at
            if progress:
                snapshot.progress = progress
            if error:
                snapshot.error = error
            self.db.insert_snapshot(snapshot)
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]


class HistoryAnalyzer:
    """Analyzes task history for patterns and insights"""
    
    def __init__(self, manager: TaskHistoryManager):
        self.manager = manager
    
    def analyze_failure_patterns(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze common failure patterns"""
        failed_tasks = self.manager.get_failed_scans(hours)
        
        error_types = defaultdict(int)
        for task in failed_tasks:
            if task.get('error'):
                error_msg = task['error'][:50]
                error_types[error_msg] += 1
        
        return {
            'total_failures': len(failed_tasks),
            'error_patterns': dict(error_types),
            'recommendations': self._generate_recommendations(error_types)
        }
    
    def analyze_performance(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze task performance"""
        stats = self.manager.get_statistics()
        recent = self.manager.db.get_recent_tasks(hours)
        
        durations = []
        for task in recent:
            if task.get('completed_at') and task.get('started_at'):
                duration = task['completed_at'] - task['started_at']
                durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            'total_tasks': len(recent),
            'average_duration': avg_duration,
            'status_distribution': stats.get('status_counts', {})
        }
    
    def analyze_vulnerability_trends(self, days: int = 7) -> Dict[str, Any]:
        """Analyze vulnerability detection trends"""
        stats = self.manager.get_statistics()
        
        return {
            'total_vulnerabilities': stats.get('total_vulnerabilities', 0),
            'severity_distribution': stats.get('severity_breakdown', {})
        }
    
    def _generate_recommendations(self, error_types: Dict[str, int]) -> List[str]:
        """Generate recommendations based on error patterns"""
        recommendations = []
        
        if any('timeout' in e.lower() for e in error_types.keys()):
            recommendations.append("Consider increasing task timeout duration")
        
        if any('memory' in e.lower() for e in error_types.keys()):
            recommendations.append("Review memory usage in task execution")
        
        if any('connection' in e.lower() for e in error_types.keys()):
            recommendations.append("Check network connectivity and API availability")
        
        return recommendations


class HistoryExporter:
    """Exports task history in various formats"""
    
    def __init__(self, manager: TaskHistoryManager):
        self.manager = manager
    
    def export_to_csv(self, filepath: str) -> bool:
        """Export history to CSV"""
        try:
            import csv
            tasks = self.manager.db.get_recent_tasks(hours=168)
            
            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'task_id', 'task_name', 'status', 'created_at', 
                    'completed_at', 'duration', 'error'
                ])
                writer.writeheader()
                
                for task in tasks:
                    writer.writerow({
                        'task_id': task.task_id,
                        'task_name': task.task_name,
                        'status': task.status.value,
                        'created_at': datetime.fromtimestamp(task.created_at).isoformat(),
                        'completed_at': datetime.fromtimestamp(task.completed_at).isoformat() if task.completed_at else '',
                        'duration': task.duration() if task.duration() else '',
                        'error': task.error or ''
                    })
            return True
        except Exception as e:
            logger.error(f"Export to CSV failed: {e}")
            return False
    
    def export_to_json(self, filepath: str) -> bool:
        """Export history to JSON"""
        try:
            stats = self.manager.get_statistics()
            recent_tasks = self.manager.db.get_recent_tasks(hours=168)
            
            data = {
                'export_timestamp': time.time(),
                'statistics': stats,
                'recent_tasks': [t.to_dict() for t in recent_tasks]
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Export to JSON failed: {e}")
            return False
    
    def export_to_html_report(self, filepath: str) -> bool:
        """Generate HTML report"""
        try:
            stats = self.manager.get_statistics()
            failed = self.manager.get_failed_scans(24)
            
            html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Task History Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background: #1a73e8; color: white; padding: 20px; }}
                    .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
                    .stat-box {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
                    .critical {{ color: #d93025; }}
                    .high {{ color: #f29900; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Task History Report</h1>
                    <p>Generated: {datetime.now().isoformat()}</p>
                </div>
                <div class="stats">
                    <div class="stat-box">
                        <h3>Task Statistics</h3>
                        <p>Status: {stats.get('status_counts', {})}</p>
                        <p>Vulnerabilities Found: {stats.get('total_vulnerabilities', 0)}</p>
                    </div>
                </div>
                <h2>Failed Tasks (Last 24h)</h2>
                <table>
                    <tr><th>Task ID</th><th>Error</th><th>Time</th></tr>
            '''
            
            for task in failed:
                html += f'''
                <tr>
                    <td>{task.get('task_id', '')}</td>
                    <td>{task.get('error', 'Unknown')}</td>
                    <td>{task.get('created_at', '')}</td>
                </tr>
                '''
            
            html += '''
                </table>
            </body>
            </html>
            '''
            
            with open(filepath, 'w') as f:
                f.write(html)
            return True
        except Exception as e:
            logger.error(f"Export to HTML failed: {e}")
            return False


_default_history_manager: Optional[TaskHistoryManager] = None


def get_history_manager(db_path: str = "task_history.db") -> TaskHistoryManager:
    """Get or create default history manager"""
    global _default_history_manager
    if _default_history_manager is None:
        _default_history_manager = TaskHistoryManager(db_path)
    return _default_history_manager


def record_task_completion(task_id: str, result: str) -> None:
    """Quick helper to record task completion"""
    manager = get_history_manager()
    manager.complete_task(task_id, result)


def get_task_status(task_id: str) -> Optional[str]:
    """Quick helper to get task status"""
    manager = get_history_manager()
    timeline = manager.get_task_timeline(task_id)
    if timeline:
        return timeline[0].get('status')
    return None


def export_history_report(format: str = "json", filepath: str = "history_report") -> bool:
    """Export history report"""
    manager = get_history_manager()
    exporter = HistoryExporter(manager)
    
    if format == "csv":
        return exporter.export_to_csv(filepath + ".csv")
    elif format == "html":
        return exporter.export_to_html_report(filepath + ".html")
    else:
        return exporter.export_to_json(filepath + ".json")


if __name__ == "__main__":
    manager = get_history_manager()
    
    manager.start_task("test_task_001", "security_scan", "Test Contract Scan", TaskPriority.HIGH)
    manager.update_progress("test_task_001", 50.0, "Scanning...")
    manager.update_progress("test_task_001", 100.0, "Complete")
    manager.complete_task("test_task_001", "Found 3 vulnerabilities")
    
    stats = manager.get_statistics()
    print(json.dumps(stats, indent=2))