"""
Vulnerability Triage Engine Module

This module implements the triage system for categorizing, prioritizing, and 
managing vulnerability findings from the security audit process. It provides
sophisticated algorithms for determining the appropriate response to each finding.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TriageStatus(Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    DUPLICATE = "duplicate"


class TriagePriority(Enum):
    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"
    P4_INFORMATIONAL = "P4_INFORMATIONAL"


class TriageCategory(Enum):
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    FRONT_RUNNING = "front_running"
    FLASH_LOAN = "flash_loan"
    ORACLE = "oracle"
    CENTRALIZATION = "centralization"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    OTHER = "other"


@dataclass
class VulnerabilityRecord:
    vuln_id: str
    title: str
    category: TriageCategory
    priority: TriagePriority
    status: TriageStatus
    severity_score: float
    contract_name: str
    function_name: Optional[str]
    line_number: int
    code_snippet: str
    description: str
    impact: str
    recommendation: str
    cvss_vector: str
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    discovered_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    assignee: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    related_issues: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    false_positive_count: int = 0
    
    def __post_init__(self):
        if not self.vuln_id:
            self.vuln_id = self._generate_id()
    
    def _generate_id(self) -> str:
        data = f"{self.contract_name}:{self.function_name}:{self.line_number}:{time.time()}"
        return f"VULN-{hashlib.md5(data.encode()).hexdigest()[:8].upper()}"
    
    def update_status(self, new_status: TriageStatus):
        self.status = new_status
        self.updated_at = time.time()
    
    def add_note(self, note: str):
        self.notes.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {note}")
        self.updated_at = time.time()
    
    def mark_false_positive(self, reason: str):
        self.false_positive_count += 1
        if self.false_positive_count >= 3:
            self.update_status(TriageStatus.FALSE_POSITIVE)
        self.add_note(f"False positive check: {reason}")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'title': self.title,
            'category': self.category.value,
            'priority': self.priority.value,
            'status': self.status.value,
            'severity_score': self.severity_score,
            'contract_name': self.contract_name,
            'function_name': self.function_name,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet[:200],
            'description': self.description,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'cvss_vector': self.cvss_vector,
            'cwe_id': self.cwe_id,
            'cve_id': self.cve_id,
            'discovered_at': self.discovered_at,
            'updated_at': self.updated_at,
            'assignee': self.assignee,
            'notes': self.notes,
            'related_issues': self.related_issues,
            'tags': self.tags
        }


class TriageRule:
    def __init__(self, rule_id: str, name: str):
        self.rule_id = rule_id
        self.name = name
    
    def evaluate(self, record: VulnerabilityRecord) -> bool:
        return True
    
    def get_action(self) -> Optional[str]:
        return None


class SeverityBasedTriageRule(TriageRule):
    def __init__(self):
        super().__init__("SEVERITY_001", "Severity-based triage")
    
    def evaluate(self, record: VulnerabilityRecord) -> bool:
        return True
    
    def get_action(self) -> Optional[str]:
        return None


class TriageEngine:
    def __init__(self):
        self.records: Dict[str, VulnerabilityRecord] = {}
        self.rules: List[TriageRule] = []
        self.statistics = {
            'total_processed': 0,
            'by_status': Counter(),
            'by_priority': Counter(),
            'by_category': Counter(),
        }
        self.workflow_queue = deque()
    
    def add_rule(self, rule: TriageRule):
        self.rules.append(rule)
        logger.info(f"Added triage rule: {rule.rule_id}")
    
    def process_finding(self, finding: Dict[str, Any]) -> VulnerabilityRecord:
        record = self._create_record(finding)
        
        for rule in self.rules:
            if not rule.evaluate(record):
                continue
        
        self._assign_priority(record)
        self._assign_category(record)
        
        self.records[record.vuln_id] = record
        self.workflow_queue.append(record.vuln_id)
        
        self._update_statistics(record)
        self.statistics['total_processed'] += 1
        
        logger.info(f"Processed finding: {record.vuln_id} - {record.status.value}")
        
        return record
    
    def _create_record(self, finding: Dict[str, Any]) -> VulnerabilityRecord:
        return VulnerabilityRecord(
            vuln_id="",
            title=finding.get('title', 'Untitled Finding'),
            category=TriageCategory.OTHER,
            priority=TriagePriority.P3_LOW,
            status=TriageStatus.NEW,
            severity_score=finding.get('severity_score', 0.0),
            contract_name=finding.get('contract_name', 'Unknown'),
            function_name=finding.get('function_name'),
            line_number=finding.get('line_number', 0),
            code_snippet=finding.get('code_snippet', ''),
            description=finding.get('description', ''),
            impact=finding.get('impact', ''),
            recommendation=finding.get('recommendation', ''),
            cvss_vector=finding.get('cvss_vector', ''),
            cwe_id=finding.get('cwe_id'),
        )
    
    def _assign_priority(self, record: VulnerabilityRecord):
        score = record.severity_score
        
        if score >= 9.0:
            record.priority = TriagePriority.P0_CRITICAL
        elif score >= 7.0:
            record.priority = TriagePriority.P1_HIGH
        elif score >= 5.0:
            record.priority = TriagePriority.P2_MEDIUM
        elif score >= 3.0:
            record.priority = TriagePriority.P3_LOW
        else:
            record.priority = TriagePriority.P4_INFORMATIONAL
    
    def _assign_category(self, record: VulnerabilityRecord):
        desc_lower = record.description.lower()
        title_lower = record.title.lower()
        combined = f"{desc_lower} {title_lower}"
        
        if 'reentrancy' in combined:
            record.category = TriageCategory.REENTRANCY
        elif 'access control' in combined or 'authorization' in combined:
            record.category = TriageCategory.ACCESS_CONTROL
        elif 'overflow' in combined or 'underflow' in combined:
            record.category = TriageCategory.ARITHMETIC
        elif 'front run' in combined or 'mev' in combined:
            record.category = TriageCategory.FRONT_RUNNING
        elif 'flash loan' in combined:
            record.category = TriageCategory.FLASH_LOAN
        elif 'oracle' in combined or 'price' in combined:
            record.category = TriageCategory.ORACLE
        elif 'central' in combined or 'admin' in combined:
            record.category = TriageCategory.CENTRALIZATION
        elif 'dos' in combined or 'denial' in combined:
            record.category = TriageCategory.DENIAL_OF_SERVICE
        else:
            record.category = TriageCategory.OTHER
    
    def _update_statistics(self, record: VulnerabilityRecord):
        self.statistics['by_status'][record.status.value] += 1
        self.statistics['by_priority'][record.priority.value] += 1
        self.statistics['by_category'][record.category.value] += 1
    
    def get_next_in_queue(self) -> Optional[VulnerabilityRecord]:
        if self.workflow_queue:
            vuln_id = self.workflow_queue.popleft()
            return self.records.get(vuln_id)
        return None
    
    def get_by_status(self, status: TriageStatus) -> List[VulnerabilityRecord]:
        return [r for r in self.records.values() if r.status == status]
    
    def get_by_priority(self, priority: TriagePriority) -> List[VulnerabilityRecord]:
        return [r for r in self.records.values() if r.priority == priority]
    
    def get_by_contract(self, contract_name: str) -> List[VulnerabilityRecord]:
        return [r for r in self.records.values() if r.contract_name == contract_name]
    
    def verify_fix(self, vuln_id: str, fixed: bool = True) -> bool:
        record = self.records.get(vuln_id)
        if not record:
            return False
        
        if fixed:
            record.update_status(TriageStatus.MITIGATED)
            record.add_note("Fix verified")
        else:
            record.update_status(TriageStatus.IN_PROGRESS)
            record.add_note("Fix not working")
        
        return True
    
    def accept_risk(self, vuln_id: str, justification: str) -> bool:
        record = self.records.get(vuln_id)
        if not record:
            return False
        
        record.update_status(TriageStatus.ACCEPTED_RISK)
        record.add_note(f"Risk accepted: {justification}")
        return True
    
    def mark_duplicate(self, vuln_id: str, original_id: str) -> bool:
        record = self.records.get(vuln_id)
        if not record:
            return False
        
        record.update_status(TriageStatus.DUPLICATE)
        record.related_issues.append(original_id)
        record.add_note(f"Duplicate of {original_id}")
        return True
    
    def assign_to(self, vuln_id: str, assignee: str) -> bool:
        record = self.records.get(vuln_id)
        if not record:
            return False
        
        record.assignee = assignee
        record.updated_at = time.time()
        return True
    
    def get_workload(self, assignee: Optional[str] = None) -> Dict[str, Any]:
        records = self.records.values()
        
        if assignee:
            records = [r for r in records if r.assignee == assignee]
        
        pending = [r for r in records if r.status in [TriageStatus.NEW, TriageStatus.TRIAGED, TriageStatus.IN_PROGRESS]]
        
        return {
            'total': len(records),
            'pending': len(pending),
            'by_priority': {
                p.value: len([r for r in pending if r.priority == p])
                for p in TriagePriority
            }
        }
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            'summary': dict(self.statistics),
            'records': {k: v.to_dict() for k, v in self.records.items()},
            'workload': self.get_workload()
        }
    
    def export_json(self, filepath: str):
        report = self.generate_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
    
    def import_json(self, filepath: str):
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        records = data.get('records', {})
        for vuln_id, record_data in records.items():
            record = VulnerabilityRecord(**record_data)
            self.records[vuln_id] = record
    
    def get_sla_status(self) -> Dict[str, Any]:
        now = time.time()
        overdue = []
        
        for record in self.records.values():
            age_hours = (now - record.updated_at) / 3600
            
            if record.priority == TriagePriority.P0_CRITICAL and age_hours > 24:
                overdue.append((record.vuln_id, age_hours))
            elif record.priority == TriagePriority.P1_HIGH and age_hours > 72:
                overdue.append((record.vuln_id, age_hours))
            elif record.priority == TriagePriority.P2_MEDIUM and age_hours > 168:
                overdue.append((record.vuln_id, age_hours))
        
        return {
            'overdue_count': len(overdue),
            'overdue_items': overdue
        }


class TriageAnalytics:
    def __init__(self, engine: TriageEngine):
        self.engine = engine
    
    def get_mttr(self) -> float:
        resolved = [r for r in self.engine.records.values() 
                 if r.status in [TriageStatus.MITIGATED, TriageStatus.ACCEPTED_RISK]]
        
        if not resolved:
            return 0.0
        
        total_time = sum(r.updated_at - r.discovered_at for r in resolved)
        return (total_time / len(resolved)) / 3600
    
    def get_false_positive_rate(self) -> float:
        total = len(self.engine.records)
        if total == 0:
            return 0.0
        
        fp = sum(1 for r in self.engine.records.values() 
                 if r.status == TriageStatus.FALSE_POSITIVE)
        return fp / total
    
    def get_resolution_rate(self) -> float:
        total = len(self.engine.records)
        if total == 0:
            return 0.0
        
        resolved = sum(1 for r in self.engine.records.values()
                  if r.status in [TriageStatus.MITIGATED, TriageStatus.ACCEPTED_RISK])
        return resolved / total
    
    def get_summary(self) -> Dict[str, Any]:
        return {
            'mttr_hours': round(self.get_mttr(), 2),
            'false_positive_rate': round(self.get_false_positive_rate() * 100, 2),
            'resolution_rate': round(self.get_resolution_rate() * 100, 2),
            'total_findings': len(self.engine.records)
        }


def create_triage_engine() -> TriageEngine:
    engine = TriageEngine()
    engine.add_rule(SeverityBasedTriageRule())
    return engine


if __name__ == '__main__':
    engine = create_triage_engine()
    
    sample_finding = {
        'title': 'Reentrancy Vulnerability',
        'severity_score': 9.5,
        'contract_name': 'Bank',
        'function_name': 'withdraw',
        'line_number': 45,
        'code_snippet': '(bool success,) = msg.sender.call{value: amount}("");',
        'description': 'External call before state change',
        'impact': 'Attacker can re-enter and drain funds',
        'recommendation': 'Use ReentrancyGuard',
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    }
    
    record = engine.process_finding(sample_finding)
    print(json.dumps(record.to_dict(), indent=2))
    
    report = engine.generate_report()
    print(json.dumps(report['summary'], indent=2))