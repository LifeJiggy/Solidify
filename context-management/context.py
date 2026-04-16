"""
Solidify Context Module
Core context representation for smart contract security auditing

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Context data structures and representations for audit workflows
"""

import json
import hashlib
import time
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, Counter, deque
import logging
import re
import copy
import os

logger = logging.getLogger(__name__)


class ContextType(Enum):
    AUDIT = "audit"
    HUNT = "hunt"
    SCAN = "scan"
    INVESTIGATION = "investigation"
    MONITORING = "monitoring"
    BREACH = "breach"
    THREAT_INTEL = "threat_intel"
    INCIDENT_RESPONSE = "incident_response"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class Status(Enum):
    ACTIVE = "active"
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class ContextPriority(Enum):
    P0 = 0
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4


@dataclass
class ContractContext:
    address: str
    network: str
    chain_id: int
    source_code: Optional[str] = None
    abi: Optional[List[Dict]] = None
    bytecode: Optional[str] = None
    compiler_version: Optional[str] = None
    optimization_enabled: Optional[bool] = None
    runs: Optional[int] = None
    license_type: Optional[str] = None
    contract_name: Optional[str] = None
    constructor_args: Optional[str] = None
    EOB: Optional[bool] = None


@dataclass
class VulnerabilityContext:
    vuln_id: str
    vulnerability_type: str
    severity: Severity
    title: str
    description: str
    affected_contracts: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    code_references: List[Dict] = field(default_factory=list)
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None


@dataclass
class FindingContext:
    finding_id: str
    context_id: str
    vuln_context: VulnerabilityContext
    timestamp: datetime = field(default_factory=datetime.now)
    status: Status = Status.PENDING
    false_positive: bool = False
    verified: bool = False
    assignee: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditContext:
    audit_id: str
    context_type: ContextType = ContextType.AUDIT
    title: str = ""
    description: str = ""
    contracts: List[ContractContext] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityContext] = field(default_factory=list)
    findings: List[FindingContext] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: Status = Status.PENDING
    priority: ContextPriority = ContextPriority.P2
    auditor: Optional[str] = None
    scope: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    exclude_list: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    linked_audits: List[str] = field(default_factory=list)


@dataclass
class HuntContext:
    hunt_id: str
    context_type: ContextType = ContextType.HUNT
    title: str = ""
    description: str = ""
    target_addresses: List[str] = field(default_factory=list)
    target_networks: List[str] = field(default_factory=list)
    suspicious_contracts: List[str] = field(default_factory=list)
    malicious_patterns: List[str] = field(default_factory=list)
    ioc_list: List[Dict] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    TTPs: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: Status = Status.PENDING
    priority: ContextPriority = ContextPriority.P1
    hunter: Optional[str] = None
    findings: List[FindingContext] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    scan_id: str
    context_type: ContextType = ContextType.SCAN
    title: str = ""
    description: str = ""
    scan_type: str = "full"
    target_patterns: List[str] = field(default_factory=list)
    rules_applied: List[str] = field(default_factory=list)
    patterns_found: List[Dict] = field(default_factory=list)
    artifacts: List[Dict] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    status: Status = Status.PENDING
    priority: ContextPriority = ContextPriority.P2
    scanner: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationContext:
    investigation_id: str
    context_type: ContextType = ContextType.INVESTIGATION
    title: str = ""
    description: str = ""
    subject: str = ""
    subject_type: str = ""
    evidence: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    witnesses: List[str] = field(default_factory=list)
    suspects: List[str] = field(default_factory=list)
    conclusion: Optional[str] = None
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: Status = Status.PENDING
    priority: ContextPriority = ContextPriority.P0
    investigator: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitoringContext:
    monitor_id: str
    context_type: ContextType = ContextType.MONITORING
    title: str = ""
    description: str = ""
    network: str = ""
    addresses: List[str] = field(default_factory=list)
    alert_channels: List[str] = field(default_factory=list)
    thresholds: Dict[str, Any] = field(default_factory=dict)
    alerts: List[Dict] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    status: Status = Status.ACTIVE
    priority: ContextPriority = ContextPriority.P1
    monitor: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BreachContext:
    breach_id: str
    context_type: ContextType = ContextType.BREACH
    title: str = ""
    description: str = ""
    affected_addresses: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    funds_lost: Optional[float] = None
    token: Optional[str] = None
    attack_vector: Optional[str] = None
    root_cause: Optional[str] = None
    timeline: List[Dict] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    detection_time: Optional[datetime] = None
    status: Status = Status.PENDING
    priority: ContextPriority = ContextPriority.P0
    investigator: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelContext:
    intel_id: str
    context_type: ContextType = ContextType.THREAT_INTEL
    title: str = ""
    description: str = ""
    intel_type: str = ""
    source: str = ""
    iocs: List[Dict] = field(default_factory=list)
    TTPs: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    confidence: str = ""
    reliability: str = ""
    severity: Severity = Severity.INFO
    tlp: str = "AMBER"
    timestamp: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    status: Status = Status.ACTIVE
    priority: ContextPriority = ContextPriority.P2
    collector: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentResponseContext:
    incident_id: str
    context_type: ContextType = ContextType.INCIDENT_RESPONSE
    title: str = ""
    description: str = ""
    incident_type: str = ""
    severity: Severity = Severity.HIGH
    affected_systems: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)
    eradication_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    containment_time: Optional[datetime] = None
    eradication_time: Optional[datetime] = None
    recovery_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: Status = Status.PENDING
    priority: ContextPriority = ContextPriority.P0
    responder: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextBuilder:
    def __init__(self):
        self._context: Optional[AuditContext] = None
        self._contracts: List[ContractContext] = []
        self._vulnerabilities: List[VulnerabilityContext] = []
        self._findings: List[FindingContext] = []

    def create_audit(self, audit_id: str, title: str, description: str = "") -> "ContextBuilder":
        self._context = AuditContext(
            audit_id=audit_id,
            title=title,
            description=description
        )
        return self

    def add_contract(self, address: str, network: str, chain_id: int, **kwargs) -> "ContextBuilder":
        contract = ContractContext(
            address=address,
            network=network,
            chain_id=chain_id,
            **kwargs
        )
        self._contracts.append(contract)
        return self

    def add_vulnerability(self, vuln_id: str, vuln_type: str, severity: Severity,
                       title: str, description: str, **kwargs) -> "ContextBuilder":
        vuln = VulnerabilityContext(
            vuln_id=vuln_id,
            vulnerability_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            **kwargs
        )
        self._vulnerabilities.append(vuln)
        return self

    def add_finding(self, finding_id: str, vuln_context: VulnerabilityContext, **kwargs) -> "ContextBuilder":
        finding = FindingContext(
            finding_id=finding_id,
            context_id=self._context.audit_id if self._context else "",
            vuln_context=vuln_context,
            **kwargs
        )
        self._findings.append(finding)
        return self

    def set_auditor(self, auditor: str) -> "ContextBuilder":
        if self._context:
            self._context.auditor = auditor
        return self

    def set_priority(self, priority: ContextPriority) -> "ContextBuilder":
        if self._context:
            self._context.priority = priority
        return self

    def add_scope(self, scope: List[str]) -> "ContextBuilder":
        if self._context:
            self._context.scope.extend(scope)
        return self

    def add_target(self, target: str) -> "ContextBuilder":
        if self._context:
            self._context.targets.append(target)
        return self

    def add_rule(self, rule: str) -> "ContextBuilder":
        if self._context:
            self._context.rules.append(rule)
        return self

    def add_tag(self, tag: str) -> "ContextBuilder":
        if self._context:
            self._context.tags.append(tag)
        return self

    def add_metadata(self, key: str, value: Any) -> "ContextBuilder":
        if self._context:
            self._context.metadata[key] = value
        return self

    def build(self) -> AuditContext:
        if self._context:
            self._context.contracts = self._contracts
            self._context.vulnerabilities = self._vulnerabilities
            self._context.findings = self._findings
        return self._context


class ContextSerializer:
    @staticmethod
    def serialize_context(context: AuditContext) -> str:
        return json.dumps(context.__dict__, default=str, indent=2)

    @staticmethod
    def deserialize_context(data: str) -> AuditContext:
        data_dict = json.loads(data)
        return AuditContext(**data_dict)

    @staticmethod
    def serialize_contract(contract: ContractContext) -> str:
        return json.dumps(contract.__dict__, default=str, indent=2)

    @staticmethod
    def deserialize_contract(data: str) -> ContractContext:
        data_dict = json.loads(data)
        return ContractContext(**data_dict)

    @staticmethod
    def serialize_vulnerability(vuln: VulnerabilityContext) -> str:
        data = vuln.__dict__.copy()
        if isinstance(data.get("severity"), Severity):
            data["severity"] = data["severity"].value
        return json.dumps(data, default=str, indent=2)

    @staticmethod
    def deserialize_vulnerability(data: str) -> VulnerabilityContext:
        data_dict = json.loads(data)
        if "severity" in data_dict and isinstance(data_dict["severity"], str):
            data_dict["severity"] = Severity(data_dict["severity"])
        return VulnerabilityContext(**data_dict)


class ContextValidator:
    @staticmethod
    def validate_audit_context(context: AuditContext) -> Tuple[bool, List[str]]:
        errors = []
        if not context.audit_id:
            errors.append("audit_id is required")
        if not context.title:
            errors.append("title is required")
        if context.priority is None:
            errors.append("priority is required")
        if not context.status:
            errors.append("status is required")
        return len(errors) == 0, errors

    @staticmethod
    def validate_contract(contract: ContractContext) -> Tuple[bool, List[str]]:
        errors = []
        if not contract.address:
            errors.append("address is required")
        if not contract.network:
            errors.append("network is required")
        if contract.chain_id is None or contract.chain_id <= 0:
            errors.append("valid chain_id is required")
        if contract.address and not ContextValidator._is_valid_eth_address(contract.address):
            errors.append("invalid Ethereum address format")
        return len(errors) == 0, errors

    @staticmethod
    def _is_valid_eth_address(address: str) -> bool:
        if not address:
            return False
        return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))

    @staticmethod
    def validate_vulnerability(vuln: VulnerabilityContext) -> Tuple[bool, List[str]]:
        errors = []
        if not vuln.vuln_id:
            errors.append("vuln_id is required")
        if not vuln.vulnerability_type:
            errors.append("vulnerability_type is required")
        if not vuln.severity:
            errors.append("severity is required")
        if not vuln.title:
            errors.append("title is required")
        if not vuln.description:
            errors.append("description is required")
        return len(errors) == 0, errors

    @staticmethod
    def validate_finding(finding: FindingContext) -> Tuple[bool, List[str]]:
        errors = []
        if not finding.finding_id:
            errors.append("finding_id is required")
        if not finding.context_id:
            errors.append("context_id is required")
        if not finding.vuln_context:
            errors.append("vuln_context is required")
        return len(errors) == 0, errors


class ContextHasher:
    @staticmethod
    def hash_context(context: AuditContext) -> str:
        data = json.dumps(context.__dict__, default=str, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_contract(contract: ContractContext) -> str:
        data = json.dumps(contract.__dict__, default=str, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def hash_vulnerability(vuln: VulnerabilityContext) -> str:
        data = json.dumps(vuln.__dict__, default=str, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()


class ContextAggregator:
    @staticmethod
    def aggregate_findings(contexts: List[AuditContext]) -> Dict[str, Any]:
        total_findings = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        info_vulns = 0

        vuln_types: Dict[str, int] = defaultdict(int)

        for ctx in contexts:
            total_findings += len(ctx.findings)
            for vuln in ctx.vulnerabilities:
                vuln_types[vuln.vulnerability_type] += 1
                if vuln.severity == Severity.CRITICAL:
                    critical_vulns += 1
                elif vuln.severity == Severity.HIGH:
                    high_vulns += 1
                elif vuln.severity == Severity.MEDIUM:
                    medium_vulns += 1
                elif vuln.severity == Severity.LOW:
                    low_vulns += 1
                elif vuln.severity == Severity.INFO:
                    info_vulns += 1

        return {
            "total_audits": len(contexts),
            "total_findings": total_findings,
            "critical_vulns": critical_vulns,
            "high_vulns": high_vulns,
            "medium_vulns": medium_vulns,
            "low_vulns": low_vulns,
            "info_vulns": info_vulns,
            "vuln_types": dict(vuln_types)
        }


class ContextFilter:
    @staticmethod
    def filter_by_severity(contexts: List[AuditContext], severity: Severity) -> List[AuditContext]:
        result = []
        for ctx in contexts:
            for vuln in ctx.vulnerabilities:
                if vuln.severity == severity:
                    result.append(ctx)
                    break
        return result

    @staticmethod
    def filter_by_status(contexts: List[AuditContext], status: Status) -> List[AuditContext]:
        return [ctx for ctx in contexts if ctx.status == status]

    @staticmethod
    def filter_by_priority(contexts: List[AuditContext], priority: ContextPriority) -> List[AuditContext]:
        return [ctx for ctx in contexts if ctx.priority == priority]

    @staticmethod
    def filter_by_date_range(contexts: List[AuditContext],
                           start: datetime, end: datetime) -> List[AuditContext]:
        return [ctx for ctx in contexts
                if start <= ctx.start_time <= end]

    @staticmethod
    def filter_by_auditor(contexts: List[AuditContext], auditor: str) -> List[AuditContext]:
        return [ctx for ctx in contexts if ctx.auditor == auditor]


class ContextMerger:
    @staticmethod
    def merge_contexts(contexts: List[AuditContext]) -> AuditContext:
        if not contexts:
            raise ValueError("No contexts to merge")

        merged_id = f"merged_{uuid.uuid4().hex[:8]}"
        merged_contracts = []
        merged_vulnerabilities = []
        merged_findings = []
        all_tags = set()
        all_metadata = {}

        for ctx in contexts:
            merged_contracts.extend(ctx.contracts)
            merged_vulnerabilities.extend(ctx.vulnerabilities)
            merged_findings.extend(ctx.findings)
            all_tags.update(ctx.tags)
            all_metadata.update(ctx.metadata)

        return AuditContext(
            audit_id=merged_id,
            title=f"Merged Audit ({len(contexts)} contexts)",
            description=f"Combined {len(contexts)} audit contexts",
            contracts=merged_contracts,
            vulnerabilities=merged_vulnerabilities,
            findings=merged_findings,
            tags=list(all_tags),
            metadata=all_metadata
        )


class ContextDeduplicator:
    @staticmethod
    def deduplicate_vulnerabilities(vulns: List[VulnerabilityContext]) -> List[VulnerabilityContext]:
        seen = set()
        unique = []
        for vuln in vulns:
            key = (vuln.vulnerability_type, vuln.title)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        return unique

    @staticmethod
    def deduplicate_findings(findings: List[FindingContext]) -> List[FindingContext]:
        seen = set()
        unique = []
        for finding in findings:
            key = (finding.context_id, finding.vuln_context.vulnerability_type)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique


class ContextCopier:
    @staticmethod
    def deep_copy_context(context: AuditContext) -> AuditContext:
        return copy.deepcopy(context)

    @staticmethod
    def shallow_copy_context(context: AuditContext) -> AuditContext:
        return copy.copy(context)


class ContextExporter:
    @staticmethod
    def export_to_json(context: AuditContext, filepath: str) -> None:
        data = json.dumps(context.__dict__, default=str, indent=2)
        with open(filepath, 'w') as f:
            f.write(data)

    @staticmethod
    def export_to_csv(contexts: List[AuditContext], filepath: str) -> None:
        import csv
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['audit_id', 'title', 'status', 'priority', 'auditor', 'severity'])
            for ctx in contexts:
                writer.writerow([
                    ctx.audit_id,
                    ctx.title,
                    ctx.status.value,
                    ctx.priority.value,
                    ctx.auditor,
                    max([v.severity.value for v in ctx.vulnerabilities], default="none")
                ])

    @staticmethod
    def export_findings_csv(findings: List[FindingContext], filepath: str) -> None:
        import csv
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['finding_id', 'context_id', 'severity', 'type', 'title'])
            for finding in findings:
                writer.writerow([
                    finding.finding_id,
                    finding.context_id,
                    finding.vuln_context.severity.value,
                    finding.vuln_context.vulnerability_type,
                    finding.vuln_context.title
                ])