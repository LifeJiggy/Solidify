"""
Solidify Context Factory Module
Factory methods for creating various context types

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Factory pattern implementation for context creation
"""

import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import copy
import re

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority,
    ContractContext, VulnerabilityContext, FindingContext
)

logger = logging.getLogger(__name__)


class ContextFactoryType(Enum):
    AUDIT = "audit"
    HUNT = "hunt"
    SCAN = "scan"
    INVESTIGATION = "investigation"
    MONITORING = "monitoring"
    BREACH = "breach"
    THREAT_INTEL = "threat_intel"
    INCIDENT_RESPONSE = "incident_response"


@dataclass
class ContextTemplate:
    template_id: str
    name: str
    context_type: ContextFactoryType
    default_values: Dict[str, Any] = field(default_factory=dict)
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    validators: Dict[str, Callable] = field(default_factory=dict)
    preprocessors: Dict[str, Callable] = field(default_factory=dict)
    postprocessors: List[Callable] = field(default_factory=list)


@dataclass
class ContextConfig:
    auto_id: bool = True
    auto_timestamp: bool = True
    validate: bool = True
    preprocess: bool = True
    postprocess: bool = True
    track_metrics: bool = True
    emit_events: bool = True


class ContextFactoryBase(ABC):
    def __init__(self, config: Optional[ContextConfig] = None):
        self._config = config or ContextConfig()
        self._templates: Dict[str, ContextTemplate] = {}
        self._cache: Dict[str, Any] = {}
        self._reuse_pool: Dict[str, List[Any]] = defaultdict(list)
        self._max_pool_size = 10

    @abstractmethod
    def create(self, **kwargs) -> Any:
        pass

    @abstractmethod
    def validate(self, context: Any) -> Tuple[bool, List[str]]:
        pass

    def register_template(self, template: ContextTemplate) -> None:
        self._templates[template.template_id] = template

    def get_template(self, template_id: str) -> Optional[ContextTemplate]:
        return self._templates.get(template_id)

    def apply_template(self, template_id: str, overrides: Optional[Dict[str, Any]] = None) -> Any:
        template = self._templates.get(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")
        
        data = template.default_values.copy()
        if overrides:
            data.update(overrides)
        
        return self.create(**data)

    def cache_context(self, context_id: str, context: Any) -> None:
        self._cache[context_id] = context

    def get_cached(self, context_id: str) -> Optional[Any]:
        return self._cache.get(context_id)

    def clear_cache(self) -> None:
        self._cache.clear()

    def get_from_pool(self, context_type: ContextFactoryType) -> Optional[Any]:
        pool = self._reuse_pool.get(context_type.value, [])
        if pool:
            return pool.pop(0)
        return None

    def return_to_pool(self, context: Any) -> None:
        context_type = getattr(context, 'context_type', None)
        if context_type:
            pool = self._reuse_pool[context_type.value]
            if len(pool) < self._max_pool_size:
                pool.append(context)


class AuditContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"audit_{int(time.time())}_{self._sequence}"

    def create(self, audit_id: Optional[str] = None, title: str = "", description: str = "",
             auditor: Optional[str] = None, priority: ContextPriority = ContextPriority.P2,
             scope: Optional[List[str]] = None, targets: Optional[List[str]] = None,
             rules: Optional[List[str]] = None, tags: Optional[List[str]] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> AuditContext:
        
        if self._config.auto_id and not audit_id:
            audit_id = self.generate_id()
        
        if self._config.preprocess:
            if title:
                title = self._preprocess_title(title)
            if description:
                description = self._preprocess_description(description)
        
        context = AuditContext(
            audit_id=audit_id or "",
            title=title,
            description=description,
            context_type=ContextType.AUDIT,
            auditor=auditor,
            priority=priority,
            scope=scope or [],
            targets=targets or [],
            rules=rules or [],
            tags=tags or [],
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        if self._config.postprocess:
            context = self._postprocess(context)
        
        if self._config.track_metrics:
            logger.info(f"Created audit context: {audit_id}")
        
        return context

    def _preprocess_title(self, title: str) -> str:
        return title.strip()

    def _preprocess_description(self, description: str) -> str:
        return description.strip()

    def _postprocess(self, context: AuditContext) -> AuditContext:
        if not context.audit_id:
            context.audit_id = self.generate_id()
        return context

    def validate(self, context: AuditContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.audit_id:
            errors.append("audit_id is required")
        if not context.title:
            errors.append("title is required")
        if context.title and len(context.title) < 3:
            errors.append("title must be at least 3 characters")
        if context.title and len(context.title) > 200:
            errors.append("title must not exceed 200 characters")
        
        return len(errors) == 0, errors

    def create_from_template(self, template_id: str, overrides: Optional[Dict[str, Any]] = None) -> AuditContext:
        template = self.get_template(template_id)
        if not template:
            return self.create(**(overrides or {}))
        
        data = template.default_values.copy()
        if overrides:
            data.update(overrides)
        
        return self.create(**data)

    def bulk_create(self, count: int, base_title: str = "Audit",
                   **kwargs) -> List[AuditContext]:
        contexts = []
        for i in range(count):
            title = f"{base_title} {i+1}"
            ctx = self.create(title=title, **kwargs)
            contexts.append(ctx)
        return contexts

    def clone(self, source: AuditContext, new_audit_id: Optional[str] = None) -> AuditContext:
        cloned = copy.deepcopy(source)
        if new_audit_id:
            cloned.audit_id = new_audit_id
        else:
            cloned.audit_id = self.generate_id()
        
        cloned.status = Status.PENDING
        cloned.start_time = datetime.now()
        cloned.end_time = None
        cloned.findings = []
        
        return cloned

    def merge(self, contexts: List[AuditContext]) -> AuditContext:
        if not contexts:
            raise ValueError("No contexts to merge")
        
        merged_contracts = []
        merged_vulnerabilities = []
        merged_findings = []
        all_tags = set()
        
        for ctx in contexts:
            merged_contracts.extend(ctx.contracts)
            merged_vulnerabilities.extend(ctx.vulnerabilities)
            merged_findings.extend(ctx.findings)
            all_tags.update(ctx.tags)
        
        return self.create(
            title=f"Merged Audit ({len(contexts)} contexts)",
            description=f"Combined {len(contexts)} audit contexts",
            tags=list(all_tags),
            scope=[],
            targets=[],
            rules=[]
        )


class HuntContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"hunt_{int(time.time())}_{self._sequence}"

    def create(self, hunt_id: Optional[str] = None, title: str = "",
              description: str = "", hunter: Optional[str] = None,
              priority: ContextPriority = ContextPriority.P1,
              target_addresses: Optional[List[str]] = None,
              target_networks: Optional[List[str]] = None,
              suspicious_contracts: Optional[List[str]] = None,
              malicious_patterns: Optional[List[str]] = None,
              ioc_list: Optional[List[Dict]] = None,
              threat_actors: Optional[List[str]] = None,
              campaigns: Optional[List[str]] = None,
              TTPs: Optional[List[str]] = None,
              metadata: Optional[Dict[str, Any]] = None, **kwargs) -> HuntContext:
        
        if self._config.auto_id and not hunt_id:
            hunt_id = self.generate_id()
        
        context = HuntContext(
            hunt_id=hunt_id or "",
            title=title,
            description=description,
            context_type=ContextType.HUNT,
            hunter=hunter,
            priority=priority,
            target_addresses=target_addresses or [],
            target_networks=target_networks or [],
            suspicious_contracts=suspicious_contracts or [],
            malicious_patterns=malicious_patterns or [],
            ioc_list=ioc_list or [],
            threat_actors=threat_actors or [],
            campaigns=campaigns or [],
            TTPs=TTPs or [],
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.info(f"Created hunt context: {hunt_id}")
        return context

    def validate(self, context: HuntContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.hunt_id:
            errors.append("hunt_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors

    def create_from_iocs(self, ioc_list: List[Dict], title: str = "",
                        hunter: Optional[str] = None) -> HuntContext:
        target_addresses = []
        for ioc in ioc_list:
            if ioc.get("type") == "address":
                target_addresses.append(ioc.get("value"))
        
        return self.create(
            title=title or "IOC-based Hunt",
            hunter=hunter,
            target_addresses=target_addresses,
            ioc_list=ioc_list
        )

    def create_from_threat_actor(self, threat_actor: str, title: str = "",
                                hunter: Optional[str] = None) -> HuntContext:
        return self.create(
            title=title or f"Hunt for {threat_actor}",
            hunter=hunter,
            threat_actors=[threat_actor]
        )

    def clone(self, source: HuntContext, new_hunt_id: Optional[str] = None) -> HuntContext:
        cloned = copy.deepcopy(source)
        if new_hunt_id:
            cloned.hunt_id = new_hunt_id
        else:
            cloned.hunt_id = self.generate_id()
        
        cloned.status = Status.PENDING
        cloned.start_time = datetime.now()
        cloned.end_time = None
        cloned.findings = []
        
        return cloned


class ScanContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"scan_{int(time.time())}_{self._sequence}"

    def create(self, scan_id: Optional[str] = None, title: str = "",
             description: str = "", scanner: Optional[str] = None,
             scan_type: str = "full", priority: ContextPriority = ContextPriority.P2,
             target_patterns: Optional[List[str]] = None,
             rules_applied: Optional[List[str]] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> ScanContext:
        
        if self._config.auto_id and not scan_id:
            scan_id = self.generate_id()
        
        context = ScanContext(
            scan_id=scan_id or "",
            title=title,
            description=description,
            context_type=ContextType.SCAN,
            scanner=scanner,
            scan_type=scan_type,
            priority=priority,
            target_patterns=target_patterns or [],
            rules_applied=rules_applied or [],
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.info(f"Created scan context: {scan_id}")
        return context

    def validate(self, context: ScanContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.scan_id:
            errors.append("scan_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors

    def create_quick_scan(self, targets: List[str], scanner: Optional[str] = None) -> ScanContext:
        return self.create(
            title=f"Quick Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            description=f"Quick scan of {len(targets)} targets",
            scanner=scanner,
            scan_type="quick",
            target_patterns=targets
        )

    def create_full_scan(self, targets: List[str], scanner: Optional[str] = None,
                       rules: Optional[List[str]] = None) -> ScanContext:
        return self.create(
            title=f"Full Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            description=f"Full scan of {len(targets)} targets",
            scanner=scanner,
            scan_type="full",
            rules_applied=rules or ["all"]
        )


class InvestigationContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"inv_{int(time.time())}_{self._sequence}"

    def create(self, investigation_id: Optional[str] = None, title: str = "",
             description: str = "", investigator: Optional[str] = None,
             priority: ContextPriority = ContextPriority.P0,
             subject: str = "", subject_type: str = "",
             evidence: Optional[List[Dict]] = None,
             timeline: Optional[List[Dict]] = None,
             witnesses: Optional[List[str]] = None,
             suspects: Optional[List[str]] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> InvestigationContext:
        
        if self._config.auto_id and not investigation_id:
            investigation_id = self.generate_id()
        
        context = InvestigationContext(
            investigation_id=investigation_id or "",
            title=title,
            description=description,
            context_type=ContextType.INVESTIGATION,
            investigator=investigator,
            priority=priority,
            subject=subject,
            subject_type=subject_type,
            evidence=evidence or [],
            timeline=timeline or [],
            witnesses=witnesses or [],
            suspects=suspects or [],
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.info(f"Created investigation context: {investigation_id}")
        return context

    def validate(self, context: InvestigationContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.investigation_id:
            errors.append("investigation_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors


class MonitoringContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"monitor_{int(time.time())}_{self._sequence}"

    def create(self, monitor_id: Optional[str] = None, title: str = "",
             description: str = "", monitor: Optional[str] = None,
             network: str = "", priority: ContextPriority = ContextPriority.P1,
             addresses: Optional[List[str]] = None,
             alert_channels: Optional[List[str]] = None,
             thresholds: Optional[Dict[str, Any]] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> MonitoringContext:
        
        if self._config.auto_id and not monitor_id:
            monitor_id = self.generate_id()
        
        context = MonitoringContext(
            monitor_id=monitor_id or "",
            title=title,
            description=description,
            context_type=ContextType.MONITORING,
            monitor=monitor,
            network=network,
            priority=priority,
            addresses=addresses or [],
            alert_channels=alert_channels or [],
            thresholds=thresholds or {},
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            status=Status.ACTIVE,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.info(f"Created monitoring context: {monitor_id}")
        return context

    def validate(self, context: MonitoringContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.monitor_id:
            errors.append("monitor_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors


class BreachContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"breach_{int(time.time())}_{self._sequence}"

    def create(self, breach_id: Optional[str] = None, title: str = "",
             description: str = "", investigator: Optional[str] = None,
             priority: ContextPriority = ContextPriority.P0,
             affected_addresses: Optional[List[str]] = None,
             affected_users: Optional[List[str]] = None,
             funds_lost: Optional[float] = None,
             token: Optional[str] = None,
             attack_vector: Optional[str] = None,
             root_cause: Optional[str] = None,
             timeline: Optional[List[Dict]] = None,
             mitigations: Optional[List[str]] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> BreachContext:
        
        if self._config.auto_id and not breach_id:
            breach_id = self.generate_id()
        
        context = BreachContext(
            breach_id=breach_id or "",
            title=title,
            description=description,
            context_type=ContextType.BREACH,
            investigator=investigator,
            priority=priority,
            affected_addresses=affected_addresses or [],
            affected_users=affected_users or [],
            funds_lost=funds_lost,
            token=token,
            attack_vector=attack_vector,
            root_cause=root_cause,
            timeline=timeline or [],
            mitigations=mitigations or [],
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            detection_time=datetime.now(),
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.warning(f"Created breach context: {breach_id}")
        return context

    def validate(self, context: BreachContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.breach_id:
            errors.append("breach_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors


class ThreatIntelContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"intel_{int(time.time())}_{self._sequence}"

    def create(self, intel_id: Optional[str] = None, title: str = "",
             description: str = "", collector: Optional[str] = None,
             intel_type: str = "", source: str = "",
             priority: ContextPriority = ContextPriority.P2,
             iocs: Optional[List[Dict]] = None,
             TTPs: Optional[List[str]] = None,
             threat_actors: Optional[List[str]] = None,
             campaigns: Optional[List[str]] = None,
             confidence: str = "", reliability: str = "",
             severity: Severity = Severity.INFO,
             tlp: str = "AMBER",
             expires_at: Optional[datetime] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> ThreatIntelContext:
        
        if self._config.auto_id and not intel_id:
            intel_id = self.generate_id()
        
        context = ThreatIntelContext(
            intel_id=intel_id or "",
            title=title,
            description=description,
            context_type=ContextType.THREAT_INTEL,
            collector=collector,
            intel_type=intel_type,
            source=source,
            priority=priority,
            iocs=iocs or [],
            TTPs=TTPs or [],
            threat_actors=threat_actors or [],
            campaigns=campaigns or [],
            confidence=confidence,
            reliability=reliability,
            severity=severity,
            tlp=tlp,
            expires_at=expires_at,
            metadata=metadata or {},
            timestamp=datetime.now() if self._config.auto_timestamp else None,
            status=Status.ACTIVE,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.info(f"Created threat intel context: {intel_id}")
        return context

    def validate(self, context: ThreatIntelContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.intel_id:
            errors.append("intel_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors


class IncidentResponseContextFactory(ContextFactoryBase):
    def __init__(self, config: Optional[ContextConfig] = None):
        super().__init__(config)
        self._sequence = 0

    def generate_id(self) -> str:
        self._sequence += 1
        return f"incident_{int(time.time())}_{self._sequence}"

    def create(self, incident_id: Optional[str] = None, title: str = "",
             description: str = "", responder: Optional[str] = None,
             priority: ContextPriority = ContextPriority.P0,
             incident_type: str = "", severity: Severity = Severity.HIGH,
             affected_systems: Optional[List[str]] = None,
             affected_users: Optional[List[str]] = None,
             containment_actions: Optional[List[str]] = None,
             eradication_actions: Optional[List[str]] = None,
             recovery_actions: Optional[List[str]] = None,
             lessons_learned: Optional[List[str]] = None,
             metadata: Optional[Dict[str, Any]] = None, **kwargs) -> IncidentResponseContext:
        
        if self._config.auto_id and not incident_id:
            incident_id = self.generate_id()
        
        context = IncidentResponseContext(
            incident_id=incident_id or "",
            title=title,
            description=description,
            context_type=ContextType.INCIDENT_RESPONSE,
            responder=responder,
            priority=priority,
            incident_type=incident_type,
            severity=severity,
            affected_systems=affected_systems or [],
            affected_users=affected_users or [],
            containment_actions=containment_actions or [],
            eradication_actions=eradication_actions or [],
            recovery_actions=recovery_actions or [],
            lessons_learned=lessons_learned or [],
            metadata=metadata or {},
            start_time=datetime.now() if self._config.auto_timestamp else None,
            **kwargs
        )
        
        if self._config.validate:
            valid, errors = self.validate(context)
            if not valid:
                raise ValueError(f"Validation failed: {errors}")
        
        logger.warning(f"Created incident response context: {incident_id}")
        return context

    def validate(self, context: IncidentResponseContext) -> Tuple[bool, List[str]]:
        errors = []
        
        if not context.incident_id:
            errors.append("incident_id is required")
        if not context.title:
            errors.append("title is required")
        
        return len(errors) == 0, errors


class ContextFactoryRegistry:
    _factories: Dict[ContextFactoryType, ContextFactoryBase] = {}

    @classmethod
    def register(cls, context_type: ContextFactoryType, factory: ContextFactoryBase) -> None:
        cls._factories[context_type] = factory

    @classmethod
    def get(cls, context_type: ContextFactoryType) -> Optional[ContextFactoryBase]:
        return cls._factories.get(context_type)

    @classmethod
    def create(cls, context_type: ContextFactoryType, **kwargs) -> Any:
        factory = cls._factories.get(context_type)
        if not factory:
            raise ValueError(f"No factory registered for {context_type}")
        return factory.create(**kwargs)


class ContextFactoryManager:
    def __init__(self):
        self._audit_factory = AuditContextFactory()
        self._hunt_factory = HuntContextFactory()
        self._scan_factory = ScanContextFactory()
        self._investigation_factory = InvestigationContextFactory()
        self._monitoring_factory = MonitoringContextFactory()
        self._breach_factory = BreachContextFactory()
        self._threat_intel_factory = ThreatIntelContextFactory()
        self._incident_response_factory = IncidentResponseContextFactory()

        ContextFactoryRegistry.register(ContextFactoryType.AUDIT, self._audit_factory)
        ContextFactoryRegistry.register(ContextFactoryType.HUNT, self._hunt_factory)
        ContextFactoryRegistry.register(ContextFactoryType.SCAN, self._scan_factory)
        ContextFactoryRegistry.register(ContextFactoryType.INVESTIGATION, self._investigation_factory)
        ContextFactoryRegistry.register(ContextFactoryType.MONITORING, self._monitoring_factory)
        ContextFactoryRegistry.register(ContextFactoryType.BREACH, self._breach_factory)
        ContextFactoryRegistry.register(ContextFactoryType.THREAT_INTEL, self._threat_intel_factory)
        ContextFactoryRegistry.register(ContextFactoryType.INCIDENT_RESPONSE, self._incident_response_factory)

    def get_audit_factory(self) -> AuditContextFactory:
        return self._audit_factory

    def get_hunt_factory(self) -> HuntContextFactory:
        return self._hunt_factory

    def get_scan_factory(self) -> ScanContextFactory:
        return self._scan_factory

    def get_investigation_factory(self) -> InvestigationContextFactory:
        return self._investigation_factory

    def get_monitoring_factory(self) -> MonitoringContextFactory:
        return self._monitoring_factory

    def get_breach_factory(self) -> BreachContextFactory:
        return self._breach_factory

    def get_threat_intel_factory(self) -> ThreatIntelContextFactory:
        return self._threat_intel_factory

    def get_incident_response_factory(self) -> IncidentResponseContextFactory:
        return self._incident_response_factory


def create_audit_context(title: str, description: str = "",
                      auditor: Optional[str] = None) -> AuditContext:
    factory = AuditContextFactory()
    return factory.create(title=title, description=description, auditor=auditor)


def create_hunt_context(title: str, description: str = "",
                      hunter: Optional[str] = None) -> HuntContext:
    factory = HuntContextFactory()
    return factory.create(title=title, description=description, hunter=hunter)


def create_scan_context(title: str, description: str = "",
                       scanner: Optional[str] = None) -> ScanContext:
    factory = ScanContextFactory()
    return factory.create(title=title, description=description, scanner=scanner)


def create_investigation_context(title: str, description: str = "",
                                investigator: Optional[str] = None) -> InvestigationContext:
    factory = InvestigationContextFactory()
    return factory.create(title=title, description=description, investigator=investigator)


def create_monitoring_context(title: str, network: str,
                             monitor: Optional[str] = None) -> MonitoringContext:
    factory = MonitoringContextFactory()
    return factory.create(title=title, network=network, monitor=monitor)


def create_breach_context(title: str, description: str = "",
                        investigator: Optional[str] = None) -> BreachContext:
    factory = BreachContextFactory()
    return factory.create(title=title, description=description, investigator=investigator)


def create_threat_intel_context(title: str, intel_type: str,
                             collector: Optional[str] = None) -> ThreatIntelContext:
    factory = ThreatIntelContextFactory()
    return factory.create(title=title, intel_type=intel_type, collector=collector)


def create_incident_response_context(title: str, incident_type: str,
                                   responder: Optional[str] = None) -> IncidentResponseContext:
    factory = IncidentResponseContextFactory()
    return factory.create(title=title, incident_type=incident_type, responder=responder)