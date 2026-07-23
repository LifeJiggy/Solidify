"""
Solidify Context Parser Module
Parses and serializes various context formats

Author: Joel Emmanuel Adinoyi (Security Lead)
Description: Parsing support for context data in multiple formats
"""

import json
import logging
import re
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union, TextIO
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from collections import defaultdict, Counter, deque
from abc import ABC, abstractmethod
import copy
import io
import base64
import hashlib

from .context import (
    AuditContext, HuntContext, ScanContext, InvestigationContext,
    MonitoringContext, BreachContext, ThreatIntelContext, IncidentResponseContext,
    ContextType, Severity, Status, ContextPriority,
    ContractContext, VulnerabilityContext, FindingContext
)

logger = logging.getLogger(__name__)


class ParseFormat(Enum):
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"
    XML = "xml"
    TOML = "toml"
    TEXT = "text"


class ParseError(Exception):
    def __init__(self, message: str, line: Optional[int] = None, column: Optional[int] = None):
        self.line = line
        self.column = column
        super().__init__(message)


class ParseResult:
    def __init__(self, success: bool, data: Any = None, errors: Optional[List[str]] = None,
                 warnings: Optional[List[str]] = None, metadata: Optional[Dict[str, Any]] = None):
        self.success = success
        self.data = data
        self.errors = errors or []
        self.warnings = warnings or []
        self.metadata = metadata or {}

    def __bool__(self) -> bool:
        return self.success


@dataclass
class ParseConfig:
    strict: bool = False
    allow_missing_fields: bool = True
    allow_extra_fields: bool = True
    validate_values: bool = True
    normalize_keys: bool = True
    convert_types: bool = True
    max_depth: int = 10
    max_size: int = 10 * 1024 * 1024


class ContextParserBase(ABC):
    def __init__(self, config: Optional[ParseConfig] = None):
        self._config = config or ParseConfig()
        self._field_validators: Dict[str, Callable] = {}
        self._field_transformers: Dict[str, Callable] = {}
        self._required_fields: Set[str] = set()
        self._optional_fields: Set[str] = set()

    @abstractmethod
    def parse(self, data: str) -> ParseResult:
        pass

    @abstractmethod
    def serialize(self, context: Any) -> str:
        pass

    def add_validator(self, field: str, validator: Callable) -> None:
        self._field_validators[field] = validator

    def add_transformer(self, field: str, transformer: Callable) -> None:
        self._field_transformers[field] = transformer

    def set_required_fields(self, fields: List[str]) -> None:
        self._required_fields = set(fields)

    def set_optional_fields(self, fields: List[str]) -> None:
        self._optional_fields = set(fields)

    def validate_required_fields(self, data: Dict) -> Tuple[bool, List[str]]:
        missing = []
        for field in self._required_fields:
            if field not in data:
                missing.append(field)
        return len(missing) == 0, missing

    def transform_fields(self, data: Dict) -> Dict:
        result = data.copy()
        for field, transformer in self._field_transformers.items():
            if field in result:
                try:
                    result[field] = transformer(result[field])
                except Exception as e:
                    logger.warning(f"Transform failed for {field}: {e}")
        return result

    def validate_fields(self, data: Dict) -> Tuple[bool, List[str]]:
        errors = []
        for field, validator in self._field_validators.items():
            if field in data:
                try:
                    if not validator(data[field]):
                        errors.append(f"Validation failed for {field}")
                except Exception as e:
                    errors.append(f"Validator error for {field}: {e}")
        return len(errors) == 0, errors


class JsonContextParser(ContextParserBase):
    def __init__(self, config: Optional[ParseConfig] = None):
        super().__init__(config)
        self._set_default_fields()

    def _set_default_fields(self):
        self._required_fields = {"audit_id", "title", "context_type"}
        self._optional_fields = {"description", "status", "priority", "auditor"}

    def parse(self, data: str) -> ParseResult:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            return ParseResult(False, errors=[f"JSON parse error: {e}"])

        if self._config.normalize_keys:
            parsed = self._normalize_keys(parsed)

        if self._config.convert_types:
            parsed = self._convert_types(parsed)

        valid, missing = self.validate_required_fields(parsed)
        if not valid and self._config.strict:
            return ParseResult(False, errors=[f"Missing required fields: {missing}"])

        data = self.transform_fields(parsed)

        valid, errors = self.validate_fields(data)
        if not valid:
            return ParseResult(False, errors=errors)

        context_type = parsed.get("context_type")
        if not context_type:
            return ParseResult(False, errors=["context_type is required"])

        try:
            context = self._create_context(context_type, parsed)
            return ParseResult(True, data=context, metadata={"type": context_type})
        except Exception as e:
            return ParseResult(False, errors=[f"Context creation error: {e}"])

    def _normalize_keys(self, data: Dict) -> Dict:
        result = {}
        for key, value in data.items():
            new_key = key.lower().replace("-", "_")
            result[new_key] = value
        return result

    def _convert_types(self, data: Dict) -> Dict:
        result = {}
        for key, value in data.items():
            if key == "context_type" and isinstance(value, str):
                try:
                    value = ContextType(value)
                except ValueError:
                    pass
            elif key == "severity" and isinstance(value, str):
                try:
                    value = Severity(value)
                except ValueError:
                    pass
            elif key == "status" and isinstance(value, str):
                try:
                    value = Status(value)
                except ValueError:
                    pass
            elif key == "priority" and isinstance(value, str):
                try:
                    value = ContextPriority(int(value))
                except ValueError:
                    try:
                        value = ContextPriority[value.upper()]
                    except KeyError:
                        pass
            result[key] = value
        return result

    def _create_context(self, context_type: ContextType, data: Dict) -> Any:
        if context_type == ContextType.AUDIT:
            return self._parse_audit_context(data)
        elif context_type == ContextType.HUNT:
            return self._parse_hunt_context(data)
        elif context_type == ContextType.SCAN:
            return self._parse_scan_context(data)
        elif context_type == ContextType.INVESTIGATION:
            return self._parse_investigation_context(data)
        elif context_type == ContextType.MONITORING:
            return self._parse_monitoring_context(data)
        elif context_type == ContextType.BREACH:
            return self._parse_breach_context(data)
        elif context_type == ContextType.THREAT_INTEL:
            return self._parse_threat_intel_context(data)
        elif context_type == ContextType.INCIDENT_RESPONSE:
            return self._parse_incident_response_context(data)
        else:
            raise ValueError(f"Unknown context type: {context_type}")

    def _parse_audit_context(self, data: Dict) -> AuditContext:
        return AuditContext(
            audit_id=data.get("audit_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.AUDIT),
            status=data.get("status", Status.PENDING),
            priority=data.get("priority", ContextPriority.P2),
            auditor=data.get("auditor"),
            scope=data.get("scope", []),
            targets=data.get("targets", []),
            rules=data.get("rules", []),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
            end_time=self._parse_datetime(data.get("end_time")),
        )

    def _parse_hunt_context(self, data: Dict) -> HuntContext:
        return HuntContext(
            hunt_id=data.get("hunt_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.HUNT),
            status=data.get("status", Status.PENDING),
            priority=data.get("priority", ContextPriority.P1),
            hunter=data.get("hunter"),
            target_addresses=data.get("target_addresses", []),
            target_networks=data.get("target_networks", []),
            suspicious_contracts=data.get("suspicious_contracts", []),
            malicious_patterns=data.get("malicious_patterns", []),
            ioc_list=data.get("ioc_list", []),
            threat_actors=data.get("threat_actors", []),
            campaigns=data.get("campaigns", []),
            TTPs=data.get("TTPs", []),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
            end_time=self._parse_datetime(data.get("end_time")),
        )

    def _parse_scan_context(self, data: Dict) -> ScanContext:
        return ScanContext(
            scan_id=data.get("scan_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.SCAN),
            status=data.get("status", Status.PENDING),
            priority=data.get("priority", ContextPriority.P2),
            scanner=data.get("scanner"),
            scan_type=data.get("scan_type", "full"),
            target_patterns=data.get("target_patterns", []),
            rules_applied=data.get("rules_applied", []),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
            end_time=self._parse_datetime(data.get("end_time")),
        )

    def _parse_investigation_context(self, data: Dict) -> InvestigationContext:
        return InvestigationContext(
            investigation_id=data.get("investigation_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.INVESTIGATION),
            status=data.get("status", Status.PENDING),
            priority=data.get("priority", ContextPriority.P0),
            investigator=data.get("investigator"),
            subject=data.get("subject", ""),
            subject_type=data.get("subject_type", ""),
            evidence=data.get("evidence", []),
            timeline=data.get("timeline", []),
            witnesses=data.get("witnesses", []),
            suspects=data.get("suspects", []),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
            end_time=self._parse_datetime(data.get("end_time")),
        )

    def _parse_monitoring_context(self, data: Dict) -> MonitoringContext:
        return MonitoringContext(
            monitor_id=data.get("monitor_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.MONITORING),
            status=data.get("status", Status.ACTIVE),
            priority=data.get("priority", ContextPriority.P1),
            monitor=data.get("monitor"),
            network=data.get("network", ""),
            addresses=data.get("addresses", []),
            alert_channels=data.get("alert_channels", []),
            thresholds=data.get("thresholds", {}),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
        )

    def _parse_breach_context(self, data: Dict) -> BreachContext:
        return BreachContext(
            breach_id=data.get("breach_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.BREACH),
            status=data.get("status", Status.PENDING),
            priority=data.get("priority", ContextPriority.P0),
            investigator=data.get("investigator"),
            affected_addresses=data.get("affected_addresses", []),
            affected_users=data.get("affected_users", []),
            funds_lost=data.get("funds_lost"),
            token=data.get("token"),
            attack_vector=data.get("attack_vector"),
            root_cause=data.get("root_cause"),
            timeline=data.get("timeline", []),
            mitigations=data.get("mitigations", []),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
            detection_time=self._parse_datetime(data.get("detection_time")),
        )

    def _parse_threat_intel_context(self, data: Dict) -> ThreatIntelContext:
        return ThreatIntelContext(
            intel_id=data.get("intel_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.THREAT_INTEL),
            status=data.get("status", Status.ACTIVE),
            priority=data.get("priority", ContextPriority.P2),
            collector=data.get("collector"),
            intel_type=data.get("intel_type", ""),
            source=data.get("source", ""),
            iocs=data.get("iocs", []),
            TTPs=data.get("TTPs", []),
            threat_actors=data.get("threat_actors", []),
            campaigns=data.get("campaigns", []),
            confidence=data.get("confidence", ""),
            reliability=data.get("reliability", ""),
            severity=data.get("severity", Severity.INFO),
            tlp=data.get("tlp", "AMBER"),
            metadata=data.get("metadata", {}),
            timestamp=self._parse_datetime(data.get("timestamp")),
            expires_at=self._parse_datetime(data.get("expires_at")),
        )

    def _parse_incident_response_context(self, data: Dict) -> IncidentResponseContext:
        return IncidentResponseContext(
            incident_id=data.get("incident_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            context_type=data.get("context_type", ContextType.INCIDENT_RESPONSE),
            status=data.get("status", Status.PENDING),
            priority=data.get("priority", ContextPriority.P0),
            responder=data.get("responder"),
            incident_type=data.get("incident_type", ""),
            severity=data.get("severity", Severity.HIGH),
            affected_systems=data.get("affected_systems", []),
            affected_users=data.get("affected_users", []),
            containment_actions=data.get("containment_actions", []),
            eradication_actions=data.get("eradication_actions", []),
            recovery_actions=data.get("recovery_actions", []),
            lessons_learned=data.get("lessons_learned", []),
            metadata=data.get("metadata", {}),
            start_time=self._parse_datetime(data.get("start_time")),
            containment_time=self._parse_datetime(data.get("containment_time")),
            eradication_time=self._parse_datetime(data.get("eradication_time")),
            recovery_time=self._parse_datetime(data.get("recovery_time")),
            end_time=self._parse_datetime(data.get("end_time")),
        )

    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)
        if isinstance(value, str):
            for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                      "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
        return None

    def serialize(self, context: Any) -> str:
        data = self._context_to_dict(context)
        return json.dumps(data, default=str, indent=2)

    def _context_to_dict(self, context: Any) -> Dict:
        if isinstance(context, AuditContext):
            return {
                "audit_id": context.audit_id,
                "title": context.title,
                "description": context.description,
                "context_type": context.context_type.value,
                "status": context.status.value,
                "priority": context.priority.value,
                "auditor": context.auditor,
                "scope": context.scope,
                "targets": context.targets,
                "rules": context.rules,
                "tags": context.tags,
                "metadata": context.metadata,
                "start_time": context.start_time.isoformat() if context.start_time else None,
                "end_time": context.end_time.isoformat() if context.end_time else None,
            }
        elif isinstance(context, HuntContext):
            return {
                "hunt_id": context.hunt_id,
                "title": context.title,
                "description": context.description,
                "context_type": context.context_type.value,
                "status": context.status.value,
                "priority": context.priority.value,
                "hunter": context.hunter,
                "target_addresses": context.target_addresses,
                "target_networks": context.target_networks,
                "suspicious_contracts": context.suspicious_contracts,
                "malicious_patterns": context.malicious_patterns,
                "ioc_list": context.ioc_list,
                "threat_actors": context.threat_actors,
                "campaigns": context.campaigns,
                "TTPs": context.TTPs,
                "metadata": context.metadata,
                "start_time": context.start_time.isoformat() if context.start_time else None,
                "end_time": context.end_time.isoformat() if context.end_time else None,
            }
        return {"error": "Unknown context type"}


class CsvContextParser(ContextParserBase):
    def __init__(self, config: Optional[ParseConfig] = None):
        super().__init__(config)

    def parse(self, data: str) -> ParseResult:
        try:
            reader = csv.DictReader(io.StringIO(data))
            rows = list(reader)
        except Exception as e:
            return ParseResult(False, errors=[f"CSV parse error: {e}"])

        contexts = []
        for row in rows:
            try:
                context = self._parse_row(row)
                contexts.append(context)
            except Exception as e:
                logger.warning(f"Row parse error: {e}")

        return ParseResult(True, data=contexts, metadata={"count": len(contexts)})

    def _parse_row(self, row: Dict) -> Dict:
        return {k.strip(): v.strip() for k, v in row.items() if v}

    def serialize(self, contexts: List[Any]) -> str:
        if not contexts:
            return ""

        output = io.StringIO()
        fieldnames = ["id", "title", "description", "type", "status", "priority"]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for context in contexts:
            writer.writerow({
                "id": getattr(context, 'audit_id', getattr(context, 'hunt_id', '')),
                "title": context.title,
                "description": context.description,
                "type": context.context_type.value if hasattr(context, 'context_type') else '',
                "status": context.status.value if hasattr(context, 'status') else '',
                "priority": context.priority.value if hasattr(context, 'priority') else '',
            })
        
        return output.getvalue()


class XmlContextParser(ContextParserBase):
    def __init__(self, config: Optional[ParseConfig] = None):
        super().__init__(config)

    def parse(self, data: str) -> ParseResult:
        try:
            root = ET.fromstring(data)
        except ET.ParseError as e:
            return ParseResult(False, errors=[f"XML parse error: {e}"])

        contexts = []
        for element in root.findall(".//context"):
            try:
                context = self._parse_element(element)
                contexts.append(context)
            except Exception as e:
                logger.warning(f"Element parse error: {e}")

        return ParseResult(True, data=contexts, metadata={"count": len(contexts)})

    def _parse_element(self, element: ET.Element) -> Dict:
        return {child.tag: child.text for child in element}

    def serialize(self, context: Any) -> str:
        root = ET.Element("contexts")
        
        context_elem = ET.SubElement(root, "context")
        
        for key, value in self._context_to_dict(context).items():
            child = ET.SubElement(context_elem, key)
            child.text = str(value)
        
        return ET.tostring(root, encoding="unicode")

    def _context_to_dict(self, context: Any) -> Dict:
        return {
            "id": getattr(context, 'audit_id', getattr(context, 'hunt_id', '')),
            "title": context.title,
            "description": context.description,
            "type": context.context_type.value if hasattr(context, 'context_type') else '',
        }


class MultiFormatParser:
    def __init__(self, config: Optional[ParseConfig] = None):
        self._config = config or ParseConfig()
        self._parsers: Dict[ParseFormat, ContextParserBase] = {
            ParseFormat.JSON: JsonContextParser(config),
            ParseFormat.CSV: CsvContextParser(config),
            ParseFormat.XML: XmlContextParser(config),
        }

    def parse(self, data: str, format: ParseFormat = ParseFormat.JSON) -> ParseResult:
        parser = self._parsers.get(format)
        if not parser:
            return ParseResult(False, errors=[f"No parser for format: {format}"])
        return parser.parse(data)

    def serialize(self, context: Any, format: ParseFormat = ParseFormat.JSON) -> str:
        parser = self._parsers.get(format)
        if not parser:
            raise ValueError(f"No parser for format: {format}")
        return parser.serialize(context)

    def detect_format(self, data: str) -> ParseFormat:
        data = data.strip()
        if data.startswith("{"):
            return ParseFormat.JSON
        elif data.startswith("["):
            return ParseFormat.JSON
        elif data.startswith("<"):
            return ParseFormat.XML
        elif "," in data and "\n" in data:
            return ParseFormat.CSV
        else:
            return ParseFormat.JSON

    def auto_parse(self, data: str) -> ParseResult:
        format = self.detect_format(data)
        return self.parse(data, format)


class ContextSerializer:
    def __init__(self):
        self._json_parser = JsonContextParser()

    def serialize(self, context: Any, format: ParseFormat = ParseFormat.JSON) -> str:
        if format == ParseFormat.JSON:
            return self._json_parser.serialize(context)
        else:
            raise ValueError(f"Unsupported format: {format}")


class BatchContextParser:
    def __init__(self):
        self._parser = MultiFormatParser()

    def parse_file(self, filepath: str, format: Optional[ParseFormat] = None) -> ParseResult:
        with open(filepath, 'r') as f:
            data = f.read()

        if format is None:
            format = self._parser.detect_format(data)

        result = self._parser.parse(data, format)
        
        if result.success:
            result.metadata["source_file"] = filepath
        
        return result

    def serialize_to_file(self, contexts: List[Any], filepath: str,
                    format: ParseFormat = ParseFormat.JSON) -> bool:
        try:
            if not contexts:
                return False

            data = self._parser.serialize(contexts[0], format)
            
            with open(filepath, 'w') as f:
                f.write(data)
            
            return True
        except Exception as e:
            logger.error(f"Serialize error: {e}")
            return False


class ContextParserCache:
    def __init__(self, max_size: int = 100):
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            timestamp, context = self._cache[key]
            self._hits += 1
            return context
        self._misses += 1
        return None

    def set(self, key: str, context: Any) -> None:
        if len(self._cache) >= self._max_size:
            oldest = min(self._cache.items(), key=lambda x: x[1][0])
            del self._cache[oldest[0]]
        
        self._cache[key] = (datetime.now().timestamp(), context)

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def get_stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "size": len(self._cache)
        }


def parse_context(data: str, format: ParseFormat = ParseFormat.JSON) -> ParseResult:
    parser = MultiFormatParser()
    return parser.parse(data, format)


def parse_context_file(filepath: str) -> ParseResult:
    parser = BatchContextParser()
    return parser.parse_file(filepath)


def serialize_context(context: Any, format: ParseFormat = ParseFormat.JSON) -> str:
    parser = MultiFormatParser()
    return parser.serialize(context, format)


def serialize_contexts_to_file(contexts: List[Any], filepath: str) -> bool:
    parser = BatchContextParser()
    format = ParseFormat.JSON if filepath.endswith(".json") else ParseFormat.CSV if filepath.endswith(".csv") else ParseFormat.XML
    return parser.serialize_to_file(contexts, filepath, format)