"""
SoliGuard MCP Resources
MCP resources for model context protocol

Author: Peace Stephen (Tech Lead)
Description: MCP resources implementation
"""

import re
import logging
import json
import os
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    FILE = "file"
    CONTRACT = "contract"
    FINDING = "finding"
    REPORT = "report"
    CONFIG = "config"
    CACHE = "cache"
    SESSION = "session"


class ResourceFormat(Enum):
    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"
    BINARY = "binary"


class ResourceStatus(Enum):
    AVAILABLE = "available"
    IN_USE = "in_use"
    LOCKED = "locked"
    UNAVAILABLE = "unavailable"


@dataclass
class Resource:
    resource_id: str
    resource_type: ResourceType
    name: str
    path: str
    format: ResourceFormat = ResourceFormat.TEXT
    size: int = 0
    status: ResourceStatus = ResourceStatus.AVAILABLE
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)


class BaseResourceManager(ABC):
    def __init__(self, name: str):
        self.name = name
        self.resources: Dict[str, Resource] = {}
        self.locked_resources: Set[str] = set()
        
    @abstractmethod
    def get(self, resource_id: str) -> Optional[Resource]:
        pass
    
    @abstractmethod
    def list(self, resource_type: Optional[ResourceType] = None) -> List[Resource]:
        pass
    
    @abstractmethod
    def create(self, resource: Resource) -> bool:
        pass
    
    @abstractmethod
    def delete(self, resource_id: str) -> bool:
        pass
    
    @abstractmethod
    def lock(self, resource_id: str) -> bool:
        pass
    
    @abstractmethod
    def unlock(self, resource_id: str) -> bool:
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_resources": len(self.resources),
            "locked_resources": len(self.locked_resources),
            "resource_types": list(set(r.resource_type.value for r in self.resources.values()))
        }


class FileResourceManager(BaseResourceManager):
    def __init__(self, name: str = "file_manager"):
        super().__init__(name)
        
    def get(self, resource_id: str) -> Optional[Resource]:
        return self.resources.get(resource_id)
        
    def list(self, resource_type: Optional[ResourceType] = None) -> List[Resource]:
        if resource_type:
            return [r for r in self.resources.values() if r.resource_type == resource_type]
        return list(self.resources.values())
        
    def create(self, resource: Resource) -> bool:
        if resource.resource_id in self.resources:
            return False
        self.resources[resource.resource_id] = resource
        return True
        
    def delete(self, resource_id: str) -> bool:
        if resource_id in self.resources:
            del self.resources[resource_id]
            return True
        return False
        
    def lock(self, resource_id: str) -> bool:
        if resource_id in self.resources and resource_id not in self.locked_resources:
            self.locked_resources.add(resource_id)
            self.resources[resource_id].status = ResourceStatus.LOCKED
            return True
        return False
        
    def unlock(self, resource_id: str) -> bool:
        if resource_id in self.locked_resources:
            self.locked_resources.remove(resource_id)
            self.resources[resource_id].status = ResourceStatus.AVAILABLE
            return True
        return False


class ContractResourceManager(BaseResourceManager):
    def __init__(self, name: str = "contract_manager"):
        super().__init__(name)
        
    def get(self, resource_id: str) -> Optional[Resource]:
        return self.resources.get(resource_id)
        
    def list(self, resource_type: Optional[ResourceType] = None) -> List[Resource]:
        if resource_type:
            return [r for r in self.resources.values() if r.resource_type == resource_type]
        return list(self.resources.values())
        
    def create(self, resource: Resource) -> bool:
        if resource.resource_id in self.resources:
            return False
        self.resources[resource.resource_id] = resource
        return True
        
    def delete(self, resource_id: str) -> bool:
        if resource_id in self.resources:
            del self.resources[resource_id]
            return True
        return False
        
    def lock(self, resource_id: str) -> bool:
        if resource_id in self.resources and resource_id not in self.locked_resources:
            self.locked_resources.add(resource_id)
            self.resources[resource_id].status = ResourceStatus.LOCKED
            return True
        return False
        
    def unlock(self, resource_id: str) -> bool:
        if resource_id in self.locked_resources:
            self.locked_resources.remove(resource_id)
            self.resources[resource_id].status = ResourceStatus.AVAILABLE
            return True
        return False
        
    def load_contract(self, file_path: str) -> Optional[Resource]:
        if not os.path.exists(file_path):
            return None
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        resource_id = f"contract:{os.path.basename(file_path)}"
        
        resource = Resource(
            resource_id=resource_id,
            resource_type=ResourceType.CONTRACT,
            name=os.path.basename(file_path),
            path=file_path,
            format=ResourceFormat.TEXT,
            size=len(content),
            metadata={"lines": len(content.split('\n'))}
        )
        
        self.create(resource)
        return resource


class FindingResourceManager(BaseResourceManager):
    def __init__(self, name: str = "finding_manager"):
        super().__init__(name)
        
    def get(self, resource_id: str) -> Optional[Resource]:
        return self.resources.get(resource_id)
        
    def list(self, resource_type: Optional[ResourceType] = None) -> List[Resource]:
        if resource_type:
            return [r for r in self.resources.values() if r.resource_type == resource_type]
        return list(self.resources.values())
        
    def create(self, resource: Resource) -> bool:
        if resource.resource_id in self.resources:
            return False
        self.resources[resource.resource_id] = resource
        return True
        
    def delete(self, resource_id: str) -> bool:
        if resource_id in self.resources:
            del self.resources[resource_id]
            return True
        return False
        
    def lock(self, resource_id: str) -> bool:
        if resource_id in self.resources and resource_id not in self.locked_resources:
            self.locked_resources.add(resource_id)
            self.resources[resource_id].status = ResourceStatus.LOCKED
            return True
        return False
        
    def unlock(self, resource_id: str) -> bool:
        if resource_id in self.locked_resources:
            self.locked_resources.remove(resource_id)
            self.resources[resource_id].status = ResourceStatus.AVAILABLE
            return True
        return False
        
    def add_finding(self, finding_id: str, finding_data: Dict[str, Any]) -> Optional[Resource]:
        resource_id = f"finding:{finding_id}"
        
        resource = Resource(
            resource_id=resource_id,
            resource_type=ResourceType.FINDING,
            name=finding_id,
            path="",
            format=ResourceFormat.JSON,
            size=len(json.dumps(finding_data)),
            metadata=finding_data
        )
        
        self.create(resource)
        return resource


class ReportResourceManager(BaseResourceManager):
    def __init__(self, name: str = "report_manager"):
        super().__init__(name)
        
    def get(self, resource_id: str) -> Optional[Resource]:
        return self.resources.get(resource_id)
        
    def list(self, resource_type: Optional[ResourceType] = None) -> List[Resource]:
        if resource_type:
            return [r for r in self.resources.values() if r.resource_type == resource_type]
        return list(self.resources.values())
        
    def create(self, resource: Resource) -> bool:
        if resource.resource_id in self.resources:
            return False
        self.resources[resource.resource_id] = resource
        return True
        
    def delete(self, resource_id: str) -> bool:
        if resource_id in self.resources:
            del self.resources[resource_id]
            return True
        return False
        
    def lock(self, resource_id: str) -> bool:
        if resource_id in self.resources and resource_id not in self.locked_resources:
            self.locked_resources.add(resource_id)
            self.resources[resource_id].status = ResourceStatus.LOCKED
            return True
        return False
        
    def unlock(self, resource_id: str) -> bool:
        if resource_id in self.locked_resources:
            self.locked_resources.remove(resource_id)
            self.resources[resource_id].status = ResourceStatus.AVAILABLE
            return True
        return False
        
    def generate_report(
        self,
        report_id: str,
        findings: List[Dict[str, Any]],
        output_dir: str = "output"
    ) -> Optional[Resource]:
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, f"{report_id}.json")
        
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
            
        resource = Resource(
            resource_id=f"report:{report_id}",
            resource_type=ResourceType.REPORT,
            name=f"{report_id}.json",
            path=output_file,
            format=ResourceFormat.JSON,
            size=os.path.getsize(output_file),
            metadata={"findings_count": len(findings)}
        )
        
        self.create(resource)
        return resource


def create_resource_manager(manager_type: str) -> BaseResourceManager:
    managers = {
        "file": FileResourceManager,
        "contract": ContractResourceManager,
        "finding": FindingResourceManager,
        "report": ReportResourceManager,
    }
    
    manager_class = managers.get(manager_type, FileResourceManager)
    return manager_class()


_default_resource_manager: Optional[FileResourceManager] = None
_contract_manager: Optional[ContractResourceManager] = None
_finding_manager: Optional[FindingResourceManager] = None
_report_manager: Optional[ReportResourceManager] = None


def get_default_resource_manager() -> FileResourceManager:
    global _default_resource_manager
    
    if _default_resource_manager is None:
        _default_resource_manager = FileResourceManager()
        
    return _default_resource_manager


def get_contract_manager() -> ContractResourceManager:
    global _contract_manager
    
    if _contract_manager is None:
        _contract_manager = ContractResourceManager()
        
    return _contract_manager


def get_finding_manager() -> FindingResourceManager:
    global _finding_manager
    
    if _finding_manager is None:
        _finding_manager = FindingResourceManager()
        
    return _finding_manager


def get_report_manager() -> ReportResourceManager:
    global _report_manager
    
    if _report_manager is None:
        _report_manager = ReportResourceManager()
        
    return _report_manager


def register_resource(resource: Resource) -> bool:
    return get_default_resource_manager().create(resource)


def get_resource(resource_id: str) -> Optional[Resource]:
    return get_default_resource_manager().get(resource_id)


def list_resources(resource_type: Optional[ResourceType] = None) -> List[Resource]:
    return get_default_resource_manager().list(resource_type)


def delete_resource(resource_id: str) -> bool:
    return get_default_resource_manager().delete(resource_id)


def lock_resource(resource_id: str) -> bool:
    return get_default_resource_manager().lock(resource_id)


def unlock_resource(resource_id: str) -> bool:
    return get_default_resource_manager().unlock(resource_id)


def load_contract(file_path: str) -> Optional[Resource]:
    return get_contract_manager().load_contract(file_path)


def add_finding(finding_id: str, finding_data: Dict[str, Any]) -> Optional[Resource]:
    return get_finding_manager().add_finding(finding_id, finding_data)


def generate_report(
    report_id: str,
    findings: List[Dict[str, Any]],
    output_dir: str = "output"
) -> Optional[Resource]:
    return get_report_manager().generate_report(report_id, findings, output_dir)


def get_resource_stats() -> Dict[str, Any]:
    return {
        "file": get_default_resource_manager().get_stats(),
        "contract": get_contract_manager().get_stats(),
        "finding": get_finding_manager().get_stats(),
        "report": get_report_manager().get_stats()
    }