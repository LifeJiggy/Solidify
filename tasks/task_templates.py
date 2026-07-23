"""
Task Templates Module for Solidify Security Scanner

This module provides comprehensive task template definitions, presets,
and template utilities for security scan operations. Contains pre-built
templates for common scanning scenarios.

Author: Solidify Security Team
Version: 1.0.0
"""

import os
import json
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Set, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from collections import defaultdict
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TaskTemplateType(Enum):
    """Template type categories"""
    SECURITY = "security"
    ANALYSIS = "analysis"
    OPTIMIZATION = "optimization"
    COMPLIANCE = "compliance"
    DEPLOYMENT = "deployment"
    MAINTENANCE = "maintenance"


class ScanLevel(Enum):
    """Scan depth levels"""
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    COMPREHENSIVE = "comprehensive"


class RuleCategory(Enum):
    """Security rule categories"""
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    front_run = "front_run"
    oracle = "oracle"
    VALIDATION = "validation"
    AUTHORIZATION = "authorization"


@dataclass
class TemplateMetadata:
    """Template metadata"""
    author: str = "Solidify"
    version: str = "1.0.0"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)


@dataclass
class RuleTemplate:
    """Template for security rule"""
    rule_id: str
    name: str
    category: RuleCategory
    severity: str
    pattern: str
    description: str
    cwe_id: str = ""
    recommendation: str = ""
    false_positive_filters: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'category': self.category.value,
            'severity': self.severity,
            'pattern': self.pattern,
            'description': self.description,
            'cwe_id': self.cwe_id,
            'recommendation': self.recommendation
        }


@dataclass
class ScanTemplate:
    """Security scan template"""
    template_id: str
    name: str
    template_type: TaskTemplateType
    scan_level: ScanLevel
    rules: List[str] = field(default_factory=list)
    exclude_rules: List[str] = field(default_factory=list)
    timeout: int = 3600
    metadata: TemplateMetadata = field(default_factory=TemplateMetadata)
    config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'template_id': self.template_id,
            'name': self.name,
            'template_type': self.template_type.value,
            'scan_level': self.scan_level.value,
            'rules': self.rules,
            'exclude_rules': self.exclude_rules,
            'timeout': self.timeout,
            'metadata': {
                'author': self.metadata.author,
                'version': self.metadata.version,
                'description': self.metadata.description
            },
            'config': self.config
        }
    
    def validate(self) -> List[str]:
        """Validate template"""
        errors = []
        
        if not self.template_id:
            errors.append("Template ID is required")
        
        if not self.name:
            errors.append("Template name is required")
        
        if self.timeout <= 0:
            errors.append("Timeout must be positive")
        
        return errors
    
    def merge(self, overrides: Dict[str, Any]) -> 'ScanTemplate':
        """Create merged template"""
        return ScanTemplate(
            template_id=overrides.get('template_id', self.template_id),
            name=overrides.get('name', self.name),
            template_type=overrides.get('template_type', self.template_type),
            scan_level=overrides.get('scan_level', self.scan_level),
            rules=overrides.get('rules', self.rules),
            exclude_rules=overrides.get('exclude_rules', self.exclude_rules),
            timeout=overrides.get('timeout', self.timeout),
            metadata=self.metadata,
            config={**self.config, **overrides.get('config', {})}
        )


class TemplateLibrary:
    """Manages template library"""
    
    def __init__(self):
        self.templates: Dict[str, ScanTemplate] = {}
        self.templates_by_category: Dict[TaskTemplateType, List[str]] = defaultdict(list)
        self._register_default_templates()
    
    def _register_default_templates(self) -> None:
        """Register default templates"""
        
        self.register_template(ScanTemplate(
            template_id="security_quick",
            name="Quick Security Scan",
            template_type=TaskTemplateType.SECURITY,
            scan_level=ScanLevel.QUICK,
            rules=["REENT-001", "OVERFLOW-001", "ACCESS-001"],
            timeout=600,
            metadata=TemplateMetadata(
                description="Fast scan for critical vulnerabilities",
                tags=["quick", "critical"]
            )
        ))
        
        self.register_template(ScanTemplate(
            template_id="security_standard",
            name="Standard Security Scan",
            template_type=TaskTemplateType.SECURITY,
            scan_level=ScanLevel.STANDARD,
            rules=["REENT-001", "REENT-002", "OVERFLOW-001", "OVERFLOW-002",
                  "ACCESS-001", "ACCESS-002", "CALL-001", "CALL-002"],
            timeout=1800,
            metadata=TemplateMetadata(
                description="Standard security scan with common rules",
                tags=["security", "standard"]
            )
        ))
        
        self.register_template(ScanTemplate(
            template_id="security_deep",
            name="Deep Security Scan",
            template_type=TaskTemplateType.SECURITY,
            scan_level=ScanLevel.DEEP,
            rules=["REENT-001", "REENT-002", "REENT-003", "OVERFLOW-001",
                  "OVERFLOW-002", "OVERFLOW-003", "ACCESS-001", "ACCESS-002",
                  "ACCESS-003", "CALL-001", "CALL-002", "CALL-003",
                  "FRONT-001", "ORACLE-001", "ORACLE-002"],
            timeout=3600,
            metadata=TemplateMetadata(
                description="Comprehensive security scan",
                tags=["security", "deep", "complete"]
            )
        ))
        
        self.register_template(ScanTemplate(
            template_id="comprehensive",
            name="Comprehensive Security Scan",
            template_type=TaskTemplateType.SECURITY,
            scan_level=ScanLevel.COMPREHENSIVE,
            timeout=7200,
            metadata=TemplateMetadata(
                description="Full security scan with all rules",
                tags=["security", "comprehensive", "full"]
            )
        ))
        
        self.register_template(ScanTemplate(
            template_id="gas_analysis",
            name="Gas Optimization Scan",
            template_type=TaskTemplateType.OPTIMIZATION,
            scan_level=ScanLevel.STANDARD,
            rules=["GAS-001", "GAS-002", "GAS-003", "GAS-004"],
            timeout=1800,
            metadata=TemplateMetadata(
                description="Analyze gas optimization opportunities",
                tags=["gas", "optimization"]
            ),
            config={'optimization_level': 'standard'}
        ))
        
        self.register_template(ScanTemplate(
            template_id="compliance_erc20",
            name="ERC20 Compliance Check",
            template_type=TaskTemplateType.COMPLIANCE,
            scan_level=ScanLevel.STANDARD,
            rules=["COMP-ERC20-001", "COMP-ERC20-002"],
            timeout=900,
            metadata=TemplateMetadata(
                description="Check ERC20 compliance",
                tags=["compliance", "erc20"]
            ),
            config={'standard': 'erc20'}
        ))
        
        self.register_template(ScanTemplate(
            template_id="compliance_erc721",
            name="ERC721 Compliance Check",
            template_type=TaskTemplateType.COMPLIANCE,
            scan_level=ScanLevel.STANDARD,
            rules=["COMP-ERC721-001", "COMP-ERC721-002"],
            timeout=900,
            metadata=TemplateMetadata(
                description="Check ERC721 compliance",
                tags=["compliance", "erc721"]
            ),
            config={'standard': 'erc721'}
        ))
        
        self.register_template(ScanTemplate(
            template_id="access_control",
            name="Access Control Audit",
            template_type=TaskTemplateType.ANALYSIS,
            scan_level=ScanLevel.DEEP,
            rules=["ACCESS-001", "ACCESS-002", "ACCESS-003", "ACCESS-004"],
            timeout=1800,
            metadata=TemplateMetadata(
                description="Detailed access control analysis",
                tags=["access", "authorization"]
            )
        ))
        
        self.register_template(ScanTemplate(
            template_id="oracle_analysis",
            name="Oracle Manipulation Analysis",
            template_type=TaskTemplateType.ANALYSIS,
            scan_level=ScanLevel.DEEP,
            rules=["ORACLE-001", "ORACLE-002", "ORACLE-003", "ORACLE-004"],
            timeout=1800,
            metadata=TemplateMetadata(
                description="Analyze oracle manipulation risks",
                tags=["oracle", "price", "manipulation"]
            )
        ))
    
    def register_template(self, template: ScanTemplate) -> None:
        """Register template"""
        self.templates[template.template_id] = template
        self.templates_by_category[template.template_type].append(template.template_id)
    
    def get_template(self, template_id: str) -> Optional[ScanTemplate]:
        """Get template by ID"""
        return self.templates.get(template_id)
    
    def get_templates_by_type(self, template_type: TaskTemplateType) -> List[ScanTemplate]:
        """Get templates by type"""
        ids = self.templates_by_category.get(template_type, [])
        return [self.templates[tid] for tid in ids if tid in self.templates]
    
    def search_templates(self, query: str) -> List[ScanTemplate]:
        """Search templates"""
        results = []
        query_lower = query.lower()
        
        for template in self.templates.values():
            if query_lower in template.name.lower():
                results.append(template)
            elif query_lower in template.metadata.description.lower():
                results.append(template)
            elif any(query_lower in tag.lower() for tag in template.metadata.tags):
                results.append(template)
        
        return results
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all templates"""
        return [t.to_dict() for t in self.templates.values()]


class TemplateBuilder:
    """Builds custom templates"""
    
    def __init__(self, library: Optional[TemplateLibrary] = None):
        self.library = library or TemplateLibrary()
    
    def build_from_base(self, base_id: str, 
                   name: str, overrides: Dict[str, Any] = None) -> Optional[ScanTemplate]:
        """Build template from base"""
        base = self.library.get_template(base_id)
        if not base:
            return None
        
        return base.merge(overrides or {})
    
    def build_custom(self, name: str, rules: List[str],
                 template_type: TaskTemplateType = TaskTemplateType.SECURITY,
                 scan_level: ScanLevel = ScanLevel.STANDARD,
                 **kwargs) -> ScanTemplate:
        """Build custom template"""
        template_id = f"custom_{hashlib.md5(name.encode()).hexdigest()[:8]}"
        
        return ScanTemplate(
            template_id=template_id,
            name=name,
            template_type=template_type,
            scan_level=scan_level,
            rules=rules,
            **kwargs
        )
    
    def build_preset(self, preset: str) -> Optional[ScanTemplate]:
        """Build preset template"""
        presets = {
            'audit': self.library.get_template('security_deep'),
            'quick': self.library.get_template('security_quick'),
            'standard': self.library.get_template('security_standard'),
            'gas': self.library.get_template('gas_analysis'),
            'compliance': self.library.get_template('compliance_erc20')
        }
        return presets.get(preset)


class TemplateValidator:
    """Validates templates"""
    
    def __init__(self, library: Optional[TemplateLibrary] = None):
        self.library = library or TemplateLibrary()
        self.validation_rules = self._init_validation_rules()
    
    def _init_validation_rules(self) -> Dict[str, Callable]:
        """Initialize validation rules"""
        return {
            'template_id': self._validate_id,
            'name': self._validate_name,
            'rules': self._validate_rules,
            'timeout': self._validate_timeout,
            'config': self._validate_config
        }
    
    def validate(self, template: ScanTemplate) -> Dict[str, List[str]]:
        """Validate template"""
        errors = defaultdict(list)
        
        template_errors = template.validate()
        if template_errors:
            errors['template'].extend(template_errors)
        
        for field_name, validator in self.validation_rules.items():
            field_errors = validator(getattr(template, field_name, None))
            if field_errors:
                errors[field_name].extend(field_errors)
        
        return dict(errors)
    
    def _validate_id(self, template_id: str) -> List[str]:
        """Validate template ID"""
        errors = []
        
        if not template_id:
            errors.append("Template ID is required")
        elif len(template_id) < 3:
            errors.append("Template ID too short")
        elif not re.match(r'^[a-z0-9_]+$', template_id):
            errors.append("Invalid template ID format")
        
        return errors
    
    def _validate_name(self, name: str) -> List[str]:
        """Validate template name"""
        errors = []
        
        if not name:
            errors.append("Template name is required")
        elif len(name) < 3:
            errors.append("Template name too short")
        elif len(name) > 100:
            errors.append("Template name too long")
        
        return errors
    
    def _validate_rules(self, rules: List[str]) -> List[str]:
        """Validate rule list"""
        errors = []
        
        if not rules:
            return errors
        
        for rule_id in rules:
            if not rule_id or not isinstance(rule_id, str):
                errors.append(f"Invalid rule: {rule_id}")
        
        return errors
    
    def _validate_timeout(self, timeout: int) -> List[str]:
        """Validate timeout"""
        errors = []
        
        if timeout <= 0:
            errors.append("Timeout must be positive")
        elif timeout > 7200:
            errors.append("Timeout too large")
        
        return errors
    
    def _validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate config"""
        errors = []
        
        if not isinstance(config, dict):
            errors.append("Config must be dictionary")
        
        return errors


class TemplateExporter:
    """Exports templates"""
    
    def __init__(self, library: TemplateLibrary):
        self.library = library
    
    def export_to_json(self, filepath: str, 
                   template_ids: List[str] = None) -> bool:
        """Export to JSON"""
        try:
            templates = self.library.templates
            
            if template_ids:
                templates = {k: v for k, v in templates.items() 
                         if k in template_ids}
            
            data = {k: v.to_dict() for k, v in templates.items()}
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def export_to_yaml(self, filepath: str,
                   template_ids: List[str] = None) -> bool:
        """Export to YAML"""
        try:
            templates = self.library.templates
            
            if template_ids:
                templates = {k: v for k, v in templates.items() 
                         if k in template_ids}
            
            content = ""
            for template in templates.values():
                content += f"# {template.name}\n"
                content += f"template_id: {template.template_id}\n"
                content += f"scan_level: {template.scan_level.value}\n"
                content += f"rules: {json.dumps(template.rules)}\n"
                content += f"timeout: {template.timeout}\n\n"
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            return True
        except Exception as e:
            logger.error(f"Export to YAML failed: {e}")
            return False
    
    def export_to_markdown(self, filepath: str) -> bool:
        """Export to Markdown documentation"""
        try:
            content = "# Scan Templates\n\n"
            
            for template in self.library.templates.values():
                content += f"## {template.name}\n\n"
                content += f"**ID:** `{template.template_id}`\n\n"
                content += f"**Type:** {template.template_type.value}\n\n"
                content += f"**Level:** {template.scan_level.value}\n\n"
                
                if template.metadata.description:
                    content += f"{template.metadata.description}\n\n"
                
                if template.rules:
                    content += f"**Rules:** {len(template.rules)}\n\n"
                
                content += "---\n\n"
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            return True
        except Exception as e:
            logger.error(f"Export to Markdown failed: {e}")
            return False


class TemplateImporter:
    """Imports templates"""
    
    def __init__(self, library: TemplateLibrary):
        self.library = library
    
    def import_from_json(self, filepath: str) -> List[ScanTemplate]:
        """Import from JSON"""
        templates = []
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            for template_data in data.values():
                template = ScanTemplate(
                    template_id=template_data['template_id'],
                    name=template_data['name'],
                    template_type=TaskTemplateType(template_data['template_type']),
                    scan_level=ScanLevel(template_data['scan_level']),
                    rules=template_data.get('rules', []),
                    timeout=template_data.get('timeout', 3600)
                )
                templates.append(template)
                self.library.register_template(template)
        
        except Exception as e:
            logger.error(f"Import failed: {e}")
        
        return templates
    
    def import_from_dict(self, data: Dict[str, Any]) -> Optional[ScanTemplate]:
        """Import from dictionary"""
        try:
            template = ScanTemplate(
                template_id=data['template_id'],
                name=data['name'],
                template_type=TaskTemplateType(data['template_type']),
                scan_level=ScanLevel(data['scan_level']),
                rules=data.get('rules', []),
                timeout=data.get('timeout', 3600),
                config=data.get('config', {})
            )
            
            self.library.register_template(template)
            return template
        
        except Exception as e:
            logger.error(f"Import failed: {e}")
            return None


class TemplatePresetGenerator:
    """Generates template presets"""
    
    def __init__(self, library: TemplateLibrary):
        self.library = library
    
    def generate_preset(self, level: ScanLevel) -> ScanTemplate:
        """Generate preset for level"""
        if level == ScanLevel.QUICK:
            return self.library.get_template('security_quick')
        elif level == ScanLevel.STANDARD:
            return self.library.get_template('security_standard')
        elif level == ScanLevel.DEEP:
            return self.library.get_template('security_deep')
        else:
            return self.library.get_template('comprehensive')
    
    def generate_custom_preset(self, name: str, 
                            includes: List[str],
                            excludes: List[str] = None) -> ScanTemplate:
        """Generate custom preset"""
        builder = TemplateBuilder(self.library)
        return builder.build_custom(
            name=name,
            rules=includes,
            exclude_rules=excludes or []
        )
    
    def generate_category_preset(self, category: RuleCategory) -> ScanTemplate:
        """Generate category preset"""
        rule_map = {
            RuleCategory.REENTRANCY: ["REENT-001", "REENT-002", "REENT-003"],
            RuleCategory.ACCESS_CONTROL: ["ACCESS-001", "ACCESS-002", "ACCESS-003"],
            RuleCategory.ARITHMETIC: ["OVERFLOW-001", "OVERFLOW-002"],
            RuleCategory.front_run: ["FRONT-001", "FRONT-002"],
            RuleCategory.oracle: ["ORACLE-001", "ORACLE-002"]
        }
        
        rules = rule_map.get(category, [])
        
        builder = TemplateBuilder(self.library)
        return builder.build_custom(
            name=f"{category.value.title()} Analysis",
            rules=rules,
            template_type=TaskTemplateType.ANALYSIS
        )


_default_library: Optional[TemplateLibrary] = None


def get_template_library() -> TemplateLibrary:
    """Get or create default library"""
    global _default_library
    if _default_library is None:
        _default_library = TemplateLibrary()
    return _default_library


def get_template(template_id: str) -> Optional[ScanTemplate]:
    """Quick helper to get template"""
    library = get_template_library()
    return library.get_template(template_id)


def list_templates() -> List[Dict[str, Any]]:
    """Quick helper to list templates"""
    library = get_template_library()
    return library.list_templates()


def create_template(name: str, rules: List[str],
                template_type: str = "security") -> Optional[ScanTemplate]:
    """Quick helper to create template"""
    library = get_template_library()
    builder = TemplateBuilder(library)
    return builder.build_custom(name, rules, TaskTemplateType(template_type))


def import_templates(filepath: str) -> int:
    """Quick helper to import templates"""
    library = get_template_library()
    importer = TemplateImporter(library)
    templates = importer.import_from_json(filepath)
    return len(templates)


def export_templates(filepath: str, format: str = "json") -> bool:
    """Quick helper to export templates"""
    library = get_template_library()
    exporter = TemplateExporter(library)
    
    if format == "yaml":
        return exporter.export_to_yaml(filepath)
    elif format == "md":
        return exporter.export_to_markdown(filepath)
    else:
        return exporter.export_to_json(filepath)


if __name__ == "__main__":
    library = get_template_library()
    
    template = library.get_template('security_standard')
    print(f"Template: {template.to_dict()}")
    
    templates = library.list_templates()
    print(f"Total templates: {len(templates)}")