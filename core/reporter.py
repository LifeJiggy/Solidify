"""
SoliGuard Core Reporter
Comprehensive reporting and analytics engine

Author: Peace Stephen (Tech Lead)
Description: Production-grade reporting with multiple format support
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
import hashlib
import re

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"
    CSV = "csv"
    XML = "xml"


class ReportType(Enum):
    """Types of reports"""
    AUDIT = "audit"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    TREND = "trend"
    SUMMARY = "summary"
    DETAILED = "detailed"


class ReportStatus(Enum):
    """Report generation status"""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    CACHED = "cached"


@dataclass
class ReportConfig:
    """Report configuration"""
    format: ReportFormat = ReportFormat.JSON
    report_type: ReportType = ReportType.AUDIT
    include_raw_data: bool = False
    include_charts: bool = False
    max_items: int = 1000
    filters: Dict[str, Any] = field(default_factory=dict)
    group_by: Optional[str] = None


@dataclass
class ReportMetadata:
    """Report metadata"""
    report_id: str
    title: str
    description: str
    report_type: ReportType
    format: ReportFormat
    created_at: str
    generated_by: str
    version: str = "1.0"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    """Report definition"""
    metadata: ReportMetadata
    data: Any
    status: ReportStatus
    generation_time: float = 0.0
    error: Optional[str] = None
    file_path: Optional[str] = None


# ============================================================================
# Report Builder
# ============================================================================

class ReportBuilder:
    """Build reports with configurable options"""
    
    def __init__(self, config: ReportConfig):
        self.config = config
        self._sections: List[Dict[str, Any]] = []
    
    def add_section(self, title: str, content: Any, **kwargs):
        """Add a section to report"""
        self._sections.append({
            "title": title,
            "content": content,
            **kwargs
        })
    
    def add_summary(self, summary: Dict[str, Any]):
        """Add summary section"""
        self.add_section("Summary", summary)
    
    def add_table(self, title: str, headers: List[str], rows: List[List[Any]]):
        """Add table section"""
        self.add_section(title, {"headers": headers, "rows": rows}, type="table")
    
    def add_chart(self, title: str, chart_data: Dict[str, Any]):
        """Add chart section"""
        if self.config.include_charts:
            self.add_section(title, chart_data, type="chart")
    
    def build(self) -> Dict[str, Any]:
        """Build final report"""
        return {
            "config": self.config.__dict__,
            "sections": self._sections
        }


# ============================================================================
# Analytics Engine
# ============================================================================

class AnalyticsEngine:
    """Analytics and data processing engine"""
    
    def __init__(self):
        self._data_store: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._aggregations: Dict[str, Callable] = {}
    
    def add_data(self, event_type: str, data: Dict[str, Any]):
        """Add data to store"""
        self._data_store[event_type].append({
            **data,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def query(
        self,
        event_type: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query data with filters"""
        results = self._data_store.get(event_type, [])
        
        if filters:
            results = self._filter_results(results, filters)
        
        return results[-limit:]
    
    def _filter_results(
        self,
        results: List[Dict[str, Any]],
        filters: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Apply filters to results"""
        filtered = []
        
        for item in results:
            match = True
            for key, value in filters.items():
                if key not in item or item[key] != value:
                    match = False
                    break
            if match:
                filtered.append(item)
        
        return filtered
    
    def aggregate(
        self,
        event_type: str,
        field: str,
        agg_type: str = "sum"
    ) -> Union[float, int]:
        """Aggregate data"""
        results = self._data_store.get(event_type, [])
        
        if not results:
            return 0
        
        values = [r.get(field, 0) for r in results if field in r]
        
        if agg_type == "sum":
            return sum(values)
        elif agg_type == "avg":
            return sum(values) / len(values) if values else 0
        elif agg_type == "count":
            return len(values)
        elif agg_type == "max":
            return max(values) if values else 0
        elif agg_type == "min":
            return min(values) if values else 0
        
        return 0
    
    def group_by(self, event_type: str, field: str) -> Dict[str, List]:
        """Group results by field"""
        results = self._data_store.get(event_type, [])
        grouped = defaultdict(list)
        
        for item in results:
            key = item.get(field, "unknown")
            grouped[key].append(item)
        
        return dict(grouped)


# ============================================================================
# Report Generator
# ============================================================================

class ReportGenerator:
    """
    Production-grade report generator
    
    Features:
    - Multiple format support
    - Template system
    - Caching
    - Analytics integration
    - Export options
    """
    
    def __init__(self, config: Optional[ReportConfig] = None):
        """Initialize generator"""
        self.config = config or ReportConfig()
        self._templates: Dict[str, Callable] = {}
        self._cache: Dict[str, Report] = {}
        self._analytics = AnalyticsEngine()
        self._formatters: Dict[ReportFormat, Callable] = {}
        
        # Register default formatters
        self._register_default_formatters()
        
        logger.info("✅ Report generator initialized")
    
    def _register_default_formatters(self):
        """Register default formatters"""
        self._formatters[ReportFormat.JSON] = self._format_json
        self._formatters[ReportFormat.HTML] = self._format_html
        self._formatters[ReportFormat.MARKDOWN] = self._format_markdown
        self._formatters[ReportFormat.CSV] = self._format_csv
    
    def register_template(self, name: str, template: Callable):
        """Register a report template"""
        self._templates[name] = template
    
    def register_formatter(self, fmt: ReportFormat, formatter: Callable):
        """Register custom formatter"""
        self._formatters[fmt] = formatter
    
    # ============================================================================
    # Report Generation
    # ============================================================================
    
    def generate(
        self,
        data: Dict[str, Any],
        title: str,
        description: str = "",
        report_type: ReportType = ReportType.AUDIT,
        format: ReportFormat = ReportFormat.JSON,
        use_cache: bool = True,
        **kwargs
    ) -> Report:
        """Generate a report"""
        start_time = datetime.utcnow()
        
        # Generate report ID
        report_id = self._generate_report_id(title, data)
        
        # Check cache
        if use_cache and report_id in self._cache:
            cached = self._cache[report_id]
            cached.status = ReportStatus.CACHED
            logger.debug(f"Using cached report: {report_id}")
            return cached
        
        try:
            # Build metadata
            metadata = ReportMetadata(
                report_id=report_id,
                title=title,
                description=description,
                report_type=report_type,
                format=format,
                created_at=datetime.utcnow().isoformat(),
                generated_by="SoliGuard",
                tags=kwargs.get("tags", [])
            )
            
            # Format data
            formatter = self._formatters.get(format, self._format_json)
            formatted_data = formatter(data)
            
            # Calculate generation time
            generation_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Create report
            report = Report(
                metadata=metadata,
                data=formatted_data,
                status=ReportStatus.COMPLETED,
                generation_time=generation_time
            )
            
            # Cache the report
            if use_cache:
                self._cache[report_id] = report
            
            logger.info(f"Generated report: {report_id} ({generation_time:.2f}s)")
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return Report(
                metadata=ReportMetadata(
                    report_id=report_id,
                    title=title,
                    description=description,
                    report_type=report_type,
                    format=format,
                    created_at=datetime.utcnow().isoformat(),
                    generated_by="SoliGuard"
                ),
                data=None,
                status=ReportStatus.FAILED,
                error=str(e)
            )
    
    def _generate_report_id(self, title: str, data: Dict[str, Any]) -> str:
        """Generate unique report ID"""
        content = f"{title}:{json.dumps(data, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    # ============================================================================
    # Formatters
    # ============================================================================
    
    def _format_json(self, data: Dict[str, Any]) -> str:
        """Format as JSON"""
        return json.dumps(data, indent=2, default=str)
    
    def _format_html(self, data: Dict[str, Any]) -> str:
        """Format as HTML"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>SoliGuard Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #1a1a2e; color: white; padding: 20px; }
        .section { margin: 20px 0; }
        .vuln-critical { color: #ff3333; }
        .vuln-high { color: #ff9900; }
        .vuln-medium { color: #ffcc00; }
        .vuln-low { color: #4dba4d; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SoliGuard Security Report</h1>
    </div>
"""
        
        # Add data sections
        for key, value in data.items():
            html += f'<div class="section"><h2>{key}</h2>'
            
            if isinstance(value, dict):
                html += "<table>"
                for k, v in value.items():
                    html += f"<tr><th>{k}</th><td>{v}</td></tr>"
                html += "</table>"
            elif isinstance(value, list):
                html += "<table><tr>"
                if value and isinstance(value[0], dict):
                    for k in value[0].keys():
                        html += f"<th>{k}</th>"
                    html += "</tr>"
                    for item in value:
                        html += "<tr>"
                        for v in item.values():
                            html += f"<td>{v}</td>"
                        html += "</tr>"
                html += "</table>"
            else:
                html += f"<p>{value}</p>"
            
            html += "</div>"
        
        html += "</body></html>"
        return html
    
    def _format_markdown(self, data: Dict[str, Any]) -> str:
        """Format as Markdown"""
        md = "# SoliGuard Security Report\n\n"
        
        for key, value in data.items():
            md += f"## {key}\n\n"
            
            if isinstance(value, dict):
                for k, v in value.items():
                    md += f"- **{k}**: {v}\n"
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        md += f"- {json.dumps(item)}\n"
                    else:
                        md += f"- {item}\n"
            else:
                md += f"{value}\n"
            
            md += "\n"
        
        return md
    
    def _format_csv(self, data: Dict[str, Any]) -> str:
        """Format as CSV"""
        rows = []
        
        # Flatten data for CSV
        def flatten(d, prefix=""):
            items = []
            for k, v in d.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    items.extend(flatten(v, key))
                else:
                    items.append((key, str(v)))
            return items
        
        # Get all keys
        all_keys = set()
        for value in data.values():
            if isinstance(value, list) and value:
                for item in value:
                    if isinstance(item, dict):
                        all_keys.update(item.keys())
        
        # Header
        rows.append(",".join(all_keys))
        
        # Data rows
        for value in data.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        row = [str(item.get(k, "")) for k in all_keys]
                        rows.append(",".join(row))
        
        return "\n".join(rows)
    
    # ============================================================================
    # Report Operations
    # ============================================================================
    
    def get_cached(self, report_id: str) -> Optional[Report]:
        """Get cached report"""
        return self._cache.get(report_id)
    
    def clear_cache(self):
        """Clear report cache"""
        self._cache.clear()
        logger.info("Report cache cleared")
    
    def save_to_file(self, report: Report, file_path: str) -> bool:
        """Save report to file"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, "w") as f:
                f.write(str(report.data))
            
            report.file_path = file_path
            logger.info(f"Saved report to: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics"""
        return {
            "cached_reports": len(self._cache),
            "registered_templates": len(self._templates),
            "registered_formatters": len(self._formatters),
            "total_data_points": sum(len(v) for v in self._analytics._data_store.values())
        }


# ============================================================================
# Factory Functions
# ============================================================================

def create_report_generator(
    format: ReportFormat = ReportFormat.JSON,
    report_type: ReportType = ReportType.AUDIT
) -> ReportGenerator:
    """Create report generator instance"""
    config = ReportConfig(format=format, report_type=report_type)
    return ReportGenerator(config)


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    generator = create_report_generator()
    
    # Sample audit data
    audit_data = {
        "contract_name": "TestToken",
        "risk_score": 8.5,
        "vulnerabilities": [
            {"name": "Reentrancy", "severity": "CRITICAL"},
            {"name": "Overflow", "severity": "HIGH"}
        ]
    }
    
    report = generator.generate(
        data=audit_data,
        title="Test Contract Audit",
        report_type=ReportType.AUDIT,
        format=ReportFormat.HTML
    )
    
    print(f"Report ID: {report.metadata.report_id}")
    print(f"Status: {report.status.value}")
    print(f"Generated in: {report.generation_time:.2f}s")