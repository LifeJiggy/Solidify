"""
Solidify Runtime Reporter
Runtime reporting and output generation

Author: Peace Stephen (Tech Lead)
Description: Generates runtime reports and output
"""

import json
import logging
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import traceback

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ReportFormat(Enum):
    """Report format"""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"


class ReportLevel(Enum):
    """Report verbosity level"""
    SUMMARY = "summary"
    NORMAL = "normal"
    DETAILED = "detailed"
    VERBOSE = "verbose"


@dataclass
class ReportSection:
    """Report section"""
    title: str
    content: Any
    level: int = 1
    collapsed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    """Report container"""
    title: str
    timestamp: str
    format: ReportFormat = ReportFormat.TEXT
    level: ReportLevel = ReportLevel.NORMAL
    sections: List[ReportSection] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# Report Builder
# ============================================================================

class ReportBuilder:
    """
    Build reports dynamically
    
    Features:
    - Section management
    - Content formatting
    - Template support
    """
    
    def __init__(self, title: str = "Solidify Report"):
        self.title = title
        self._sections: List[ReportSection] = []
        self._metadata: Dict[str, Any] = {}
        self._errors: List[str] = []
        self._warnings: List[str] = []
    
    def add_section(
        self,
        title: str,
        content: Any,
        level: int = 1,
        collapsed: bool = False
    ) -> "ReportBuilder":
        """Add section to report"""
        section = ReportSection(
            title=title,
            content=content,
            level=level,
            collapsed=collapsed
        )
        self._sections.append(section)
        return self
    
    def add_metadata(self, key: str, value: Any) -> "ReportBuilder":
        """Add metadata"""
        self._metadata[key] = value
        return self
    
    def add_error(self, error: str) -> "ReportBuilder":
        """Add error"""
        self._errors.append(error)
        return self
    
    def add_warning(self, warning: str) -> "ReportBuilder":
        """Add warning"""
        self._warnings.append(warning)
        return self
    
    def build(
        self,
        format: ReportFormat = ReportFormat.TEXT,
        level: ReportLevel = ReportLevel.NORMAL
    ) -> Report:
        """Build report"""
        return Report(
            title=self.title,
            timestamp=datetime.utcnow().isoformat(),
            format=format,
            level=level,
            sections=self._sections,
            metadata=self._metadata,
            errors=self._errors,
            warnings=self._warnings
        )


# ============================================================================
# Formatter
# ============================================================================

class ReportFormatter:
    """
    Format reports
    
    Features:
    - Multiple output formats
    - Custom styling
    - Content transformation
    """
    
    def __init__(self):
        self._formatters: Dict[ReportFormat, Callable] = {
            ReportFormat.TEXT: self._format_text,
            ReportFormat.JSON: self._format_json,
            ReportFormat.HTML: self._format_html,
            ReportFormat.MARKDOWN: self._format_markdown,
        }
    
    def format(self, report: Report) -> str:
        """Format report"""
        formatter = self._formatters.get(report.format, self._format_text)
        return formatter(report)
    
    def _format_text(self, report: Report) -> str:
        """Format as plain text"""
        lines = []
        lines.append("=" * 60)
        lines.append(report.title.center(60))
        lines.append("=" * 60)
        lines.append(f"Timestamp: {report.timestamp}")
        
        if report.errors:
            lines.append(f"\nErrors: {len(report.errors)}")
            for error in report.errors:
                lines.append(f"  - {error}")
        
        if report.warnings:
            lines.append(f"\nWarnings: {len(report.warnings)}")
            for warning in report.warnings:
                lines.append(f"  - {warning}")
        
        for section in report.sections:
            lines.append("")
            lines.append(self._format_section_text(section))
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def _format_section_text(self, section: ReportSection) -> str:
        """Format section as text"""
        prefix = "#" * section.level
        lines = [f"{prefix} {section.title}"]
        
        content = section.content
        if isinstance(content, (dict, list)):
            content = json.dumps(content, indent=2)
        
        lines.append(str(content))
        
        return "\n".join(lines)
    
    def _format_json(self, report: Report) -> str:
        """Format as JSON"""
        data = {
            "title": report.title,
            "timestamp": report.timestamp,
            "format": report.format.value,
            "level": report.level.value,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "level": s.level
                }
                for s in report.sections
            ],
            "metadata": report.metadata,
            "errors": report.errors,
            "warnings": report.warnings
        }
        
        return json.dumps(data, indent=2)
    
    def _format_html(self, report: Report) -> str:
        """Format as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{report.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
        .error {{ color: red; }}
        .warning {{ color: orange; }}
        pre {{ background: #f5f5f5; padding: 10px; }}
    </style>
</head>
<body>
    <h1>{report.title}</h1>
    <p>Timestamp: {report.timestamp}</p>
"""
        
        if report.errors:
            html += '<div class="errors"><h3>Errors</h3><ul>'
            for error in report.errors:
                html += f'<li class="error">{error}</li>'
            html += '</ul></div>'
        
        if report.warnings:
            html += '<div class="warnings"><h3>Warnings</h3><ul>'
            for warning in report.warnings:
                html += f'<li class="warning">{warning}</li>'
            html += '</ul></div>'
        
        for section in report.sections:
            content = section.content
            if isinstance(content, (dict, list)):
                content = f"<pre>{json.dumps(content, indent=2)}</pre>"
            
            html += f"""
    <div class="section">
        <h{section.level}>{section.title}</h{section.level}>
        <div>{content}</div>
    </div>
"""
        
        html += "</body></html>"
        
        return html
    
    def _format_markdown(self, report: Report) -> str:
        """Format as Markdown"""
        md = []
        md.append(f"# {report.title}")
        md.append("")
        md.append(f"**Timestamp:** {report.timestamp}")
        
        if report.errors:
            md.append("")
            md.append("## Errors")
            for error in report.errors:
                md.append(f"- {error}")
        
        if report.warnings:
            md.append("")
            md.append("## Warnings")
            for warning in report.warnings:
                md.append(f"- {warning}")
        
        for section in report.sections:
            md.append("")
            prefix = "#" * (section.level + 1)
            md.append(f"{prefix} {section.title}")
            md.append("")
            
            content = section.content
            if isinstance(content, (dict, list)):
                content = f"```json\n{json.dumps(content, indent=2)}\n```"
            
            md.append(str(content))
        
        return "\n".join(md)


# ============================================================================
# Runtime Reporter
# ============================================================================

class RuntimeReporter:
    """
    Main runtime reporter
    
    Features:
    - Report generation
    - Multiple formats
    - Event tracking
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.formatter = ReportFormatter()
        self._events: List[Dict[str, Any]] = []
        self._start_time = time.time()
        
        logger.info("✅ Runtime Reporter initialized")
    
    def create_report(
        self,
        title: str,
        sections: Optional[List[ReportSection]] = None,
        format: ReportFormat = ReportFormat.TEXT,
        level: ReportLevel = ReportLevel.NORMAL
    ) -> Report:
        """Create new report"""
        builder = ReportBuilder(title)
        
        if sections:
            for section in sections:
                builder.add_section(
                    section.title,
                    section.content,
                    section.level,
                    section.collapsed
                )
        
        return builder.build(format, level)
    
    def add_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Add runtime event"""
        self._events.append({
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        })
    
    def get_events(
        self,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get events"""
        events = self._events
        
        if event_type:
            events = [e for e in events if e["type"] == event_type]
        
        return events[-limit:]
    
    def generate_audit_report(
        self,
        audit_result: Dict[str, Any],
        format: ReportFormat = ReportFormat.TEXT
    ) -> str:
        """Generate audit report"""
        builder = ReportBuilder("Security Audit Report")
        
        builder.add_section(
            "Summary",
            audit_result.get("audit_summary", "No summary available")
        )
        
        if "vulnerabilities" in audit_result:
            vulns = audit_result["vulnerabilities"]
            builder.add_section(
                f"Vulnerabilities ({len(vulns)})",
                self._format_vulnerabilities(vulns)
            )
        
        if "overall_risk_score" in audit_result:
            builder.add_section(
                "Risk Score",
                str(audit_result["overall_risk_score"])
            )
        
        if "recommendations" in audit_result:
            recs = audit_result["recommendations"]
            builder.add_section(
                "Recommendations",
                self._format_list(recs)
            )
        
        builder.add_metadata("contract", audit_result.get("contract_name", "Unknown"))
        builder.add_metadata("chain", audit_result.get("chain", "ethereum"))
        
        report = builder.build(format)
        return self.formatter.format(report)
    
    def _format_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities"""
        lines = []
        
        for i, vuln in enumerate(vulns, 1):
            lines.append(f"\n{i}. {vuln.get('title', 'Unknown')}")
            lines.append(f"   Severity: {vuln.get('severity', 'unknown')}")
            lines.append(f"   Description: {vuln.get('description', 'N/A')}")
            
            if "cvss_score" in vuln:
                lines.append(f"   CVSS: {vuln['cvss_score']}")
            
            if "location" in vuln:
                lines.append(f"   Location: {vuln['location']}")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_list(self, items: List[str]) -> str:
        """Format list"""
        return "\n".join(f"- {item}" for item in items)
    
    def generate_status_report(self) -> Dict[str, Any]:
        """Generate status report"""
        elapsed = time.time() - self._start_time
        
        return {
            "uptime": elapsed,
            "events": len(self._events),
            "event_types": list(set(e["type"] for e in self._events)),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def export_events(self, filepath: str, format: ReportFormat = ReportFormat.JSON) -> bool:
        """Export events to file"""
        try:
            report = Report(
                title="Runtime Events Export",
                timestamp=datetime.utcnow().isoformat(),
                format=format,
                sections=[
                    ReportSection("Events", self._events, level=1)
                ]
            )
            
            content = self.formatter.format(report)
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to export events: {str(e)}")
            return False


# ============================================================================
# Streaming Reporter
# ============================================================================

class StreamingReporter:
    """
    Reporter for streaming output
    
    Features:
    - Real-time updates
    - Progress tracking
    - Chunk output
    """
    
    def __init__(self, reporter: RuntimeReporter):
        self.reporter = reporter
        self._chunks: List[str] = []
        self._callbacks: List[Callable] = []
    
    def add_callback(self, callback: Callable) -> None:
        """Add chunk callback"""
        self._callbacks.append(callback)
    
    def add_chunk(self, chunk: str) -> None:
        """Add output chunk"""
        self._chunks.append(chunk)
        
        for callback in self._callbacks:
            try:
                callback(chunk)
            except Exception as e:
                logger.warning(f"Callback error: {str(e)}")
    
    def get_chunks(self) -> List[str]:
        """Get all chunks"""
        return self._chunks.copy()
    
    def clear_chunks(self) -> None:
        """Clear chunks"""
        self._chunks.clear()
    
    def flush(self) -> str:
        """Flush all chunks"""
        result = "".join(self._chunks)
        self._chunks.clear()
        return result


# ============================================================================
# Summary Generator
# ============================================================================

class SummaryGenerator:
    """
    Generate report summaries
    
    Features:
    - Key metrics
    - Statistics
    - Trend analysis
    """
    
    def __init__(self):
        self._data: Dict[str, Any] = {}
    
    def add_data(self, key: str, value: Any) -> None:
        """Add data point"""
        if key not in self._data:
            self._data[key] = []
        self._data[key].append(value)
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary"""
        summary = {}
        
        for key, values in self._data.items():
            if all(isinstance(v, (int, float)) for v in values):
                summary[key] = {
                    "count": len(values),
                    "sum": sum(values),
                    "avg": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values)
                }
            else:
                summary[key] = {
                    "count": len(values),
                    "unique": len(set(values))
                }
        
        return summary
    
    def generate_text_summary(self) -> str:
        """Generate text summary"""
        summary = self.generate_summary()
        
        lines = ["Summary:", ""]
        
        for key, stats in summary.items():
            lines.append(f"{key}:")
            
            for stat, value in stats.items():
                if isinstance(value, float):
                    lines.append(f"  {stat}: {value:.2f}")
                else:
                    lines.append(f"  {stat}: {value}")
            
            lines.append("")
        
        return "\n".join(lines)