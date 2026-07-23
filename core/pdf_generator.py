"""
Solidify PDF Generator
Generates professional PDF audit reports

Author: Peace Stephen (Tech Lead)
Description: PDF report generation using ReportLab
"""

import io
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, PageBreakIfNeeded
)
from reportlab.platypus.flowables import KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ReportConfig:
    """Configuration for PDF report"""
    page_size: str = "A4"
    margin_top: float = 20
    margin_bottom: float = 20
    margin_left: float = 20
    margin_right: float = 20
    include_cover: bool = True
    include_toc: bool = True
    include_summary: bool = True
    include_patches: bool = True
    include_recommendations: bool = True
    company_name: str = "Solidify"
    logo_path: Optional[str] = None


# ============================================================================
# PDF Generator
# ============================================================================

class PDFGenerator:
    """
    Generate professional PDF audit reports
    
    Features:
    - Cover page with branding
    - Executive summary
    - Vulnerability table with severity colors
    - Code snippets with highlighting
    - Patched code suggestions
    - Recommendations
    - Professional formatting
    """
    
    # Color scheme
    COLORS = {
        "critical": colors.Color(0.9, 0.2, 0.2),      # Red
        "high": colors.Color(0.95, 0.5, 0.0),         # Orange
        "medium": colors.Color(0.95, 0.8, 0.0),       # Yellow
        "low": colors.Color(0.3, 0.7, 0.3),           # Green
        "info": colors.Color(0.4, 0.4, 0.8),          # Blue
        "header": colors.Color(0.1, 0.1, 0.15),       # Dark
        "subheader": colors.Color(0.2, 0.2, 0.25),    # Dark gray
        "background": colors.Color(0.98, 0.98, 0.98), # Light gray
        "white": colors.white,
    }
    
    # Severity order for sorting
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    def __init__(self, config: Optional[ReportConfig] = None):
        """
        Initialize PDF generator
        
        Args:
            config: Report configuration
        """
        self.config = config or ReportConfig()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        logger.info("✅ PDF generator initialized")
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=self.styles["Title"],
            fontSize=28,
            textColor=self.COLORS["header"],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold"
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name="ReportSubtitle",
            parent=self.styles["Heading2"],
            fontSize=16,
            textColor=self.COLORS["subheader"],
            spaceAfter=20,
            alignment=TA_CENTER
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name="SectionHeader",
            parent=self.styles["Heading1"],
            fontSize=18,
            textColor=self.COLORS["header"],
            spaceBefore=20,
            spaceAfter=10,
            borderPadding=5,
            backColor=self.COLORS["background"]
        ))
        
        # Subsection header
        self.styles.add(ParagraphStyle(
            name="SubsectionHeader",
            parent=self.styles["Heading2"],
            fontSize=14,
            textColor=self.COLORS["subheader"],
            spaceBefore=15,
            spaceAfter=8
        ))
        
        # Code style
        self.styles.add(ParagraphStyle(
            name="CodeBlock",
            parent=self.styles["Code"],
            fontSize=9,
            fontName="Courier",
            textColor=colors.black,
            backgroundColor=colors.Color(0.95, 0.95, 0.95),
            spaceAfter=10,
            leftIndent=20,
            rightIndent=20,
            borderPadding=10
        ))
        
        # Normal text
        self.styles.add(ParagraphStyle(
            name="ReportBody",
            parent=self.styles["Normal"],
            fontSize=11,
            textColor=colors.black,
            spaceAfter=10,
            alignment=TA_JUSTIFY
        ))
        
        # Bullet points
        self.styles.add(ParagraphStyle(
            name="BulletPoint",
            parent=self.styles["Normal"],
            fontSize=10,
            spaceAfter=5,
            leftIndent=20
        ))
    
    def generate(self, audit_data: Dict[str, Any]) -> bytes:
        """
        Generate PDF from audit data
        
        Args:
            audit_data: Audit results dictionary
        
        Returns:
            PDF bytes
        """
        logger.info(f"Generating PDF for: {audit_data.get('contract_name', 'Unknown')}")
        
        # Create buffer
        buffer = io.BytesIO()
        
        # Setup document
        page_size = A4 if self.config.page_size == "A4" else letter
        doc = SimpleDocTemplate(
            buffer,
            pagesize=page_size,
            topMargin=self.config.margin_top * mm,
            bottomMargin=self.config.margin_bottom * mm,
            leftMargin=self.config.margin_left * mm,
            rightMargin=self.config.margin_right * mm
        )
        
        # Build story
        story = []
        
        # Add cover page
        if self.config.include_cover:
            self._add_cover_page(story, audit_data)
        
        # Add table of contents
        if self.config.include_toc:
            self._add_toc(story, audit_data)
        
        # Add executive summary
        self._add_executive_summary(story, audit_data)
        
        # Add vulnerability details
        self._add_vulnerabilities(story, audit_data)
        
        # Add recommendations
        if self.config.include_recommendations:
            self._add_recommendations(story, audit_data)
        
        # Add appendix if needed
        self._add_appendix(story, audit_data)
        
        # Build PDF
        doc.build(story)
        
        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        logger.info(f"PDF generated: {len(pdf_bytes)} bytes")
        return pdf_bytes
    
    def _add_cover_page(self, story: List, audit_data: Dict):
        """Add cover page"""
        # Logo/Title
        story.append(Spacer(1, 2 * inch))
        story.append(Paragraph("🔐 Solidify", self.styles["ReportTitle"]))
        story.append(Paragraph("Smart Contract Security Audit Report", self.styles["ReportSubtitle"]))
        
        story.append(Spacer(1, 1.5 * inch))
        
        # Contract info
        story.append(Paragraph("Contract Information", self.styles["SubsectionHeader"]))
        
        info_data = [
            ["Contract Name:", audit_data.get("contract_name", "Unknown")],
            ["Audit Date:", audit_data.get("scan_timestamp", datetime.utcnow().isoformat())[:10]],
            ["Overall Risk Score:", f"{audit_data.get('overall_risk_score', 0):.1f} / 10"],
            ["Total Vulnerabilities:", str(audit_data.get("total_vulnerabilities", 0))],
        ]
        
        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 11),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(info_table)
        
        story.append(Spacer(1, 2 * inch))
        
        # Summary
        story.append(Paragraph("Executive Summary", self.styles["SubsectionHeader"]))
        story.append(Paragraph(
            audit_data.get("audit_summary", "No summary available"),
            self.styles["ReportBody"]
        ))
        
        # Add page break
        story.append(PageBreak())
    
    def _add_toc(self, story: List, audit_data: Dict):
        """Add table of contents"""
        story.append(Paragraph("Table of Contents", self.styles["SectionHeader"]))
        
        vuln_count = audit_data.get("total_vulnerabilities", 0)
        
        toc_items = [
            "1. Executive Summary",
            f"2. Vulnerability Findings ({vuln_count} issues)",
            "3. Recommendations",
            "4. Appendix"
        ]
        
        for item in toc_items:
            story.append(Paragraph(item, self.styles["BulletPoint"]))
        
        story.append(PageBreak())
    
    def _add_executive_summary(self, story: List, audit_data: Dict):
        """Add executive summary section"""
        story.append(Paragraph("1. Executive Summary", self.styles["SectionHeader"]))
        
        # Overview
        story.append(Paragraph("Overview", self.styles["SubsectionHeader"]))
        
        risk_score = audit_data.get("overall_risk_score", 0)
        severity = self._get_risk_severity(risk_score)
        
        summary_text = f"""
        This security audit was conducted on the smart contract <b>{audit_data.get('contract_name', 'Unknown')}</b>.
        The contract was analyzed for common vulnerability patterns and received an overall risk score of <b>{risk_score:.1f}/10</b> 
        ({severity}).
        """
        story.append(Paragraph(summary_text, self.styles["ReportBody"]))
        
        # Key findings
        story.append(Paragraph("Key Findings", self.styles["SubsectionHeader"]))
        
        vulnerabilities = audit_data.get("vulnerabilities", [])
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        findings_text = f"Total of <b>{len(vulnerabilities)}</b> vulnerabilities identified:<br/>"
        for sev in self.SEVERITY_ORDER:
            count = severity_counts.get(sev, 0)
            if count > 0:
                findings_text += f"• {sev}: {count}<br/>"
        
        story.append(Paragraph(findings_text, self.styles["ReportBody"]))
        
        # Risk score breakdown
        story.append(Paragraph("Risk Score Breakdown", self.styles["SubsectionHeader"]))
        
        score_data = [
            ["Risk Category", "Score", "Description"],
            ["Overall Risk", f"{risk_score:.1f}/10", severity],
            ["Critical", f"{severity_counts.get('CRITICAL', 0)}", "Immediate action required"],
            ["High", f"{severity_counts.get('HIGH', 0)}", "High priority fixes"],
            ["Medium", f"{severity_counts.get('MEDIUM', 0)}", "Should be addressed"],
            ["Low", f"{severity_counts.get('LOW', 0)}", "Minor improvements"],
        ]
        
        score_table = Table(score_data, colWidths=[1.5 * inch, 1 * inch, 3 * inch])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLORS["header"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.gray),
        ]))
        story.append(score_table)
        
        story.append(Spacer(1, 20))
    
    def _add_vulnerabilities(self, story: List, audit_data: Dict):
        """Add vulnerability details"""
        story.append(Paragraph(f"2. Vulnerability Findings", self.styles["SectionHeader"]))
        
        vulnerabilities = audit_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities detected.", self.styles["ReportBody"]))
            return
        
        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.index(v.get("severity", "INFO"))
        )
        
        # Add each vulnerability
        for idx, vuln in enumerate(sorted_vulns, 1):
            self._add_vulnerability_entry(story, idx, vuln)
    
    def _add_vulnerability_entry(self, story: List, idx: int, vuln: Dict):
        """Add a single vulnerability entry"""
        severity = vuln.get("severity", "INFO")
        color = self.COLORS.get(severity.lower(), self.COLORS["info"])
        
        # Header with severity badge
        header_text = f'<span style="background-color: {color.hexval}; color: white; padding: 3px 8px;">{severity}</span> {idx}. {vuln.get("vulnerability_name", "Unknown")}'
        story.append(Paragraph(header_text, self.styles["SubsectionHeader"]))
        
        # CVSS Score
        cvss = vuln.get("cvss_score", 0)
        story.append(Paragraph(f"CVSS Score: <b>{cvss:.1f}</b>", self.styles["ReportBody"]))
        
        # Description
        story.append(Paragraph("Description:", self.styles["BulletPoint"]))
        story.append(Paragraph(vuln.get("description", "No description"), self.styles["ReportBody"]))
        
        # Affected Lines
        if vuln.get("affected_lines"):
            lines = ", ".join(map(str, vuln["affected_lines"]))
            story.append(Paragraph(f"Affected Lines: {lines}", self.styles["ReportBody"]))
        
        # CWE ID
        if vuln.get("cwe_id"):
            story.append(Paragraph(f"CWE: {vuln['cwe_id']}", self.styles["ReportBody"]))
        
        # Confidence
        confidence = vuln.get("confidence", 1.0)
        story.append(Paragraph(f"AI Confidence: {confidence*100:.0f}%", self.styles["ReportBody"]))
        
        # Original Code (if include patches)
        if self.config.include_patches and vuln.get("original_code"):
            story.append(Paragraph("Vulnerable Code:", self.styles["SubsectionHeader"]))
            code = vuln["original_code"].replace("\n", "<br/>")
            story.append(Paragraph(f"<font face='Courier' size='9'>{code}</font>", self.styles["CodeBlock"]))
        
        # Patched Code
        if self.config.include_patches and vuln.get("patched_code"):
            story.append(Paragraph("Recommended Fix:", self.styles["SubsectionHeader"]))
            code = vuln["patched_code"].replace("\n", "<br/>")
            story.append(Paragraph(f"<font face='Courier' size='9'>{code}</font>", self.styles["CodeBlock"]))
        
        story.append(Spacer(1, 15))
    
    def _add_recommendations(self, story: List, audit_data: Dict):
        """Add recommendations section"""
        story.append(Paragraph("3. Recommendations", self.styles["SectionHeader"]))
        
        recommendations = audit_data.get("recommendations", [])
        
        if not recommendations:
            story.append(Paragraph("No specific recommendations.", self.styles["ReportBody"]))
            return
        
        for idx, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{idx}. {rec}", self.styles["BulletPoint"]))
        
        story.append(Spacer(1, 20))
    
    def _add_appendix(self, story: List, audit_data: Dict):
        """Add appendix"""
        story.append(Paragraph("4. Appendix", self.styles["SectionHeader"]))
        
        # Methodology
        story.append(Paragraph("Audit Methodology", self.styles["SubsectionHeader"]))
        methodology = """
        This audit was conducted using a combination of:
        <br/><br/>
        1. <b>Static Analysis:</b> Automated pattern matching for known vulnerability signatures<br/>
        2. <b>AI-Powered Analysis:</b> Gemini-based reasoning for complex vulnerabilities<br/>
        3. <b>Manual Review:</b> Expert security engineer review<br/>
        4. <b>Best Practices:</b> OpenZeppelin security guidelines
        """
        story.append(Paragraph(methodology, self.styles["ReportBody"]))
        
        # About Solidify
        story.append(Paragraph("About Solidify", self.styles["SubsectionHeader"]))
        about = """
        Solidify is an AI-powered smart contract security auditor developed by Team Solidify 
        at GDG Abuja × Build with AI Sprint Hackathon. It uses Google Gemini AI to analyze 
        Solidity contracts and identify security vulnerabilities.
        """
        story.append(Paragraph(about, self.styles["ReportBody"]))
        
        # Disclaimer
        story.append(Paragraph("Disclaimer", self.styles["SubsectionHeader"]))
        disclaimer = """
        This report is provided for informational purposes only. Solidify and its creators 
        make no warranties about the completeness, reliability, or accuracy of this audit. 
        Any action you take based upon the information from this report is at your own risk.
        """
        story.append(Paragraph(disclaimer, self.styles["ReportBody"]))
    
    def _get_risk_severity(self, score: float) -> str:
        """Convert risk score to severity string"""
        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        elif score >= 3:
            return "LOW"
        else:
            return "INFO"


# ============================================================================
# Factory Functions
# ============================================================================

def create_pdf_generator(
    include_patches: bool = True,
    include_cover: bool = True
) -> PDFGenerator:
    """Create a configured PDF generator"""
    config = ReportConfig(
        include_patches=include_patches,
        include_cover=include_cover,
        include_toc=True,
        include_summary=True
    )
    return PDFGenerator(config)


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    # Test PDF generation
    generator = PDFGenerator()
    
    # Sample audit data
    audit_data = {
        "contract_name": "TestToken",
        "audit_summary": "Found 2 critical vulnerabilities",
        "overall_risk_score": 8.5,
        "total_vulnerabilities": 2,
        "scan_timestamp": datetime.utcnow().isoformat(),
        "vulnerabilities": [
            {
                "vulnerability_name": "Reentrancy",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "description": "Missing reentrancy guard",
                "affected_lines": [45, 46],
                "original_code": "msg.sender.call{value: bal}(\"\");",
                "patched_code": "msg.sender.transfer(bal);",
                "confidence": 0.95,
                "cwe_id": "CWE-307"
            },
            {
                "vulnerability_name": "Integer Overflow",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": "Unsafe math operations",
                "affected_lines": [78],
                "original_code": "balance[msg.sender] -= amount;",
                "patched_code": "unchecked { balance[msg.sender] -= amount; }",
                "confidence": 0.85,
                "cwe_id": "CWE-190"
            }
        ],
        "recommendations": [
            "Add ReentrancyGuard",
            "Use SafeMath for arithmetic",
            "Implement access controls"
        ]
    }
    
    # Generate PDF
    pdf_bytes = generator.generate(audit_data)
    print(f"Generated PDF: {len(pdf_bytes)} bytes")
    
    # Save to file
    with open("test_audit_report.pdf", "wb") as f:
        f.write(pdf_bytes)
    print("Saved to test_audit_report.pdf")