"""
response/pdf_generator.py
-------------------------
Generates professional PDF security assessment reports using ReportLab.

Functions:
    generate_pdf_report(scan_data, cve_data, mitre_data, ai_analysis, output_path)
"""

import os
import re
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

# ---------------------------------------------------------------------------
# Color Palette (Professional Cyber Security Theme)
# ---------------------------------------------------------------------------
COLOR_PRIMARY_DARK = colors.HexColor("#0F172A")    # Deep Slate / Dark Header
COLOR_SECONDARY_DARK = colors.HexColor("#1E293B")  # Slate 800
COLOR_TEXT_MAIN = colors.HexColor("#334155")       # Slate 700 body text
COLOR_LIGHT_BG = colors.HexColor("#F8FAFC")        # Off-white table background
COLOR_BORDER = colors.HexColor("#E2E8F0")          # Subtle border grey

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),  # Red
    "HIGH": colors.HexColor("#EA580C"),      # Orange
    "MEDIUM": colors.HexColor("#D97706"),    # Yellow / Amber
    "LOW": colors.HexColor("#16A34A"),       # Green
    "UNKNOWN": colors.HexColor("#64748B"),   # Slate Grey
    "INFO": colors.HexColor("#2563EB"),      # Blue
}


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and draw total page numbers and headers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        # Skip header and footer on cover page (Page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748B"))

        # Header
        self.drawString(54, 750, "SECURITY ASSESSMENT REPORT")
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.5)
        self.line(54, 742, 612 - 54, 742)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 36, footer_text)
        self.drawString(54, 36, "CONFIDENTIAL & PROPRIETARY")
        self.line(54, 48, 612 - 54, 48)

        self.restoreState()


def _get_severity_color(severity_str: str):
    """Return ReportLab color object for a given severity string."""
    key = str(severity_str).upper().strip()
    return SEVERITY_COLORS.get(key, SEVERITY_COLORS["UNKNOWN"])


def _derive_overall_risk(scan_data, cve_data) -> str:
    """Derive overall risk level if not explicitly provided in scan_data."""
    if isinstance(scan_data, dict) and scan_data.get("risk_level"):
        return str(scan_data["risk_level"]).upper()

    highest = "LOW"
    cve_list = []
    if isinstance(cve_data, dict):
        for sublist in cve_data.values():
            if isinstance(sublist, list):
                cve_list.extend(sublist)
    elif isinstance(cve_data, list):
        cve_list = cve_data

    for cve in cve_list:
        if isinstance(cve, dict):
            sev = str(cve.get("severity", "")).upper()
            if sev == "CRITICAL":
                return "CRITICAL"
            elif sev == "HIGH" and highest != "CRITICAL":
                highest = "HIGH"
            elif sev == "MEDIUM" and highest not in ("CRITICAL", "HIGH"):
                highest = "MEDIUM"

    return highest


def _parse_markdown_to_flowables(text: str, styles) -> list:
    """
    Parse basic Markdown from AI response into ReportLab Flowables.
    """
    flowables = []
    if not text:
        return flowables

    lines = text.strip().split("\n")
    for line in lines:
        stripped = line.strip()
        if not stripped:
            flowables.append(Spacer(1, 4))
            continue

        # Header 2
        if stripped.startswith("## "):
            heading_text = stripped[3:].strip()
            flowables.append(Spacer(1, 10))
            flowables.append(Paragraph(heading_text, styles["SectionHeading"]))
            flowables.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY_DARK, spaceBefore=4, spaceAfter=8))
        # Header 3
        elif stripped.startswith("### "):
            heading_text = stripped[4:].strip()
            flowables.append(Spacer(1, 6))
            flowables.append(Paragraph(heading_text, styles["SubSectionHeading"]))
        # Header 4
        elif stripped.startswith("#### "):
            heading_text = stripped[5:].strip()
            flowables.append(Paragraph(f"<b>{heading_text}</b>", styles["NormalBody"]))
        # Bullet list item
        elif stripped.startswith("- ") or stripped.startswith("* "):
            content = stripped[2:].strip()
            content = _format_inline_markdown(content)
            flowables.append(Paragraph(f"• {content}", styles["BulletItem"]))
        # Numbered list item (e.g., "1. ")
        elif re.match(r"^\d+\.\s+", stripped):
            content = re.sub(r"^\d+\.\s+", "", stripped)
            content = _format_inline_markdown(content)
            flowables.append(Paragraph(f"• {content}", styles["BulletItem"]))
        # Standard paragraph
        else:
            content = _format_inline_markdown(stripped)
            flowables.append(Paragraph(content, styles["NormalBody"]))

    return flowables


def _format_inline_markdown(text: str) -> str:
    """Convert **bold** and *italic* markdown syntax into HTML tags for ReportLab."""
    # Bold
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    # Italic
    text = re.sub(r"\*(.*?)\*", r"<i>\1</i>", text)
    # Backticks code formatting
    text = re.sub(r"`(.*?)`", r"<font face='Courier'>\1</font>", text)
    return text


def generate_pdf_report(scan_data: dict, cve_data, mitre_data: list, ai_analysis: str, output_path: str) -> str:
    """
    Generates a professional security assessment PDF report.

    Args:
        scan_data:   Dict containing 'target_ip', 'scan_time', 'open_ports', and optionally 'risk_level'.
        cve_data:    CVE details dict or list.
        mitre_data:  List of MITRE mapping dicts.
        ai_analysis: String containing AI security evaluation.
        output_path: Target filepath to save the PDF.

    Returns:
        The output_path string upon completion.
    """
    # Ensure directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Define custom styles
    styles.add(ParagraphStyle(
        name="CoverTitle",
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=32,
        textColor=COLOR_PRIMARY_DARK,
        alignment=0,
        spaceAfter=15,
    ))

    styles.add(ParagraphStyle(
        name="CoverSubTitle",
        fontName="Helvetica",
        fontSize=14,
        leading=18,
        textColor=COLOR_TEXT_MAIN,
        alignment=0,
        spaceAfter=30,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=COLOR_PRIMARY_DARK,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="SubSectionHeading",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=COLOR_SECONDARY_DARK,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="NormalBody",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=COLOR_TEXT_MAIN,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="BulletItem",
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=COLOR_TEXT_MAIN,
        leftIndent=15,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="TableHeader",
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=12,
        textColor=colors.white,
        alignment=0,
    ))

    styles.add(ParagraphStyle(
        name="TableCell",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=COLOR_TEXT_MAIN,
    ))

    story = []

    # ---------------------------------------------------------------------------
    # 1. Cover Page
    # ---------------------------------------------------------------------------
    target_ip = scan_data.get("target_ip", "Unknown Target") if isinstance(scan_data, dict) else "Unknown Target"
    scan_date = scan_data.get("scan_time", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")) if isinstance(scan_data, dict) else "N/A"
    overall_risk = _derive_overall_risk(scan_data, cve_data)
    risk_color = _get_severity_color(overall_risk)

    story.append(Spacer(1, 40))
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles["CoverTitle"]))
    story.append(Paragraph("Automated Incident Response & Vulnerability Scan Analysis", styles["CoverSubTitle"]))
    story.append(HRFlowable(width="100%", thickness=4, color=COLOR_PRIMARY_DARK, spaceBefore=0, spaceAfter=40))

    # Meta information table on cover page
    meta_data = [
        [Paragraph("<b>Target IP Address:</b>", styles["NormalBody"]), Paragraph(str(target_ip), styles["NormalBody"])],
        [Paragraph("<b>Scan Timestamp:</b>", styles["NormalBody"]), Paragraph(str(scan_date), styles["NormalBody"])],
        [Paragraph("<b>Report Generated:</b>", styles["NormalBody"]), Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), styles["NormalBody"])],
    ]
    meta_table = Table(meta_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 50))

    # Overall Risk Box
    risk_box_data = [
        [Paragraph("<font color='white'><b>OVERALL THREAT RISK LEVEL</b></font>", styles["TableHeader"])],
        [Paragraph(f"<font color='{risk_color.hexval()}'><b>{overall_risk}</b></font>", ParagraphStyle(
            name="RiskLevelDisplay",
            fontName="Helvetica-Bold",
            fontSize=32,
            leading=38,
            alignment=1,
        ))]
    ]
    risk_table = Table(risk_box_data, colWidths=[504])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_PRIMARY_DARK),
        ('BACKGROUND', (0, 1), (-1, 1), COLOR_LIGHT_BG),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 1.5, risk_color),
        ('TOPPADDING', (0, 1), (-1, 1), 20),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 20),
    ]))
    story.append(risk_table)

    story.append(PageBreak())

    # ---------------------------------------------------------------------------
    # 2. Executive Summary & AI Security Analysis
    # ---------------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary & AI Analysis", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY_DARK, spaceBefore=2, spaceAfter=12))

    if ai_analysis:
        parsed_flowables = _parse_markdown_to_flowables(ai_analysis, styles)
        story.extend(parsed_flowables)
    else:
        story.append(Paragraph("No AI analysis content was provided for this assessment.", styles["NormalBody"]))

    story.append(Spacer(1, 16))

    # ---------------------------------------------------------------------------
    # 3. Open Ports Table
    # ---------------------------------------------------------------------------
    story.append(Paragraph("2. Open Ports & Detected Services", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY_DARK, spaceBefore=2, spaceAfter=12))

    open_ports = scan_data.get("open_ports", []) if isinstance(scan_data, dict) else []
    if open_ports:
        ports_table_data = [
            [
                Paragraph("Port", styles["TableHeader"]),
                Paragraph("Service", styles["TableHeader"]),
                Paragraph("Version", styles["TableHeader"]),
                Paragraph("Risk", styles["TableHeader"]),
            ]
        ]

        for p in open_ports:
            port_num = f"{p.get('port', '?')}/{p.get('protocol', 'tcp')}"
            srv_name = p.get('service_name', 'unknown')
            srv_ver = p.get('service_version', 'N/A') or 'N/A'
            
            # Simple heuristic risk tag per port if not provided
            port_val = p.get('port', 0)
            if port_val in (21, 23, 445, 3389):
                port_risk = "HIGH"
            elif port_val in (80, 443, 22, 3306):
                port_risk = "MEDIUM"
            else:
                port_risk = "LOW"

            p_color = _get_severity_color(port_risk)

            ports_table_data.append([
                Paragraph(port_num, styles["TableCell"]),
                Paragraph(srv_name, styles["TableCell"]),
                Paragraph(srv_ver, styles["TableCell"]),
                Paragraph(f"<font color='{p_color.hexval()}'><b>{port_risk}</b></font>", styles["TableCell"]),
            ])

        ports_table = Table(ports_table_data, colWidths=[90, 120, 204, 90])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_PRIMARY_DARK),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ports_table)
    else:
        story.append(Paragraph("No open ports were detected during this scan.", styles["NormalBody"]))

    story.append(Spacer(1, 16))

    # ---------------------------------------------------------------------------
    # 4. CVE Findings Section
    # ---------------------------------------------------------------------------
    story.append(Paragraph("3. Discovered Vulnerabilities (CVEs)", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY_DARK, spaceBefore=2, spaceAfter=12))

    # Normalize cve_data into list of dicts
    flat_cves = []
    if isinstance(cve_data, dict):
        for srv, cves in cve_data.items():
            if isinstance(cves, list):
                for item in cves:
                    if isinstance(item, dict):
                        item_copy = dict(item)
                        item_copy["service"] = srv
                        flat_cves.append(item_copy)
    elif isinstance(cve_data, list):
        flat_cves = [c for c in cve_data if isinstance(c, dict)]

    if flat_cves:
        for cve in flat_cves:
            cve_id = cve.get("cve_id", "N/A")
            severity = str(cve.get("severity", "UNKNOWN")).upper()
            score = cve.get("cvss_score", "N/A")
            desc = cve.get("description", "No description available.")
            pub_date = cve.get("published_date", "N/A")
            sev_color = _get_severity_color(severity)

            cve_block = []
            header_text = f"<b>{cve_id}</b> — CVSS Score: <b>{score}</b> | Published: {pub_date}"
            cve_block.append(Paragraph(header_text, styles["SubSectionHeading"]))

            # Badge table for severity
            badge_data = [[
                Paragraph(f"<font color='white'><b>{severity} SEVERITY</b></font>", ParagraphStyle(
                    name="BadgeText",
                    fontName="Helvetica-Bold",
                    fontSize=8,
                    leading=10,
                    alignment=1,
                ))
            ]]
            badge_table = Table(badge_data, colWidths=[120])
            badge_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))

            cve_block.append(badge_table)
            cve_block.append(Spacer(1, 4))
            cve_block.append(Paragraph(_format_inline_markdown(desc), styles["NormalBody"]))
            cve_block.append(Spacer(1, 10))

            story.append(KeepTogether(cve_block))
    else:
        story.append(Paragraph("No known CVE findings were identified for the target.", styles["NormalBody"]))

    story.append(Spacer(1, 16))

    # ---------------------------------------------------------------------------
    # 5. MITRE ATT&CK Mappings Table
    # ---------------------------------------------------------------------------
    story.append(Paragraph("4. MITRE ATT&CK Mappings", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY_DARK, spaceBefore=2, spaceAfter=12))

    if mitre_data and isinstance(mitre_data, list):
        mitre_table_data = [
            [
                Paragraph("Port", styles["TableHeader"]),
                Paragraph("Technique ID", styles["TableHeader"]),
                Paragraph("Technique Name", styles["TableHeader"]),
                Paragraph("Tactic", styles["TableHeader"]),
            ]
        ]

        for m in mitre_data:
            if not isinstance(m, dict):
                continue
            mitre_table_data.append([
                Paragraph(str(m.get("port", "?")), styles["TableCell"]),
                Paragraph(str(m.get("technique_id", "N/A")), styles["TableCell"]),
                Paragraph(str(m.get("technique_name", "N/A")), styles["TableCell"]),
                Paragraph(str(m.get("tactic", "N/A")), styles["TableCell"]),
            ])

        mitre_table = Table(mitre_table_data, colWidths=[60, 110, 184, 150])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_PRIMARY_DARK),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(mitre_table)
    else:
        story.append(Paragraph("No MITRE ATT&CK technique mappings available.", styles["NormalBody"]))

    story.append(Spacer(1, 16))

    # ---------------------------------------------------------------------------
    # 6. Remediation Recommendations Section
    # ---------------------------------------------------------------------------
    story.append(Paragraph("5. Immediate Remediation & Hardening", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_PRIMARY_DARK, spaceBefore=2, spaceAfter=12))

    remediations = [
        "<b>Patch & Update Software:</b> Immediately apply vendor security updates for all identified outdated services and libraries.",
        "<b>Enforce Strict Firewall Policies:</b> Restrict inbound network access to essential ports only; block unused open ports.",
        "<b>Implement Strong Authentication:</b> Enforce multi-factor authentication (MFA) and disable password-based SSH authentication in favor of key pairs.",
        "<b>Continuous Monitoring & Auditing:</b> Enable continuous log monitoring, intrusion detection systems (IDS), and regular automated vulnerability assessment.",
    ]

    for rec in remediations:
        story.append(Paragraph(f"• {rec}", styles["BulletItem"]))

    # Build document using custom NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path
