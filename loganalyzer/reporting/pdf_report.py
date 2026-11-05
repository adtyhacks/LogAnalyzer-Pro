"""Professional PDF Security Investigation Report Generator using ReportLab."""

import io
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.pdfgen import canvas

from loganalyzer.config import REPORTS_DIR, utc_now
from loganalyzer.utils import sanitize_privacy


class NumberedCanvas(canvas.Canvas):
    """Adds professional running header and footer with page numbers."""

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
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#4B5563"))

        # Running header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "LOGANALYZER PRO — SOC INCIDENT INVESTIGATION REPORT")
            self.drawRightString(letter[0] - 54, letter[1] - 36, utc_now().strftime("%Y-%m-%d %H:%M UTC"))
            self.setStrokeColor(colors.HexColor("#E5E7EB"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Running footer
        self.setFont("Helvetica", 8)
        self.drawString(54, 36, "CONFIDENTIAL — FOR INTERNAL SECURITY OPERATIONS USE ONLY")
        self.drawRightString(letter[0] - 54, 36, f"Page {self._pageNumber} of {page_count}")
        self.setStrokeColor(colors.HexColor("#E5E7EB"))
        self.setLineWidth(0.5)
        self.line(54, 48, letter[0] - 54, 48)

        self.restoreState()


class PdfReportGenerator:
    """Generates comprehensive executive and technical security investigation PDF reports."""

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        incidents: List[Dict[str, Any]],
        detections: List[Dict[str, Any]],
        stats_summary: Dict[str, Any],
        output_filename: Optional[str] = None
    ) -> Path:
        """Build and write the PDF report to disk, returning the Path."""
        if not output_filename:
            timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"Security_Investigation_Report_{timestamp}.pdf"

        report_path = self.reports_dir / output_filename
        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        # Custom styles
        primary_color = colors.HexColor("#0F172A")
        accent_color = colors.HexColor("#2563EB")
        critical_color = colors.HexColor("#DC2626")
        high_color = colors.HexColor("#EA580C")
        text_dark = colors.HexColor("#1E293B")
        bg_light = colors.HexColor("#F8FAFC")

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=primary_color,
            spaceAfter=4
        )

        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=15
        )

        heading2_style = ParagraphStyle(
            'Heading2_Custom',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=primary_color,
            spaceBefore=12,
            spaceAfter=8
        )

        body_style = ParagraphStyle(
            'Body_Custom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=text_dark
        )

        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.white
        )

        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=text_dark
        )

        elements = []

        # 1. Header Banner
        elements.append(Paragraph("LOGANALYZER PRO", title_style))
        elements.append(Paragraph("Intelligent Security Log Analysis & Incident Investigation Platform", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceAfter=15))

        # Metadata Table
        meta_data = [
            [
                Paragraph("<b>Report Generated:</b>", table_cell_style),
                Paragraph(utc_now().strftime("%Y-%m-%d %H:%M:%S UTC"), table_cell_style),
                Paragraph("<b>Investigation Scope:</b>", table_cell_style),
                Paragraph("Complete Workspace Ingestion", table_cell_style)
            ],
            [
                Paragraph("<b>Total Records Analyzed:</b>", table_cell_style),
                Paragraph(f"{stats_summary.get('total_events', 0)} (Gen: {stats_summary.get('genuine_events', 0)} | Synth: {stats_summary.get('synthetic_events', 0)})", table_cell_style),
                Paragraph("<b>Total Detections:</b>", table_cell_style),
                Paragraph(str(stats_summary.get("total_detections", 0)), table_cell_style)
            ],
            [
                Paragraph("<b>Active Incidents:</b>", table_cell_style),
                Paragraph(str(stats_summary.get("open_incidents", 0)), table_cell_style),
                Paragraph("<b>Suspicious Source IPs:</b>", table_cell_style),
                Paragraph(str(stats_summary.get("unique_suspicious_ips", 0)), table_cell_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_light),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 15))

        # 2. Executive Summary
        elements.append(Paragraph("1. Executive Summary", heading2_style))
        gen_cnt = stats_summary.get('genuine_events', 0)
        syn_cnt = stats_summary.get('synthetic_events', 0)
        tot_cnt = stats_summary.get('total_events', 0)
        exec_text = (
            f"During the security log analysis, LogAnalyzer Pro ingested and evaluated "
            f"<b>{tot_cnt} total telemetry records</b> (comprising <b>{gen_cnt} genuine host records</b> "
            f"and <b>{syn_cnt} controlled simulation records</b>) across multiple operational log formats. "
            f"The modular detection engine generated <b>{stats_summary.get('total_detections', 0)}</b> detection alerts, "
            f"including <b>{stats_summary.get('critical_count', 0)} Critical</b>, "
            f"<b>{stats_summary.get('high_count', 0)} High</b>, and <b>{stats_summary.get('medium_count', 0)} Medium</b> severity findings. "
            f"The event correlation engine grouped related findings into <b>{len(incidents)} distinct security incidents</b>, "
            f"prioritized by an explainable multi-factor risk score."
        )
        elements.append(Paragraph(exec_text, body_style))
        elements.append(Spacer(1, 15))

        # 3. Incident Findings Table
        elements.append(Paragraph("2. Correlated Security Incidents", heading2_style))
        if incidents:
            inc_headers = [
                Paragraph("Incident ID", table_header_style),
                Paragraph("Severity", table_header_style),
                Paragraph("Risk", table_header_style),
                Paragraph("Origin", table_header_style),
                Paragraph("Source IP", table_header_style),
                Paragraph("Title & Summary", table_header_style),
                Paragraph("MITRE ATT&CK", table_header_style)
            ]
            inc_rows = [inc_headers]

            for inc in incidents[:15]:  # Top 15 incidents
                sev = inc.get("severity", "LOW")
                techs = ", ".join(inc.get("mitre_techniques", [])) or "N/A"
                raw_accts = inc.get("affected_accounts", [])
                accts_clean = sanitize_privacy(raw_accts) if isinstance(raw_accts, list) else [sanitize_privacy(str(raw_accts))]
                accts = ", ".join(accts_clean) or "None"
                nature = inc.get("telemetry_nature", "GENUINE")

                clean_title = sanitize_privacy(inc.get('title', ''))
                clean_desc = sanitize_privacy(inc.get('description', ''))
                desc_text = f"<b>{clean_title}</b><br/>{clean_desc[:130]}...<br/><i>Target(s): {accts}</i>"

                inc_rows.append([
                    Paragraph(inc.get("incident_id", ""), table_cell_style),
                    Paragraph(f"<b>{sev}</b>", table_cell_style),
                    Paragraph(f"{inc.get('risk_score', 0)}/100", table_cell_style),
                    Paragraph(f"<b>{nature}</b>", table_cell_style),
                    Paragraph(inc.get("source_ip", "N/A") or "N/A", table_cell_style),
                    Paragraph(desc_text, table_cell_style),
                    Paragraph(techs, table_cell_style)
                ])

            col_widths = [1.0 * inch, 0.6 * inch, 0.5 * inch, 0.8 * inch, 0.9 * inch, 2.2 * inch, 1.0 * inch]
            inc_table = Table(inc_rows, colWidths=col_widths, repeatRows=1)
            inc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(inc_table)
        else:
            elements.append(Paragraph("No active security incidents identified.", body_style))

        elements.append(Spacer(1, 15))

        # 4. MITRE ATT&CK Technique Mapping Summary
        elements.append(Paragraph("3. MITRE ATT&CK Enterprise Mapping", heading2_style))
        mitre_headers = [
            Paragraph("Technique ID", table_header_style),
            Paragraph("Technique Name", table_header_style),
            Paragraph("Detection Count", table_header_style),
            Paragraph("Adversary Behavior", table_header_style)
        ]
        mitre_rows = [mitre_headers]

        # Calculate technique frequencies
        tech_counts: Dict[str, int] = {}
        tech_names: Dict[str, str] = {}
        for d in detections:
            tid = d.get("mitre_technique_id")
            if tid:
                tech_counts[tid] = tech_counts.get(tid, 0) + 1
                tech_names[tid] = d.get("mitre_technique_name") or "Enterprise Technique"

        if tech_counts:
            for tid, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True):
                mitre_rows.append([
                    Paragraph(f"<b>{tid}</b>", table_cell_style),
                    Paragraph(tech_names.get(tid, "Technique"), table_cell_style),
                    Paragraph(str(count), table_cell_style),
                    Paragraph(f"Mapped to {count} triggered alert events", table_cell_style)
                ])

            mitre_table = Table(mitre_rows, colWidths=[1.2 * inch, 2.2 * inch, 1.2 * inch, 2.4 * inch])
            mitre_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(mitre_table)
        else:
            elements.append(Paragraph("No MITRE ATT&CK techniques associated with current event set.", body_style))

        elements.append(Spacer(1, 15))

        # 5. Risk Assessment & Recommendations
        elements.append(Paragraph("4. Risk Assessment & Recommended Remediation", heading2_style))
        remediation_text = (
            "<b>Priority Remediation Actions:</b><br/>"
            "• <b>Block Suspicious External Source IPs:</b> Immediately drop perimeter traffic from high-frequency failure sources on corporate firewalls.<br/>"
            "• <b>Enforce MFA and Credential Reset:</b> Require mandatory Multi-Factor Authentication (MFA) and initiate password resets for targeted accounts.<br/>"
            "• <b>Account Lockout Policies:</b> Implement dynamic threshold-based account lockouts with exponential backoff to deter brute-force and password spraying.<br/>"
            "• <b>Privileged Access Monitoring:</b> Audit all administrative logins, restricting direct root and Administrator SSH/RDP access to dedicated bastion hosts."
        )
        elements.append(Paragraph(remediation_text, body_style))

        # Build document
        doc.build(elements, canvasmaker=NumberedCanvas)
        return report_path
