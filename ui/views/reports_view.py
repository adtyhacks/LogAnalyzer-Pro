"""Reporting and CSV/PDF export view for executive and technical compliance."""

import streamlit as st
from datetime import datetime
from loganalyzer.config import utc_now
from loganalyzer.database import DatabaseManager
from loganalyzer.reporting.pdf_report import PdfReportGenerator
from loganalyzer.reporting.csv_export import CsvExporter


def render_reports_view(db: DatabaseManager):
    st.markdown("### Security Investigation Reports & Data Exports")
    st.caption("Generate publication-ready PDF security investigation reports and structured CSV telemetry exports.")

    incidents = db.get_incidents()
    detections = db.get_detections()
    stats = db.get_stats_summary()
    events = db.get_events(limit=5000)

    col_pdf, col_csv = st.columns([1, 1])

    with col_pdf:
        st.markdown("#### 1. PDF Investigation Report")
        st.write(
            "Compile an executive and technical investigation report containing executive summaries, "
            "incident severity distributions, MITRE ATT&CK mappings, and forensic remediation guidance."
        )

        if st.button("Generate Official PDF Investigation Report", type="primary"):
            with st.spinner("Compiling investigation telemetry and rendering PDF..."):
                generator = PdfReportGenerator()
                pdf_path = generator.generate_report(
                    incidents=incidents,
                    detections=detections,
                    stats_summary=stats
                )

                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()

                st.success("PDF Report generated successfully!")
                st.download_button(
                    label="⬇️ Download PDF Security Report",
                    data=pdf_bytes,
                    file_name=pdf_path.name,
                    mime="application/pdf"
                )

    with col_csv:
        st.markdown("#### 2. Structured CSV Telemetry Exports")
        st.write("Export raw or normalized analytical datasets for external SIEM, BI, or archival integration.")

        # Export Detections CSV
        st.markdown("##### Detections & Alerts")
        if detections:
            det_csv = CsvExporter.export_detections(detections)
            st.download_button(
                label="⬇️ Export Detections (CSV)",
                data=det_csv,
                file_name=f"detections_export_{utc_now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.caption("No detections available to export.")

        # Export Incidents CSV
        st.markdown("##### Correlated Incidents")
        if incidents:
            inc_csv = CsvExporter.export_incidents(incidents)
            st.download_button(
                label="⬇️ Export Incidents (CSV)",
                data=inc_csv,
                file_name=f"incidents_export_{utc_now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.caption("No incidents available to export.")

        # Export Events CSV
        st.markdown("##### Normalized Events")
        if events:
            ev_csv = CsvExporter.export_events(events)
            st.download_button(
                label="⬇️ Export Normalized Events (CSV)",
                data=ev_csv,
                file_name=f"events_export_{utc_now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.caption("No events available to export.")
