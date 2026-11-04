"""LogAnalyzer Pro - Intelligent Security Log Analysis & Incident Investigation Platform.

Main Streamlit Application Entry Point.
"""

import streamlit as st
from datetime import datetime

from loganalyzer.config import APP_NAME, APP_SUBTITLE, APP_VERSION
from loganalyzer.database import DatabaseManager
from loganalyzer.detection.engine import DetectionEngine
from loganalyzer.correlation.correlator import CorrelationEngine

from ui.components import apply_theme
from ui.views.overview import render_overview
from ui.views.ingestion import render_ingestion
from ui.views.incidents import render_incidents
from ui.views.ip_intel import render_ip_intel
from ui.views.mitre_view import render_mitre_view
from ui.views.reports_view import render_reports_view


def main():
    st.set_page_config(
        page_title="LogAnalyzer Pro — SOC Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Apply SOC Dark Theme
    apply_theme()

    # Core singletons
    db = DatabaseManager()
    det_engine = DetectionEngine(db_manager=db)
    correlator = CorrelationEngine(db_manager=db)

    # Sidebar navigation with query parameter support
    page_options = [
        "🛡️ SOC Overview",
        "📥 Log Ingestion",
        "🚨 Incident Management",
        "🌐 IP Investigation",
        "🎯 MITRE ATT&CK",
        "📄 Reports & Exports"
    ]
    query_page = st.query_params.get("page", "")
    page_map = {
        "overview": 0,
        "ingestion": 1,
        "incidents": 2,
        "ip_intel": 3,
        "mitre": 4,
        "reports": 5
    }
    default_index = page_map.get(str(query_page).lower(), 0)

    # Sidebar
    with st.sidebar:
        st.markdown(f"## 🛡️ {APP_NAME}")
        st.caption(f"v{APP_VERSION} | SOC Security Platform")
        st.markdown("---")

        page = st.radio(
            "SOC Navigation",
            page_options,
            index=default_index
        )

        st.markdown("---")
        # Sidebar Quick Metrics
        stats = db.get_stats_summary()
        st.markdown("##### Operational Status")
        st.markdown(f"• **Events Ingested:** `{stats['total_events']:,}`")
        st.markdown(f"• **Active Alerts:** `{stats['total_detections']:,}`")
        st.markdown(f"• **Open Incidents:** `{stats['open_incidents']:,}`")
        st.markdown(f"• **Suspicious IPs:** `{stats['unique_suspicious_ips']:,}`")

        st.markdown("---")
        st.caption("Engine: Modular Python 3.12 Rules\nDB: SQLite (WAL Mode)\nStatus: Operational 🟢")

    # Routing
    if page == "🛡️ SOC Overview":
        render_overview(db)
    elif page == "📥 Log Ingestion":
        render_ingestion(db, det_engine, correlator)
    elif page == "🚨 Incident Management":
        render_incidents(db)
    elif page == "🌐 IP Investigation":
        render_ip_intel(db)
    elif page == "🎯 MITRE ATT&CK":
        render_mitre_view(db)
    elif page == "📄 Reports & Exports":
        render_reports_view(db)


if __name__ == "__main__":
    main()
