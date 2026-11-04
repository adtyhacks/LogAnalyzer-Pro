"""IP Investigation view providing offline RFC analysis, behavioral telemetry, and threat indicators."""

import streamlit as st
import pandas as pd
from loganalyzer.database import DatabaseManager
from loganalyzer.intel.ip_intelligence import IpIntelligence
from ui.components import render_metric_card


def render_ip_intel(db: DatabaseManager):
    st.markdown("### Offline IP Intelligence & Host Investigation")
    st.caption("RFC address profiling, traffic aggregation, account targeting analysis, and behavioral indicators.")

    ip_intel = IpIntelligence(db)

    # Get distinct IPs from database
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT source_ip FROM events
            WHERE source_ip IS NOT NULL AND source_ip != ''
            ORDER BY source_ip ASC
        """)
        discovered_ips = [r[0] for r in cursor.fetchall()]

    col_select, col_custom = st.columns([2, 1])
    with col_select:
        selected_ip = st.selectbox(
            "Select Discovered IP from Ingested Logs",
            options=discovered_ips if discovered_ips else ["No IPs Ingested"],
            index=0
        )
    with col_custom:
        custom_ip = st.text_input("Or Enter Custom IP to Profile", placeholder="e.g. 198.51.100.50")

    target_ip = custom_ip.strip() if custom_ip.strip() else selected_ip

    if not target_ip or target_ip == "No IPs Ingested":
        st.info("No IP selected. Ingest security logs or type an IP address above.")
        return

    # Run investigation
    result = ip_intel.investigate_ip(target_ip)
    cls = result["classification"]

    st.markdown("---")
    st.markdown(f"#### Profile for IP: `{target_ip}`")

    # Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        render_metric_card("Scope / Category", cls.get("scope", "Unknown"), "RFC Classification", "#3B82F6")
    with m2:
        render_metric_card("Total Transactions", str(result["total_events"]), "Logged Events", "#6366F1")
    with m3:
        render_metric_card("Failed Logins", str(result["failed_logins"]), f"Ratio: {result['failure_ratio_pct']}%", "#EF4444")
    with m4:
        render_metric_card("Successful Logins", str(result["successful_logins"]), "Accepted Sessions", "#10B981")
    with m5:
        render_metric_card("Targeted Accounts", str(len(result["associated_users"])), "Distinct Users", "#F59E0B")

    # Transparency Notice regarding External Lookups
    st.info(f"ℹ️ **Enrichment Notice:** {cls.get('enrichment_status')}")

    # Behavioral Indicators & Activity Breakdown
    c_left, c_right = st.columns([1, 1])

    with c_left:
        st.markdown("##### Behavioral Threat Indicators")
        if result["indicators"]:
            for ind in result["indicators"]:
                st.warning(f"⚠️ {ind}")
        else:
            st.success("No anomalous threat indicators triggered for this IP.")

        st.markdown("##### Temporal Footprint")
        st.write(f"- **First Seen:** `{result['first_seen'] or 'N/A'}`")
        st.write(f"- **Last Seen:** `{result['last_seen'] or 'N/A'}`")
        st.write(f"- **Public IP Space:** `{'Yes' if cls.get('is_public') else 'No'}`")
        st.write(f"- **Private RFC1918:** `{'Yes' if cls.get('is_private') else 'No'}`")
        st.write(f"- **Loopback:** `{'Yes' if cls.get('is_loopback') else 'No'}`")

    with c_right:
        st.markdown("##### Associated User Accounts")
        if result["associated_users"]:
            df_users = pd.DataFrame(result["associated_users"]).rename(columns={
                "username": "Account", "count": "Total Attempts", "fails": "Failures"
            })
            st.dataframe(df_users, use_container_width=True)
        else:
            st.write("No specific user accounts mapped.")

    # Correlated Incidents & Detections
    st.markdown("---")
    st.markdown("##### Associated Incidents & Detections")
    col_d, col_i = st.columns(2)

    with col_d:
        st.markdown("###### Detection Alerts")
        if result["detections"]:
            st.dataframe(pd.DataFrame(result["detections"])[[
                "timestamp", "rule_name", "severity", "mitre_technique_id"
            ]], use_container_width=True)
        else:
            st.write("No detection alerts linked.")

    with col_i:
        st.markdown("###### Linked Security Incidents")
        if result["incidents"]:
            st.dataframe(pd.DataFrame(result["incidents"])[[
                "incident_id", "title", "severity", "risk_score", "status"
            ]], use_container_width=True)
        else:
            st.write("No security incidents linked.")
