"""Incident Management view for investigating, updating, and documenting security incidents."""

import streamlit as st
import pandas as pd
from typing import List, Dict, Any
from loganalyzer.database import DatabaseManager
from ui.components import get_severity_badge_html, get_status_badge_html


def render_incidents(db: DatabaseManager):
    st.markdown("### Incident Management & SOC Investigation")
    st.caption("Investigate correlated security incidents, manage investigation lifecycle, and record evidence.")

    # Filtering & Search Controls
    f1, f2, f3, f4 = st.columns([1, 1, 1, 2])
    with f1:
        status_filter = st.selectbox("Status Filter", ["ALL", "OPEN", "INVESTIGATING", "RESOLVED"])
    with f2:
        severity_filter = st.selectbox("Severity Filter", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with f3:
        origin_filter = st.selectbox("Origin Filter", ["ALL", "GENUINE", "SYNTHETIC", "MIXED"])
    with f4:
        search_query = st.text_input("Search Incidents (ID, Title, IP, Account)", placeholder="e.g. 198.51.100.5 or admin")

    filter_status = None if status_filter == "ALL" else status_filter
    filter_sev = None if severity_filter == "ALL" else severity_filter
    filter_q = search_query.strip() if search_query.strip() else None

    incidents = db.get_incidents(status=filter_status, severity=filter_sev, search_query=filter_q)

    if origin_filter != "ALL":
        incidents = [inc for inc in incidents if inc.get("telemetry_nature") == origin_filter]

    if not incidents:
        st.info("No security incidents matching current filter criteria.")
        return

    st.markdown(f"**Found {len(incidents)} Incidents**")

    # Select incident for deep dive investigation
    selected_incident_id = st.selectbox(
        "Select Incident to Investigate & Manage",
        options=[inc["incident_id"] for inc in incidents],
        format_func=lambda iid: f"{iid} — {[x['title'] for x in incidents if x['incident_id'] == iid][0]}"
    )

    selected_inc = next((x for x in incidents if x["incident_id"] == selected_incident_id), incidents[0])

    # Incident Overview Cards
    st.markdown("---")
    d1, d2, d3, d4 = st.columns([2, 1, 1, 1])

    with d1:
        st.markdown(f"#### {selected_inc['title']}")
        st.write(selected_inc["description"])

    with d2:
        st.markdown(f"**Severity:** {selected_inc['severity']}")
        st.markdown(f"**Status:** {selected_inc['status']}")
        nature = selected_inc.get("telemetry_nature", "GENUINE")
        nature_badge = "🌐 Mixed Investigation" if nature == "MIXED" else ("🧪 Synthetic Lab" if nature == "SYNTHETIC" else "🛡️ Genuine Host")
        st.markdown(f"**Origin:** `{nature_badge}`")

    with d3:
        st.markdown(f"**Risk Score:** `{selected_inc['risk_score']}/100`")
        st.markdown(f"**Source IP:** `{selected_inc['source_ip'] or 'N/A'}`")

    with d4:
        st.markdown(f"**Created:** {selected_inc['created_at'][:19]}")
        st.markdown(f"**Updated:** {selected_inc['updated_at'][:19]}")

    # Tabs for Details: Analysis, Notes, Related Events
    tab_overview, tab_evidence, tab_notes = st.tabs(["Investigation Overview", "Correlated Evidence", "Analyst Notes & Actions"])

    with tab_overview:
        st.markdown("##### Attack Vector & Risk Breakdown")
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Targeted Accounts:**")
            if selected_inc["affected_accounts"]:
                st.write(", ".join(f"`{a}`" for a in selected_inc["affected_accounts"]))
            else:
                st.write("None recorded")

            st.markdown("**MITRE ATT&CK Techniques:**")
            if selected_inc["mitre_techniques"]:
                st.write(", ".join(f"`{t}`" for t in selected_inc["mitre_techniques"]))
            else:
                st.write("None")

        with col_b:
            st.markdown("**Explainable Risk Scoring Factors:**")
            if selected_inc["risk_factors"]:
                for rf in selected_inc["risk_factors"]:
                    st.markdown(f"- {rf}")
            else:
                st.write("Standard baseline risk.")

    with tab_evidence:
        st.markdown("##### Correlated Detection Alerts")
        det_ids = selected_inc.get("related_detection_ids", [])
        if det_ids:
            all_dets = db.get_detections()
            matching_dets = [d for d in all_dets if d["id"] in det_ids]
            if matching_dets:
                st.dataframe(pd.DataFrame(matching_dets)[[
                    "id", "timestamp", "rule_id", "rule_name", "severity", "description", "mitre_technique_id"
                ]], use_container_width=True)
            else:
                st.write(f"Detection IDs: {det_ids}")
        else:
            st.info("No explicit detection alerts linked to this incident.")

    with tab_notes:
        st.markdown("##### Incident Lifecycle & Analyst Case Notes")

        # Status Update
        c_stat, c_btn = st.columns([2, 1])
        with c_stat:
            new_status = st.selectbox(
                "Update Incident Lifecycle Status",
                ["OPEN", "INVESTIGATING", "RESOLVED"],
                index=["OPEN", "INVESTIGATING", "RESOLVED"].index(selected_inc["status"])
            )
        with c_btn:
            st.write("")
            st.write("")
            if st.button("Apply Status Change", type="primary"):
                db.update_incident_status(selected_inc["incident_id"], new_status)
                st.success(f"Status updated to {new_status}!")
                st.rerun()

        # Add Investigation Note
        st.markdown("---")
        st.markdown("##### Add Investigation Note")
        note_author = st.text_input("Analyst Name / ID", value="SOC Analyst 1")
        note_text = st.text_area("Investigation Findings & Action Taken", placeholder="Document containment actions, firewall blocks, or user communication...")

        if st.button("Add Case Note"):
            if note_text.strip():
                db.add_investigation_note(selected_inc["incident_id"], note_author, note_text.strip())
                st.success("Case note added successfully!")
                st.rerun()
            else:
                st.warning("Note content cannot be empty.")

        # Notes History
        existing_notes = db.get_investigation_notes(selected_inc["incident_id"])
        if existing_notes:
            st.markdown("##### Note History")
            for n in existing_notes:
                st.markdown(
                    f"**{n['author']}** (`{n['created_at'][:19]}`):<br/>"
                    f"> {n['note']}",
                    unsafe_allow_html=True
                )
        else:
            st.caption("No investigation notes logged yet.")
