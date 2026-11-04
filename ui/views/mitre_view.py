"""MITRE ATT&CK Enterprise matrix and technique exploration view."""

import streamlit as st
import pandas as pd
import plotly.express as px
from loganalyzer.database import DatabaseManager
from loganalyzer.intel.mitre_mapper import MitreMapper
from ui.components import get_plotly_dark_layout


def render_mitre_view(db: DatabaseManager):
    st.markdown("### MITRE ATT&CK Enterprise Matrix & Technique Mapping")
    st.caption("Adversary tactics, techniques, and mapped behavioral detections.")

    mapper = MitreMapper()
    techniques = mapper.get_all_techniques()

    detections = db.get_detections()

    # Calculate detection counts per technique
    tech_counts = {}
    for d in detections:
        tid = d.get("mitre_technique_id")
        if tid:
            tech_counts[tid] = tech_counts.get(tid, 0) + 1

    # Visual Distribution Chart
    st.markdown("##### Mapped Detections by ATT&CK Technique")
    chart_data = []
    for t in techniques:
        tid = t["technique_id"]
        cnt = tech_counts.get(tid, 0)
        chart_data.append({
            "Technique": f"{tid}: {t['name']}",
            "Technique ID": tid,
            "Tactic": t.get("tactic", "Unknown"),
            "Detections": cnt
        })

    df_chart = pd.DataFrame(chart_data)
    if not df_chart.empty and df_chart["Detections"].sum() > 0:
        fig = px.bar(
            df_chart[df_chart["Detections"] > 0],
            x="Detections",
            y="Technique",
            orientation='h',
            color="Tactic",
            labels={"Detections": "Alert Count", "Technique": "MITRE Technique"}
        )
        fig.update_layout(get_plotly_dark_layout())
        fig.update_layout(height=260, yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No detections currently mapped to MITRE techniques. Ingest logs to view adversary mapping.")

    st.markdown("---")
    st.markdown("##### Supported MITRE ATT&CK Techniques Knowledge Base")

    # Technique Explorer Cards
    for t in techniques:
        tid = t["technique_id"]
        cnt = tech_counts.get(tid, 0)

        with st.expander(f"**{tid} — {t['name']}** (Active Detections: {cnt})", expanded=(cnt > 0)):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"**Tactic:** `{t.get('tactic', 'N/A')}`")
                st.markdown(f"**Description:** {t['description']}")
                st.markdown(f"**Official Reference:** [{t['url']}]({t['url']})")
            with col2:
                st.metric("Triggered Alerts", cnt)

            # Show linked detections
            if cnt > 0:
                linked = [d for d in detections if d.get("mitre_technique_id") == tid]
                if linked:
                    st.markdown("###### Linked Detections:")
                    st.dataframe(pd.DataFrame(linked)[[
                        "timestamp", "rule_name", "severity", "source_ip", "username", "description"
                    ]], use_container_width=True)
