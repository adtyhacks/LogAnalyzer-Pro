"""SOC Overview dashboard view with interactive Plotly visualizations."""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from loganalyzer.database import DatabaseManager
from ui.components import render_metric_card, get_severity_badge_html, get_status_badge_html, get_plotly_dark_layout


def render_overview(db: DatabaseManager):
    st.markdown("### Security Operations Center (SOC) Overview")
    st.caption("Real-time telemetry, threat detection analysis, incident prioritization, and MITRE ATT&CK alignment.")

    stats = db.get_stats_summary()

    # 1. Metric Cards Row: 6 Core SOC Operational Metrics
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    with m1:
        render_metric_card("Total Events", f"{stats['total_events']:,}", "Normalized Logs", "#3B82F6")
    with m2:
        render_metric_card("Total Detections", f"{stats['total_detections']:,}", f"Crit: {stats['critical_count']} | High: {stats['high_count']}", "#EC4899")
    with m3:
        render_metric_card("Critical Incidents", f"{stats['critical_incidents']:,}", "Score >= 80/100", "#DC2626")
    with m4:
        render_metric_card("High-Risk Incidents", f"{stats['high_incidents']:,}", "Score 60-79/100", "#EA580C")
    with m5:
        render_metric_card("Open Incidents", f"{stats['open_incidents']:,}", "Action Required", "#F59E0B")
    with m6:
        render_metric_card("Suspicious IPs", f"{stats['unique_suspicious_ips']:,}", "Threat Sources", "#8B5CF6")

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 2. Charts Row: Timeline and Severity Breakdown
    c1, c2 = st.columns([2, 1])

    with c1:
        st.markdown("##### Attack Activity & Authentication Failure Timeline")
        events = db.get_events(limit=3000)
        if events:
            df_ev = pd.DataFrame(events)
            df_ev['timestamp'] = pd.to_datetime(df_ev['timestamp'])
            df_ev = df_ev.sort_values('timestamp')
            df_grouped = df_ev.set_index('timestamp').resample('5min').agg({
                'id': 'count',
                'status': lambda s: (s == 'FAILURE').sum()
            }).rename(columns={'id': 'Total Events', 'status': 'Failures'}).reset_index()

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_grouped['timestamp'],
                y=df_grouped['Total Events'],
                name='Total Events',
                line=dict(color='#3B82F6', width=2),
                fill='tozeroy',
                fillcolor='rgba(59, 130, 246, 0.1)'
            ))
            fig.add_trace(go.Bar(
                x=df_grouped['timestamp'],
                y=df_grouped['Failures'],
                name='Auth Failures',
                marker_color='#EF4444',
                opacity=0.8
            ))
            fig.update_layout(get_plotly_dark_layout())
            fig.update_layout(height=300, yaxis_title="Events / 5 Min")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events ingested yet. Load security logs via 'Log Ingestion'.")

    with c2:
        st.markdown("##### Detection Severity Distribution")
        sev_data = {
            "CRITICAL": stats["critical_count"],
            "HIGH": stats["high_count"],
            "MEDIUM": stats["medium_count"],
            "LOW": stats["low_count"]
        }
        df_sev = pd.DataFrame([{"Severity": k, "Count": v} for k, v in sev_data.items() if v > 0])
        if not df_sev.empty:
            colors_map = {
                "CRITICAL": "#DC2626",
                "HIGH": "#EA580C",
                "MEDIUM": "#F59E0B",
                "LOW": "#3B82F6"
            }
            fig_pie = px.pie(
                df_sev,
                values="Count",
                names="Severity",
                hole=0.55,
                color="Severity",
                color_discrete_map=colors_map
            )
            fig_pie.update_layout(get_plotly_dark_layout())
            fig_pie.update_layout(height=300, showlegend=True)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No active detection alerts recorded.")

    # 3. Third Row: Top Suspicious IPs, Most Targeted Accounts, and MITRE Distribution
    c3, c4 = st.columns(2)
    with c3:
        st.markdown("##### Top Suspicious Source IPs")
        if stats["top_ips"]:
            df_ips = pd.DataFrame(stats["top_ips"])
            fig_ips = px.bar(
                df_ips,
                x="cnt",
                y="source_ip",
                orientation='h',
                labels={"cnt": "Failure Count", "source_ip": "Source IP"},
                color="cnt",
                color_continuous_scale="Reds"
            )
            fig_ips.update_layout(get_plotly_dark_layout())
            fig_ips.update_layout(height=260, yaxis={'categoryorder': 'total ascending'}, coloraxis_showscale=False)
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.write("No suspicious IPs identified.")

    with c4:
        st.markdown("##### Most Targeted Accounts")
        if stats["top_accounts"]:
            df_accts = pd.DataFrame(stats["top_accounts"])
            fig_accts = px.bar(
                df_accts,
                x="cnt",
                y="username",
                orientation='h',
                labels={"cnt": "Authentication Count", "username": "Account"},
                color="cnt",
                color_continuous_scale="Purples"
            )
            fig_accts.update_layout(get_plotly_dark_layout())
            fig_accts.update_layout(height=260, yaxis={'categoryorder': 'total ascending'}, coloraxis_showscale=False)
            st.plotly_chart(fig_accts, use_container_width=True)
        else:
            st.write("No account targets recorded.")

    # 4. Fourth Row: MITRE ATT&CK Technique Distribution
    st.markdown("##### MITRE ATT&CK Enterprise Technique Distribution")
    if stats["mitre_distribution"]:
        df_mitre = pd.DataFrame(stats["mitre_distribution"])
        df_mitre["Label"] = df_mitre["mitre_technique_id"] + " - " + df_mitre["mitre_technique_name"]
        fig_mitre = px.bar(
            df_mitre,
            x="cnt",
            y="Label",
            orientation='h',
            labels={"cnt": "Detections", "Label": "MITRE ATT&CK Technique"},
            color="cnt",
            color_continuous_scale="Blues"
        )
        fig_mitre.update_layout(get_plotly_dark_layout())
        fig_mitre.update_layout(height=240, yaxis={'categoryorder': 'total ascending'}, coloraxis_showscale=False)
        st.plotly_chart(fig_mitre, use_container_width=True)
    else:
        st.info("No MITRE ATT&CK detections mapped yet.")

    # 5. Fifth Row: Priority Correlated Incidents Queue
    st.markdown("##### Priority Correlated Incident Queue")
    incidents = db.get_incidents(status="OPEN")
    if incidents:
        display_rows = []
        for inc in incidents[:10]:
            display_rows.append({
                "Incident ID": inc["incident_id"],
                "Severity": inc["severity"],
                "Risk Score": f"{inc['risk_score']}/100",
                "Source IP": inc["source_ip"] or "Unknown",
                "Title": inc["title"],
                "Target Accounts": ", ".join(inc["affected_accounts"]) or "N/A",
                "MITRE ATT&CK": ", ".join(inc["mitre_techniques"]) or "N/A",
                "Status": inc["status"]
            })
        st.dataframe(pd.DataFrame(display_rows), use_container_width=True)
    else:
        st.success("All security incidents have been resolved or no open incidents.")
