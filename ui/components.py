"""Reusable UI components, custom SOC styling, badges, and Plotly templates."""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

# SOC Custom CSS
SOC_CUSTOM_CSS = """
<style>
    /* Dark SOC Theme styling */
    .stApp {
        background-color: #0B0F19;
        color: #E2E8F0;
    }
    .metric-card {
        background: linear-gradient(135deg, #131B2E 0%, #111827 100%);
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 16px 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .metric-label {
        font-size: 0.8rem;
        font-weight: 600;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #F8FAFC;
        margin-top: 4px;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748B;
        margin-top: 2px;
    }
    /* Severity Badges */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #F87171;
        border: 1px solid #EF4444;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #FB923C;
        border: 1px solid #F97316;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-medium {
        background-color: rgba(245, 158, 11, 0.2);
        color: #FBBF24;
        border: 1px solid #F59E0B;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-low {
        background-color: rgba(59, 130, 246, 0.2);
        color: #60A5FA;
        border: 1px solid #3B82F6;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-open {
        background-color: rgba(239, 68, 68, 0.15);
        color: #FCA5A5;
        border: 1px solid #EF4444;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-investigating {
        background-color: rgba(245, 158, 11, 0.15);
        color: #FDE68A;
        border: 1px solid #F59E0B;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
    }
    .badge-resolved {
        background-color: rgba(16, 185, 129, 0.15);
        color: #6EE7B7;
        border: 1px solid #10B981;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.75rem;
    }
</style>
"""


def apply_theme():
    """Inject custom styles into the Streamlit session."""
    st.markdown(SOC_CUSTOM_CSS, unsafe_allow_html=True)


def render_metric_card(label: str, value: Any, subtext: str = "", border_color: str = "#1E293B"):
    html = f"""
    <div class="metric-card" style="border-left: 4px solid {border_color};">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-sub">{subtext}</div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def get_severity_badge_html(severity: str) -> str:
    s = (severity or "LOW").upper()
    cls = f"badge-{s.lower()}"
    return f'<span class="{cls}">{s}</span>'


def get_status_badge_html(status: str) -> str:
    s = (status or "OPEN").upper()
    cls = f"badge-{s.lower()}"
    return f'<span class="{cls}">{s}</span>'


def get_plotly_dark_layout() -> dict:
    """Standardized dark mode SOC theme dictionary for Plotly charts."""
    return dict(
        paper_bgcolor="rgba(17, 24, 39, 0.0)",
        plot_bgcolor="rgba(17, 24, 39, 0.0)",
        font=dict(color="#94A3B8", family="Arial, sans-serif", size=11),
        margin=dict(l=20, r=20, t=30, b=20),
        xaxis=dict(
            gridcolor="#1E293B",
            zerolinecolor="#334155",
            showline=True,
            linecolor="#334155"
        ),
        yaxis=dict(
            gridcolor="#1E293B",
            zerolinecolor="#334155",
            showline=True,
            linecolor="#334155"
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color="#CBD5E1")
        )
    )
