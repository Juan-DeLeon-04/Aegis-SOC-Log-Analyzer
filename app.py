from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from html import escape as html_escape
from pathlib import Path
import hashlib
import math
import re
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from mitre import ATTACK_REFERENCE_AS_OF, map_finding


# -----------------------------------------------------------------------------
# App configuration and visual system
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Aegis SIEM | Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

PALETTES = {
    "Graphite & Jade": {
        "bg": "#111613", "bg_deep": "#0c100e", "surface": "#19211c", "surface_2": "#202a23",
        "border": "#344238", "text": "#edf3ee", "muted": "#9ba99f", "accent": "#83c99d",
        "accent_strong": "#3e9166", "accent_soft": "rgba(131,201,157,.12)", "grid": "#344238",
        "glow": "rgba(72,126,91,.18)", "button_text": "#07120b", "panel_glow": "rgba(22,39,29,.9)",
    },
    "Midnight Blue": {
        "bg": "#0b1422", "bg_deep": "#08111d", "surface": "#101d2e", "surface_2": "#17283d",
        "border": "#2b4058", "text": "#edf3fb", "muted": "#9aadc2", "accent": "#60d4c7",
        "accent_strong": "#278b89", "accent_soft": "rgba(96,212,199,.12)", "grid": "#2b4058",
        "glow": "rgba(48,93,126,.22)", "button_text": "#061715", "panel_glow": "rgba(16,32,50,.92)",
    },
    "Light Analyst": {
        "bg": "#f1f4f1", "bg_deep": "#e9eeea", "surface": "#ffffff", "surface_2": "#e9efea",
        "border": "#d4ded6", "text": "#1c2a22", "muted": "#637268", "accent": "#277553",
        "accent_strong": "#175d40", "accent_soft": "rgba(39,117,83,.10)", "grid": "#d7e0d9",
        "glow": "rgba(76,139,99,.10)", "button_text": "#ffffff", "panel_glow": "rgba(255,255,255,.96)",
    },
}

# Use distinct, broadly available local fonts so the selector produces a visible change
# without downloading fonts or depending on a remote font service.
FONT_STACKS = {
    "Segoe UI / clean": "'Segoe UI', Tahoma, sans-serif",
    "Georgia / editorial": "'Georgia', 'Times New Roman', serif",
    "Consolas / technical": "'Consolas', 'Courier New', monospace",
}

FONT_LABELS = {
    "en": {
        "Segoe UI / clean": "Segoe UI · clean",
        "Georgia / editorial": "Georgia · editorial",
        "Consolas / technical": "Consolas · technical",
    },
    "es": {
        "Segoe UI / clean": "Segoe UI · limpia",
        "Georgia / editorial": "Georgia · editorial",
        "Consolas / technical": "Consolas · técnica",
    },
}


def build_ui_css(palette: dict[str, str], font_stack: str) -> str:
    return f"""
    <style>
      :root {{
        --bg:{palette['bg']}; --bg-deep:{palette['bg_deep']}; --surface:{palette['surface']};
        --surface-2:{palette['surface_2']}; --line:{palette['border']}; --ink:{palette['text']};
        --muted:{palette['muted']}; --accent:{palette['accent']}; --accent-strong:{palette['accent_strong']};
        --accent-soft:{palette['accent_soft']}; --grid:{palette['grid']}; --font-ui:{font_stack};
        /* Override Streamlit's startup theme tokens when the analyst switches palettes. */
        --background-color:{palette['bg']}; --secondary-background-color:{palette['surface']};
        --text-color:{palette['text']}; --primary-color:{palette['accent']}; --font:{font_stack};
      }}
      html, body, [class*="css"], [data-testid="stAppViewContainer"] {{ font-family:var(--font-ui)!important; }}
      .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {{
        background:radial-gradient(ellipse at 10% 0%, {palette['glow']} 0%, transparent 34%), linear-gradient(155deg,var(--bg),var(--bg-deep));
        color:var(--ink)!important; font-family:var(--font-ui)!important;
      }}
      /* Apply the chosen face to Streamlit text and controls too (not only custom HTML). */
      .stApp p, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4,
      .stApp [data-testid="stMarkdownContainer"], .stApp [data-testid="stMarkdownContainer"] *,
      .stApp [data-testid="stWidgetLabel"], .stApp [data-testid="stWidgetLabel"] *,
      .stApp [data-testid="stMetric"], .stApp [data-testid="stMetric"] *,
      .stApp button, .stApp input, .stApp textarea, .stApp [role="combobox"],
      .stApp [role="option"], .stApp table, .stApp th, .stApp td {{
        font-family:var(--font-ui)!important;
      }}
      .stApp p, .stApp label, .stApp [data-testid="stMarkdownContainer"],
      .stApp [data-testid="stWidgetLabel"], .stApp [data-testid="stCaptionContainer"] {{
        color:var(--ink)!important;
      }}
      [data-testid="stHeader"] {{ background:transparent; }}
      [data-testid="stSidebar"] {{ background:linear-gradient(180deg,var(--surface),var(--bg-deep)); border-right:1px solid var(--line); color:var(--ink)!important; }}
      [data-testid="stSidebar"] *:not(svg):not(path) {{ color:var(--ink)!important; }}
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {{ color:var(--muted)!important; }}
      /* BaseWeb inputs and selectboxes need their inner value nodes styled explicitly. */
      .stApp input, .stApp textarea, [data-baseweb="input"] input,
      [data-baseweb="select"] [class*="singleValue"], [data-baseweb="select"] [class*="placeholder"],
      [data-baseweb="select"] input, [data-baseweb="select"] [role="combobox"] {{
        background-color:var(--surface-2)!important; color:var(--ink)!important;
        -webkit-text-fill-color:var(--ink)!important; border-color:var(--line)!important;
      }}
      [data-baseweb="select"] svg {{ fill:var(--muted)!important; }}
      [data-baseweb="popover"], [data-baseweb="menu"], [role="listbox"] {{
        background:var(--surface)!important; color:var(--ink)!important; border-color:var(--line)!important;
      }}
      [role="option"], [role="option"] * {{ color:var(--ink)!important; }}
      input::placeholder, textarea::placeholder {{ color:var(--muted)!important; opacity:1!important; }}
      .block-container {{ padding-top:1.35rem; padding-bottom:3rem; max-width:1540px; }}
      h1,h2,h3,h4 {{ letter-spacing:-.035em; color:var(--ink); font-weight:750; }}
      h1 {{ font-weight:820; }}
      p, label, .stMarkdown, [data-testid="stMarkdownContainer"] {{ color:var(--ink); }}
      .eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.19em; font-size:.66rem; font-weight:850; }}
      .brand-lockup {{ display:flex; align-items:center; gap:11px; margin:4px 0 17px; padding:2px 0 15px; border-bottom:1px solid var(--line); }}
      .brand-glyph {{ width:38px; height:38px; border-radius:11px; display:flex; align-items:center; justify-content:center; color:var(--accent)!important; background:var(--accent-soft); border:1px solid var(--accent); font-size:1.05rem; font-weight:900; letter-spacing:-.05em; }}
      .brand-name {{ color:var(--ink); font-size:1rem; font-weight:900; letter-spacing:.13em; line-height:1.1; }}
      .brand-caption {{ color:var(--muted); font-size:.60rem; letter-spacing:.15em; margin-top:4px; }}
      .sidebar-section-label {{ color:var(--muted); font-size:.62rem; font-weight:850; letter-spacing:.17em; text-transform:uppercase; margin:4px 0 9px; }}
      .sidebar-footer {{ border-top:1px solid var(--line); margin-top:15px; padding-top:13px; color:var(--muted); font-family:var(--font-ui); font-size:.61rem; line-height:1.65; letter-spacing:.09em; }}
      .status-dot {{ display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--accent); margin-right:7px; box-shadow:0 0 0 4px var(--accent-soft); }}
      .hero {{ position:relative; overflow:hidden; border:1px solid var(--line); border-left:3px solid var(--accent); background:linear-gradient(115deg,{palette['panel_glow']},var(--surface)); border-radius:19px; padding:25px 29px; margin:0 0 24px; box-shadow:0 16px 48px rgba(0,0,0,.11); }}
      .hero:after {{ content:''; position:absolute; width:330px; height:230px; right:-90px; top:-105px; border-radius:50%; border:1px solid var(--accent-soft); box-shadow:0 0 0 22px rgba(131,201,157,.025),0 0 0 48px rgba(131,201,157,.018); pointer-events:none; }}
      .hero-content {{ display:flex; align-items:center; justify-content:space-between; gap:28px; position:relative; z-index:1; }}
      .hero-copy {{ min-width:0; }}
      .hero h1 {{ margin:.3rem 0 .45rem; font-size:2.1rem; line-height:1.08; }}
      .hero p {{ margin:0; color:var(--muted); max-width:780px; font-size:.96rem; line-height:1.55; }}
      .hero-mark {{ font-family:var(--font-ui); color:var(--accent); font-size:.68rem; font-weight:850; letter-spacing:.17em; }}
      .hero-side {{ flex:0 0 245px; border-left:1px solid var(--line); padding-left:22px; }}
      .hero-side-kicker {{ color:var(--muted); font-size:.61rem; font-weight:850; letter-spacing:.15em; text-transform:uppercase; }}
      .hero-side-value {{ color:var(--ink); font-size:.82rem; font-weight:850; letter-spacing:.04em; margin:8px 0 5px; }}
      .hero-side-meta {{ color:var(--muted); font-size:.63rem; line-height:1.55; letter-spacing:.07em; }}
      .section-kicker {{ color:var(--accent); font-size:.68rem; font-weight:900; text-transform:uppercase; letter-spacing:.17em; margin:.35rem 0 .55rem; }}
      .panel {{ border:1px solid var(--line); background:var(--surface); border-radius:15px; padding:17px 19px; }}
      .metric-card {{ position:relative; overflow:hidden; background:linear-gradient(145deg,var(--surface-2),var(--surface)); border:1px solid var(--line); border-radius:14px; padding:16px 18px; min-height:112px; box-shadow:0 8px 22px rgba(0,0,0,.06); }}
      .metric-card:before {{ content:''; position:absolute; left:0; top:15px; bottom:15px; width:2px; background:var(--accent); opacity:.9; }}
      .metric-label {{ color:var(--muted); font-size:.66rem; font-weight:850; text-transform:uppercase; letter-spacing:.12em; }}
      .metric-value {{ color:var(--ink); font-size:1.8rem; font-weight:850; margin-top:7px; letter-spacing:-.05em; }}
      .metric-note {{ color:var(--muted); font-size:.73rem; margin-top:3px; }}
      .risk-pill {{ display:inline-block; border-radius:999px; padding:5px 11px; font-size:.68rem; font-weight:850; letter-spacing:.08em; text-transform:uppercase; }}
      .risk-critical {{ color:#ffd8dc; background:#6b2432; border:1px solid #a94152; }}
      .risk-high {{ color:#ffe6ce; background:#673e23; border:1px solid #a66a37; }}
      .risk-medium {{ color:#fff0c4; background:#5b4b20; border:1px solid #9c843e; }}
      .risk-low {{ color:#c7f6ed; background:#174b48; border:1px solid #2c8278; }}
      .risk-info {{ color:#d4e2f4; background:#263b55; border:1px solid #46617f; }}
      .finding-card {{ border:1px solid var(--line); border-left:3px solid var(--accent); background:linear-gradient(145deg,var(--surface-2),var(--surface)); border-radius:13px; padding:16px 18px; margin:10px 0; box-shadow:0 7px 20px rgba(0,0,0,.05); }}
      .finding-critical {{ border-left-color:#ef6575; }} .finding-high {{ border-left-color:#f39a5b; }} .finding-medium {{ border-left-color:#e8c66b; }} .finding-low {{ border-left-color:#55c9a2; }}
      .finding-title {{ color:var(--ink); font-weight:850; font-size:1rem; margin:7px 0 5px; }}
      .finding-meta {{ color:var(--muted); font-size:.73rem; line-height:1.55; }}
      .muted {{ color:var(--muted); }}
      .mono {{ font-family:'Cascadia Code','Consolas','Courier New',monospace; font-size:.78rem; color:var(--accent); }}
      div[data-testid="stMetric"] {{ background:var(--surface-2); border:1px solid var(--line); padding:12px 15px; border-radius:13px; }}
      div[data-testid="stMetricLabel"] {{ color:var(--muted); }} div[data-testid="stMetricValue"] {{ color:var(--ink); }}
      .stButton>button, .stDownloadButton>button {{ border-radius:10px; border:1px solid var(--accent-strong); background:var(--accent); color:{palette['button_text']}!important; font-weight:850; min-height:2.65rem; letter-spacing:.01em; transition:all .16s ease; }}
      .stButton>button:hover, .stDownloadButton>button:hover {{ border-color:var(--accent); background:var(--accent-strong); color:#fff!important; transform:translateY(-1px); box-shadow:0 7px 16px rgba(0,0,0,.12); }}
      .stTextInput input, .stNumberInput input, .stSelectbox div[data-baseweb="select"], .stMultiSelect div[data-baseweb="select"], .stDateInput input {{ background:var(--surface-2)!important; border-color:var(--line)!important; color:var(--ink)!important; border-radius:9px!important; }}
      [data-baseweb="popover"] {{ background:var(--surface); border:1px solid var(--line); }}
      .stTabs [data-baseweb="tab-list"] {{ gap:7px; border-bottom:1px solid var(--line); }}
      .stTabs [data-baseweb="tab"] {{ background:var(--surface); color:var(--muted); border:1px solid var(--line); border-radius:9px 9px 0 0; padding:9px 16px; font-weight:750; }}
      .stTabs [aria-selected="true"] {{ background:var(--accent-soft)!important; color:var(--accent)!important; border-color:var(--accent)!important; }}
      .stButton>button {{ background:var(--surface-2); color:var(--ink)!important; border:1px solid var(--line); min-height:2.55rem; }}
      .stButton>button[kind="primary"] {{ background:var(--accent); color:{palette['button_text']}!important; border-color:var(--accent-strong); }}
      .stButton>button[kind="secondary"] {{ background:var(--surface-2); color:var(--muted)!important; border-color:var(--line); }}
      .stButton>button[kind="secondary"]:hover {{ background:var(--accent-soft); color:var(--accent)!important; border-color:var(--accent); }}
      .stDownloadButton>button {{ background:var(--accent); color:{palette['button_text']}!important; border-color:var(--accent-strong); }}
      .page-hero {{ border:1px solid var(--line); border-radius:18px; padding:23px 27px; margin-bottom:17px; background:linear-gradient(118deg,{palette['panel_glow']},var(--surface)); position:relative; overflow:hidden; }}
      .page-hero:after {{ content:''; position:absolute; right:-70px; top:-135px; width:330px; height:330px; border:1px solid var(--accent-soft); border-radius:50%; box-shadow:0 0 0 28px rgba(131,201,157,.025),0 0 0 58px rgba(131,201,157,.018); pointer-events:none; }}
      .page-hero-top {{ display:flex; align-items:center; justify-content:space-between; gap:14px; position:relative; z-index:1; }}
      .page-hero h1 {{ margin:.45rem 0 .35rem; font-size:1.85rem; line-height:1.12; position:relative; z-index:1; }}
      .page-hero p {{ color:var(--muted); margin:0; max-width:850px; line-height:1.55; position:relative; z-index:1; }}
      .session-chip {{ display:inline-flex; align-items:center; gap:7px; border:1px solid var(--line); background:var(--surface-2); border-radius:999px; padding:7px 11px; color:var(--muted); font-size:.64rem; font-weight:850; letter-spacing:.09em; white-space:nowrap; }}
      .nav-caption {{ color:var(--muted); text-transform:uppercase; letter-spacing:.16em; font-size:.62rem; font-weight:850; margin:12px 0 7px; }}
      .content-header {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin:18px 0 12px; }}
      .content-header h2 {{ margin:0; font-size:1.2rem; }}
      .content-header p {{ color:var(--muted); margin:3px 0 0; font-size:.78rem; }}
      .surface-card {{ border:1px solid var(--line); background:var(--surface); border-radius:15px; padding:17px 19px; }}
      .subtle-divider {{ height:1px; background:var(--line); margin:14px 0; }}
      .queue-row {{ border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:11px; padding:12px 13px; margin:8px 0; background:var(--surface-2); }}
      .queue-row.critical {{ border-left-color:#ef6575; }} .queue-row.high {{ border-left-color:#f39a5b; }} .queue-row.medium {{ border-left-color:#e8c66b; }} .queue-row.low {{ border-left-color:#55c9a2; }}
      .queue-id {{ font:700 .66rem 'Cascadia Code','Consolas',monospace; color:var(--accent); letter-spacing:.06em; }}
      .queue-title {{ color:var(--ink); font-size:.86rem; font-weight:800; margin:5px 0 4px; }}
      .queue-meta {{ color:var(--muted); font-size:.7rem; line-height:1.5; }}
      .detail-label {{ color:var(--muted); text-transform:uppercase; font-size:.62rem; font-weight:850; letter-spacing:.13em; margin:9px 0 4px; }}
      .detail-value {{ color:var(--ink); line-height:1.6; font-size:.88rem; }}
      .empty-state {{ border:1px dashed var(--border); border-radius:16px; background:var(--surface); padding:27px; text-align:center; }}
      .empty-state .empty-icon {{ color:var(--accent); font-size:1.8rem; margin-bottom:7px; }}
      .empty-state h3 {{ margin:.2rem 0 .45rem; }}
      .empty-state p {{ color:var(--muted); max-width:650px; margin:0 auto 13px; line-height:1.6; }}
      .stDataFrame {{ font-size:.8rem; }}
      [data-testid="stFileUploader"] section {{ background:var(--surface-2); border-radius:11px; }}
      [data-testid="stFileUploader"] {{ border:1px dashed var(--accent); border-radius:13px; background:var(--accent-soft); padding:12px; }}
      div[data-testid="stPlotlyChart"] {{
        border:1px solid var(--line); border-radius:13px; background:var(--surface);
        padding:7px 8px 4px; margin-top:8px; overflow:visible; min-width:0;
      }}
      [data-testid="stDataFrame"] {{
        --ag-foreground-color:var(--ink); --ag-background-color:var(--surface);
        --ag-header-background-color:var(--surface-2); --ag-odd-row-background-color:var(--surface);
        --ag-border-color:var(--line); --ag-row-hover-color:var(--accent-soft);
      }}
      div[data-testid="stCodeBlock"] {{ border:1px solid var(--line); border-radius:10px; }}
      [data-baseweb="menu"], [role="listbox"] {{ background:var(--surface)!important; color:var(--ink)!important; border:1px solid var(--line)!important; }}
      [role="option"] {{ color:var(--ink)!important; }}
      [data-testid="stExpander"] {{ border:1px solid var(--line); border-radius:12px; background:var(--surface); }}
      [data-testid="stDataFrame"], [data-testid="stTable"] {{ border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
      hr {{ border-color:var(--line); }} .small-note {{ color:var(--muted); font-size:.77rem; line-height:1.5; }}
      .stAlert {{ border-radius:11px; }}
      @media (max-width: 760px) {{ .hero-content {{ display:block; }} .hero-side {{ border-left:0; border-top:1px solid var(--line); margin-top:16px; padding:13px 0 0; }} .hero h1 {{ font-size:1.65rem; }} }}
    </style>
    """


def polish_chart(fig: Any, palette: dict[str, str], font_stack: str, **layout_updates: Any) -> None:
    """Apply the selected theme and reserve enough space for fully visible Plotly titles."""
    light = palette["bg"].startswith("#f")
    requested_title = layout_updates.pop("title", None)
    has_title = bool(requested_title)

    # Plotly draws titles inside the figure canvas. A 12px top margin clips the title
    # in Streamlit's chart container, so titled charts get a dedicated title band.
    default_margin = dict(l=22, r=18, t=62 if has_title else 18, b=28)
    supplied_margin = layout_updates.pop("margin", None)
    if isinstance(supplied_margin, dict):
        default_margin.update(supplied_margin)

    layout = {
        "template": "plotly" if light else "plotly_dark",
        "paper_bgcolor": "rgba(0,0,0,0)", "plot_bgcolor": "rgba(0,0,0,0)",
        "font": dict(family=font_stack, color=palette["text"], size=11),
        "margin": default_margin,
        "legend_title_text": "",
        "hoverlabel": dict(bgcolor=palette["surface_2"], bordercolor=palette["border"], font=dict(color=palette["text"], family=font_stack)),
        "xaxis": dict(gridcolor=palette["grid"], zerolinecolor=palette["grid"], linecolor=palette["border"], tickfont=dict(color=palette["muted"])),
        "yaxis": dict(gridcolor=palette["grid"], zerolinecolor=palette["grid"], linecolor=palette["border"], tickfont=dict(color=palette["muted"])),
    }

    if has_title:
        title_style = {
            "text": str(requested_title) if isinstance(requested_title, str) else "",
            "x": 0.025, "xanchor": "left", "y": 0.985, "yanchor": "top",
            "font": {"family": font_stack, "size": 14, "color": palette["text"]},
            "pad": {"b": 8},
        }
        if isinstance(requested_title, dict):
            title_style.update(requested_title)
            title_style["font"] = {**{"family": font_stack, "size": 14, "color": palette["text"]}, **requested_title.get("font", {})}
            title_style.setdefault("x", 0.025)
            title_style.setdefault("xanchor", "left")
            title_style.setdefault("y", 0.985)
            title_style.setdefault("yanchor", "top")
        layout["title"] = title_style
        # A slightly taller canvas prevents the reserved title band shrinking the plot too much.
        layout_updates["height"] = max(int(layout_updates.get("height", 320)), 320)

    for axis_name in ("xaxis", "yaxis"):
        if axis_name in layout_updates and isinstance(layout_updates[axis_name], dict):
            merged_axis = dict(layout.get(axis_name, {}))
            merged_axis.update(layout_updates[axis_name])
            layout_updates[axis_name] = merged_axis

    layout.update(layout_updates)
    fig.update_layout(**layout)



# -----------------------------------------------------------------------------
# Localization
# -----------------------------------------------------------------------------
TEXT = {
    "en": {
        "language": "Language", "english": "English", "spanish": "Español",
        "brand": "AEGIS / SECURITY OPERATIONS", "title": "SIEM Intelligence Workbench",
        "subtitle": "Turn raw security events into explainable findings, risk decisions, and an executive-ready technical report.",
        "upload_title": "01 / Import SIEM data", "upload_help": "Upload an Excel workbook (.xlsx or .xls). Data is processed in this session; this starter app does not send logs to an external analysis service.",
        "upload_label": "Choose SIEM Excel file", "select_sheet": "Worksheet", "mapping_title": "02 / Confirm column mapping",
        "mapping_help": "A best-effort mapping is suggested. Confirm the fields before running analysis. At minimum, map an event/message field for useful results.",
        "run": "Run security analysis", "ready": "Workbook loaded", "rows": "Events loaded", "columns": "Columns detected",
        "dashboard": "Dashboard", "findings": "Findings", "explorer": "Event explorer", "report": "Technical report",
        "overview": "Analysis overview", "risk_score": "Overall risk score", "risk_level": "Risk level", "events": "Events analyzed",
        "findings_count": "Findings generated", "critical_high": "Critical / High findings", "severity_dist": "Event severity distribution",
        "timeline": "Event volume over time", "top_sources": "Top source IPs", "categories": "Event categories",
        "filters": "Dashboard filters", "severity_filter": "Severity", "category_filter": "Category", "all": "All",
        "no_findings": "No detections were generated by the enabled rules. This does not prove the environment is safe; review coverage and source data quality.",
        "finding_evidence": "Evidence", "technical": "Technical explanation", "action": "Recommended action", "criticality": "Criticality",
        "affected": "Affected entities", "occurrences": "Occurrences", "first_seen": "First seen", "last_seen": "Last seen",
        "search": "Search events", "download_csv": "Download filtered events (CSV)", "no_data": "Upload a workbook to begin.",
        "report_title": "Technical Security Analysis Report", "generate_report": "Generate PDF report", "download_pdf": "Download PDF report",
        "scope": "Scope & methodology", "plan": "Plan of action", "priority": "Priority", "owner": "Suggested owner", "target": "Target timeframe",
        "p1": "P1 · Immediate", "p2": "P2 · High", "p3": "P3 · Planned", "p4": "P4 · Routine",
        "mapping_timestamp": "Timestamp", "mapping_src": "Source IP", "mapping_dst": "Destination IP", "mapping_user": "Username / Account",
        "mapping_id": "Event ID", "mapping_name": "Event name / Type", "mapping_severity": "Severity", "mapping_action": "Action / Result",
        "mapping_message": "Message / Raw event", "mapping_host": "Hostname / Asset", "mapping_process": "Process", "mapping_command": "Command line",
        "mapping_bytes": "Bytes sent / Outbound bytes", "mapping_country": "Country / Geo location", "not_mapped": "— Not mapped —",
        "threshold": "Detection tuning", "failed_threshold": "Failed logins per source/account", "scan_threshold": "Unique destinations for scan alert",
        "exfil_threshold": "Outbound transfer threshold (MB)", "high_severity": "Treat vendor High/Critical as findings", "time_note": "Timestamps are interpreted as UTC when timezone information is missing.",
        "quality": "Data quality notes", "missing_time": "No timestamp field was mapped; time-based charts and correlation rules are limited.",
        "missing_msg": "No message, event name, or event ID field was mapped. Detection coverage will be very limited.",
        "file_error": "Could not read this workbook. Check that it is a valid Excel file and try again.",
        "report_disclaimer": "This report is generated by transparent heuristic rules over the supplied log export. It is a triage aid, not a substitute for analyst validation, endpoint investigation, threat intelligence, or a full SIEM correlation pipeline.",
        "generated": "Generated", "source_file": "Source file", "summary": "Executive summary", "no_report": "Run an analysis to populate the report.",
        "events_sample": "Representative events", "classification": "Classification", "severity_unknown": "Unknown",
        "no_ip": "Not available", "rule_source": "Detection rule", "download_findings": "Download findings (CSV)",
        "appearance": "Appearance", "typeface": "Typeface", "font_segoe": "Segoe UI · clean", "font_georgia": "Georgia · editorial", "font_consolas": "Consolas · technical", "font_help": "Changes the font across the interface and charts: clean sans-serif, editorial serif, or technical monospace.",
        "workspace": "ANALYST WORKSPACE", "local_session": "LOCAL / SESSION BASED", "featureline": "XLSX INGESTION · RULE ENGINE<br>INTERACTIVE DASHBOARD · PDF REPORTING",
    },
    "es": {
        "language": "Idioma", "english": "English", "spanish": "Español",
        "brand": "AEGIS / OPERACIONES DE SEGURIDAD", "title": "Plataforma de Inteligencia SIEM",
        "subtitle": "Convierte eventos de seguridad sin procesar en hallazgos explicables, decisiones de riesgo e informes técnicos listos para presentar.",
        "upload_title": "01 / Importar datos SIEM", "upload_help": "Carga un libro de Excel (.xlsx o .xls). Los datos se procesan en esta sesión; esta versión inicial no envía registros a servicios externos de análisis.",
        "upload_label": "Seleccionar archivo Excel SIEM", "select_sheet": "Hoja", "mapping_title": "02 / Confirmar mapeo de columnas",
        "mapping_help": "Se sugiere un mapeo automático. Confirma los campos antes del análisis. Para obtener resultados útiles, asigna al menos un campo de evento o mensaje.",
        "run": "Ejecutar análisis de seguridad", "ready": "Libro cargado", "rows": "Eventos cargados", "columns": "Columnas detectadas",
        "dashboard": "Panel", "findings": "Hallazgos", "explorer": "Explorador de eventos", "report": "Informe técnico",
        "overview": "Resumen del análisis", "risk_score": "Puntuación de riesgo", "risk_level": "Nivel de riesgo", "events": "Eventos analizados",
        "findings_count": "Hallazgos generados", "critical_high": "Hallazgos críticos / altos", "severity_dist": "Distribución de severidad de eventos",
        "timeline": "Volumen de eventos en el tiempo", "top_sources": "Principales IP de origen", "categories": "Categorías de eventos",
        "filters": "Filtros del panel", "severity_filter": "Severidad", "category_filter": "Categoría", "all": "Todas",
        "no_findings": "Las reglas activas no generaron detecciones. Esto no demuestra que el entorno sea seguro; revisa la cobertura y la calidad de los datos.",
        "finding_evidence": "Evidencia", "technical": "Explicación técnica", "action": "Acción recomendada", "criticality": "Criticidad",
        "affected": "Entidades afectadas", "occurrences": "Ocurrencias", "first_seen": "Primera detección", "last_seen": "Última detección",
        "search": "Buscar eventos", "download_csv": "Descargar eventos filtrados (CSV)", "no_data": "Carga un libro para comenzar.",
        "report_title": "Informe Técnico de Análisis de Seguridad", "generate_report": "Generar informe PDF", "download_pdf": "Descargar informe PDF",
        "scope": "Alcance y metodología", "plan": "Plan de acción", "priority": "Prioridad", "owner": "Responsable sugerido", "target": "Plazo objetivo",
        "p1": "P1 · Inmediato", "p2": "P2 · Alto", "p3": "P3 · Planificado", "p4": "P4 · Rutinario",
        "mapping_timestamp": "Fecha y hora", "mapping_src": "IP de origen", "mapping_dst": "IP de destino", "mapping_user": "Usuario / Cuenta",
        "mapping_id": "ID de evento", "mapping_name": "Nombre / Tipo de evento", "mapping_severity": "Severidad", "mapping_action": "Acción / Resultado",
        "mapping_message": "Mensaje / Evento original", "mapping_host": "Nombre del equipo / Activo", "mapping_process": "Proceso", "mapping_command": "Línea de comandos",
        "mapping_bytes": "Bytes enviados / Salida", "mapping_country": "País / Ubicación geográfica", "not_mapped": "— Sin asignar —",
        "threshold": "Ajustes de detección", "failed_threshold": "Inicios de sesión fallidos por origen/cuenta", "scan_threshold": "Destinos únicos para alertar escaneo",
        "exfil_threshold": "Umbral de transferencia saliente (MB)", "high_severity": "Tratar severidad Alta/Crítica del proveedor como hallazgo", "time_note": "Las fechas sin zona horaria se interpretan como UTC.",
        "quality": "Notas sobre calidad de datos", "missing_time": "No se asignó un campo de fecha; los gráficos temporales y las correlaciones por tiempo serán limitados.",
        "missing_msg": "No se asignó mensaje, nombre de evento ni ID. La cobertura de detección será muy limitada.",
        "file_error": "No se pudo leer el libro. Verifica que sea un archivo Excel válido e inténtalo de nuevo.",
        "report_disclaimer": "Este informe se genera mediante reglas heurísticas transparentes aplicadas a la exportación de registros suministrada. Es una ayuda para triaje, no sustituye la validación del analista, la investigación de endpoints, la inteligencia de amenazas ni una plataforma SIEM completa.",
        "generated": "Generado", "source_file": "Archivo de origen", "summary": "Resumen ejecutivo", "no_report": "Ejecuta un análisis para generar el informe.",
        "events_sample": "Eventos representativos", "classification": "Clasificación", "severity_unknown": "Desconocida",
        "no_ip": "No disponible", "rule_source": "Regla de detección", "download_findings": "Descargar hallazgos (CSV)",
        "appearance": "Apariencia", "typeface": "Tipografía", "font_segoe": "Segoe UI · limpia", "font_georgia": "Georgia · editorial", "font_consolas": "Consolas · técnica", "font_help": "Cambia la tipografía de la interfaz y los gráficos: sans serif limpia, serif editorial o monoespaciada técnica.",
        "workspace": "ESPACIO DE ANÁLISIS", "local_session": "LOCAL / POR SESIÓN", "featureline": "IMPORTACIÓN XLSX · MOTOR DE REGLAS<br>PANEL INTERACTIVO · INFORMES PDF",
    },
}


def tr(key: str) -> str:
    return TEXT[st.session_state.get("language", "en")].get(key, key)


CANONICAL_FIELDS = [
    "timestamp", "source_ip", "destination_ip", "username", "event_id", "event_name",
    "severity", "action", "message", "host", "process", "command_line", "bytes_out", "country",
]

SEVERITY_ES = {
    "Critical": "Crítica", "High": "Alta", "Medium": "Media", "Low": "Baja",
    "Informational": "Informativa", "Unknown": "Desconocida", "None": "Ninguna",
}
CATEGORY_ES = {
    "Authentication failure": "Fallo de autenticación", "Authentication success": "Autenticación exitosa",
    "Privilege / account change": "Cambio de privilegios / cuenta", "Malware / threat": "Malware / amenaza",
    "Process execution": "Ejecución de procesos", "Network activity": "Actividad de red",
    "Account management": "Gestión de cuentas", "Policy / access event": "Política / control de acceso",
    "Other": "Otros",
}
TITLE_ES = {
    "Repeated authentication failures": "Intentos de autenticación fallidos repetidos",
    "Successful login after repeated failures": "Inicio de sesión exitoso después de varios fallos",
    "Encoded PowerShell command": "Comando PowerShell codificado",
    "PowerShell/script download cradle": "Descarga mediante PowerShell o script",
    "Living-off-the-land download utility": "Uso de utilidad del sistema para descargar contenido",
    "Potential LOLBin execution": "Posible ejecución de LOLBin",
    "Credential-dumping indicator": "Indicador de extracción de credenciales",
    "Shadow-copy or backup deletion command": "Comando para borrar copias sombra o respaldos",
    "Security event log cleared": "Registro de eventos de seguridad borrado",
    "Privileged access or group membership activity": "Actividad de acceso privilegiado o pertenencia a grupos",
    "High network destination fan-out": "Alto número de destinos de red",
    "Large outbound data transfer": "Transferencia saliente de gran volumen",
    "Vendor-classified high-severity events": "Eventos clasificados como Alta/Crítica por el SIEM",
}


def localized_severity(value: str, language: str) -> str:
    return SEVERITY_ES.get(value, value) if language == "es" else value


def localized_category(value: str, language: str) -> str:
    return CATEGORY_ES.get(value, value) if language == "es" else value


def finding_text(finding: dict[str, Any], field: str, language: str) -> str:
    if language != "es":
        return str(finding.get(field, ""))
    rule = finding.get("rule", "")
    count = int(finding.get("count", 0))
    affected = str(finding.get("affected", "entidad no disponible"))
    title = str(finding.get("title", ""))
    if field == "title":
        return TITLE_ES.get(title, title)
    if field == "description":
        templates = {
            "AUTH-BURST": f"Se observaron {count} eventos de autenticación fallida para {affected} dentro de una ventana de 10 minutos (o a lo largo de la exportación si no había fechas utilizables). Este patrón puede indicar password spraying o fuerza bruta.",
            "AUTH-SUCCESS-AFTER-FAIL": f"Un inicio de sesión exitoso ocurrió después de varios intentos fallidos en menos de 30 minutos para {affected}.",
            "EXEC-SUSPICIOUS": f"Se detectaron {count} evento(s) con un patrón de comando o proceso asociado frecuentemente con actividad posterior a la explotación o evasión de defensas.",
            "DEFENSE-EVASION-LOG-CLEAR": f"Se detectaron {count} evento(s) que indican que un registro de eventos o auditoría pudo haber sido borrado.",
            "IDENTITY-PRIVILEGE": f"Se observaron {count} evento(s) relacionados con derechos de inicio de sesión privilegiado o cambios en grupos privilegiados.",
            "NETWORK-FANOUT": f"El origen {affected} contactó {count} direcciones IP de destino distintas en el conjunto de datos suministrado.",
            "DATA-LARGE-EGRESS": f"Se detectaron {count} evento(s) con transferencias salientes iguales o superiores al umbral configurado.",
            "VENDOR-HIGH-SEVERITY": f"El SIEM de origen clasificó {count} evento(s) como Alta o Crítica; ninguna regla local más específica coincidió con esas filas.",
        }
        return templates.get(rule, str(finding.get(field, "")))
    if field == "explanation":
        templates = {
            "AUTH-BURST": "Una concentración de intentos de autenticación rechazados contra la misma cuenta u origen es una señal común de acceso mediante credenciales. También puede deberse a un servicio mal configurado o credenciales antiguas; valida el origen y el contexto operativo.",
            "AUTH-SUCCESS-AFTER-FAIL": "Un inicio de sesión exitoso después de varios fallos puede indicar que una contraseña fue adivinada u obtenida. Correlaciona el resultado de MFA, la identidad del dispositivo, la geolocalización y el comportamiento habitual del usuario antes de concluir que la cuenta fue comprometida.",
            "EXEC-SUSPICIOUS": "El comando detectado puede tener usos legítimos: administradores y herramientas de despliegue utilizan utilidades similares. El proceso padre, la firma, el usuario, el destino y la cadena de ejecución determinan si la actividad es maliciosa.",
            "DEFENSE-EVASION-LOG-CLEAR": "Borrar registros de seguridad puede ser un intento de debilitar la detección y eliminar evidencia. El evento 1102 de Windows Security es una señal especialmente relevante; otros productos utilizan identificadores y mensajes distintos.",
            "IDENTITY-PRIVILEGE": "El acceso administrativo suele ser esperado, pero una asignación inesperada de privilegios puede habilitar persistencia o ampliar el acceso. Esta regla señala la actividad para validación y no considera maliciosa toda acción administrativa.",
            "NETWORK-FANOUT": "Un equipo que contacta muchos destinos puede estar realizando descubrimiento, escaneo, evaluación de vulnerabilidades o inventario legítimo. El periodo de la exportación y la cobertura de eventos afectan la interpretación.",
            "DATA-LARGE-EGRESS": "Un gran volumen de salida puede corresponder a respaldos, sincronización, distribución de software o exfiltración. El volumen por sí solo no demuestra robo de datos; el destino, proceso, usuario y línea base son esenciales.",
            "VENDOR-HIGH-SEVERITY": "Se conserva la etiqueta de severidad del producto de origen como señal de triaje. Las escalas y significados varían entre fabricantes y deben interpretarse junto con el detalle original de la alerta.",
        }
        return templates.get(rule, str(finding.get(field, "")))
    if field == "recommendation":
        templates = {
            "AUTH-BURST": "Valida el equipo de origen y al propietario de la cuenta; busca patrones de password spraying en otras cuentas; aplica MFA y controles de bloqueo o limitación de intentos; bloquea o contiene el origen solo después de confirmar que no sea un servicio confiable.",
            "AUTH-SUCCESS-AFTER-FAIL": "Valida inmediatamente el inicio de sesión con el propietario de la cuenta; revisa MFA y la actividad de sesiones o tokens; revoca sesiones y rota credenciales si no fue autorizado; inspecciona el endpoint y los eventos de autenticación relacionados.",
            "EXEC-SUSPICIOUS": "Conserva el árbol de procesos y la línea de comandos completos; verifica la ruta, firma, proceso padre, usuario y destinos de red; aísla el endpoint si existe evidencia adicional de compromiso; busca el mismo hash o comando en el entorno.",
            "DEFENSE-EVASION-LOG-CLEAR": "Trata el evento como una investigación prioritaria: conserva copias centralizadas, identifica la cuenta y el equipo que iniciaron la acción, correlaciona los inicios privilegiados y la actividad previa, y verifica el reenvío y la retención de registros.",
            "IDENTITY-PRIVILEGE": "Confirma el cambio contra una solicitud aprobada; verifica el actor, la cuenta objetivo, el grupo y la hora; elimina la pertenencia no autorizada y revisa la actividad posterior de la cuenta afectada.",
            "NETWORK-FANOUT": "Compara el origen con escáneres aprobados y sistemas de inventario; inspecciona puertos de destino y resultados de conexión; revisa la telemetría entre procesos y red; restringe el tráfico si la actividad no está autorizada.",
            "DATA-LARGE-EGRESS": "Valida el destino y el propósito comercial; identifica el proceso y la clasificación de los datos; compara el volumen con las líneas base habituales; conserva evidencia de proxy, firewall y endpoint antes de bloquear.",
            "VENDOR-HIGH-SEVERITY": "Revisa el contexto de la alerta original, el nombre de la regla, el activo afectado y la guía del fabricante; enriquece con inteligencia de amenazas y correlaciona eventos cercanos antes de cerrar el caso.",
        }
        return templates.get(rule, str(finding.get(field, "")))
    return str(finding.get(field, ""))

FIELD_LABELS = {
    "timestamp": "mapping_timestamp", "source_ip": "mapping_src", "destination_ip": "mapping_dst",
    "username": "mapping_user", "event_id": "mapping_id", "event_name": "mapping_name",
    "severity": "mapping_severity", "action": "mapping_action", "message": "mapping_message",
    "host": "mapping_host", "process": "mapping_process", "command_line": "mapping_command",
    "bytes_out": "mapping_bytes", "country": "mapping_country",
}
ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "event time", "created", "@timestamp", "eventtime", "fecha", "hora"],
    "source_ip": ["source ip", "src ip", "src_ip", "source_address", "client ip", "src", "ip origen", "ip de origen"],
    "destination_ip": ["destination ip", "dest ip", "dst_ip", "destination_address", "dest", "dst", "ip destino"],
    "username": ["username", "user", "account", "principal", "user_name", "target user", "usuario", "cuenta"],
    "event_id": ["event id", "eventid", "event_code", "signature id", "id", "codigo evento"],
    "event_name": ["event name", "event type", "eventtype", "category", "signature", "rule name", "nombre evento", "tipo evento"],
    "severity": ["severity", "level", "priority", "risk", "alert severity", "severidad", "nivel"],
    "action": ["action", "result", "status", "outcome", "disposition", "accion", "resultado", "estado"],
    "message": ["message", "description", "details", "raw log", "log", "event", "msg", "mensaje", "descripcion"],
    "host": ["hostname", "host", "computer", "asset", "device", "endpoint", "equipo", "activo"],
    "process": ["process", "process name", "image", "executable", "proceso"],
    "command_line": ["command line", "commandline", "cmdline", "process command line", "command", "comando"],
    "bytes_out": ["bytes sent", "bytes_out", "outbound bytes", "uploaded bytes", "sent_bytes", "bytes tx", "bytes enviados"],
    "country": ["country", "geo country", "source country", "country_name", "pais"],
}


# -----------------------------------------------------------------------------
# Data normalization and detection rules
# -----------------------------------------------------------------------------
def normalize_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def suggest_mapping(columns: list[str]) -> dict[str, str | None]:
    normalized = {col: normalize_name(col) for col in columns}
    mapping: dict[str, str | None] = {}
    for field, aliases in ALIASES.items():
        alias_set = {normalize_name(a) for a in aliases}
        chosen = None
        for col, norm in normalized.items():
            if norm in alias_set:
                chosen = col
                break
        if chosen is None:
            for col, norm in normalized.items():
                if any(a and (a in norm or norm in a) for a in alias_set if len(a) >= 5):
                    chosen = col
                    break
        mapping[field] = chosen
    return mapping


def _series_or_default(df: pd.DataFrame, col: str | None, default: Any = "") -> pd.Series:
    if col and col in df.columns:
        return df[col]
    return pd.Series([default] * len(df), index=df.index)


def normalize_logs(raw: pd.DataFrame, mapping: dict[str, str | None]) -> pd.DataFrame:
    out = pd.DataFrame(index=raw.index)
    for field in CANONICAL_FIELDS:
        out[field] = _series_or_default(raw, mapping.get(field))
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    for col in ["source_ip", "destination_ip", "username", "event_id", "event_name", "severity", "action", "message", "host", "process", "command_line", "country"]:
        out[col] = out[col].fillna("").astype(str).str.strip()
    out["bytes_out"] = pd.to_numeric(out["bytes_out"], errors="coerce").fillna(0)
    out["event_text"] = (
        out["event_id"] + " " + out["event_name"] + " " + out["message"] + " " + out["process"] + " " + out["command_line"]
    ).str.lower()
    out["normalized_severity"] = out["severity"].map(normalize_severity)
    out["category"] = out.apply(classify_event, axis=1)
    out["event_index"] = range(len(out))
    return out.reset_index(drop=True)


def normalize_severity(value: Any) -> str:
    s = str(value).strip().lower()
    if not s:
        return "Unknown"
    if re.fullmatch(r"\d+(\.\d+)?", s):
        n = float(s)
        # Common vendor scales: 0-10 and 0-100.
        if n >= 80 or (n <= 10 and n >= 8): return "Critical"
        if n >= 60 or (n <= 10 and n >= 6): return "High"
        if n >= 30 or (n <= 10 and n >= 3): return "Medium"
        return "Low"
    if any(x in s for x in ["critical", "emergency", "alert", "fatal"]): return "Critical"
    if any(x in s for x in ["high", "severe", "error"]): return "High"
    if any(x in s for x in ["medium", "moderate", "warning", "warn"]): return "Medium"
    if any(x in s for x in ["low", "informational", "info", "notice", "debug"]): return "Low"
    return "Unknown"


def classify_event(row: pd.Series) -> str:
    text = str(row.get("event_text", ""))
    eid = str(row.get("event_id", "")).strip()
    action = str(row.get("action", "")).lower()
    if eid == "4625" or any(x in text for x in ["failed logon", "failed login", "authentication failure", "login failed", "invalid password", "logon failure"]):
        return "Authentication failure"
    if eid == "4624" or any(x in text for x in ["successful logon", "successful login", "login success", "authentication success"]):
        return "Authentication success"
    if eid in {"4672", "4728", "4732", "4756"} or any(x in text for x in ["privilege assigned", "privileged group", "added to administrators", "admin group", "special privileges"]):
        return "Privilege / account change"
    if any(x in text for x in ["malware", "ransomware", "trojan", "mimikatz", "cobalt strike", "malicious file", "quarantined"]):
        return "Malware / threat"
    if any(x in text for x in ["powershell", "cmd.exe", "wscript", "cscript", "process created", "process creation"]):
        return "Process execution"
    if any(x in text for x in ["firewall", "network connection", "dns query", "connection allowed", "connection blocked", "port scan", "bytes sent"]):
        return "Network activity"
    if any(x in text for x in ["account created", "user created", "password reset", "account locked", "user disabled"]):
        return "Account management"
    if any(x in action for x in ["fail", "denied", "blocked"]):
        return "Policy / access event"
    return "Other"


def _event_evidence(df: pd.DataFrame, indices: list[int], limit: int = 5) -> list[str]:
    evidence = []
    for _, row in df.loc[indices].head(limit).iterrows():
        parts = []
        ts = row["timestamp"]
        if pd.notna(ts): parts.append(ts.strftime("%Y-%m-%d %H:%M:%S UTC"))
        if row["source_ip"]: parts.append(f"src={row['source_ip']}")
        if row["username"]: parts.append(f"user={row['username']}")
        if row["event_id"]: parts.append(f"event_id={row['event_id']}")
        label = row["event_name"] or row["message"] or row["event_text"][:140]
        if label: parts.append(str(label)[:180])
        evidence.append(" | ".join(parts) if parts else f"Event row {int(row['event_index']) + 1}")
    return evidence


def analyze_logs(
    logs: pd.DataFrame,
    failed_threshold: int = 8,
    scan_threshold: int = 20,
    exfil_mb: int = 100,
    include_vendor_severity: bool = True,
) -> tuple[list[dict[str, Any]], pd.DataFrame, int, str]:
    findings: list[dict[str, Any]] = []
    enriched = logs.copy()
    enriched["finding_ids"] = ""

    def add_finding(
        rule: str, title: str, severity: str, description: str, explanation: str,
        recommendation: str, indices: list[int], affected: str = "", count: int | None = None,
    ) -> None:
        indices = sorted(set(int(i) for i in indices if 0 <= int(i) < len(enriched)))
        if not indices:
            return
        subset = enriched.loc[indices]
        times = subset["timestamp"].dropna()
        source_vals = sorted(set(x for x in subset["source_ip"].astype(str) if x))
        user_vals = sorted(set(x for x in subset["username"].astype(str) if x))
        severity_points = {"Critical": 30, "High": 22, "Medium": 13, "Low": 6}.get(severity, 4)
        volume_factor = min(1.7, 1 + math.log10(max(1, count or len(indices))) * 0.18)
        finding_id = f"F-{len(findings) + 1:03d}"
        mitre_alignment = map_finding(
            rule=rule,
            title=title,
            event_texts=subset["event_text"].astype(str).tolist() if "event_text" in subset else [],
            event_ids=subset["event_id"].astype(str).tolist() if "event_id" in subset else [],
        )
        findings.append({
            "id": finding_id, "rule": rule, "title": title, "severity": severity,
            "description": description, "explanation": explanation, "recommendation": recommendation,
            "evidence": _event_evidence(enriched, indices), "indices": indices,
            "count": int(count if count is not None else len(indices)), "affected": affected or ", ".join((source_vals[:3] + user_vals[:3])) or "Not available",
            "sources": source_vals, "users": user_vals,
            "first_seen": times.min() if len(times) else pd.NaT,
            "last_seen": times.max() if len(times) else pd.NaT,
            "score_weight": severity_points * volume_factor,
            "mitre": mitre_alignment["techniques"],
            "mitre_note": mitre_alignment["note"],
            "mitre_note_es": mitre_alignment["note_es"],
            "mitre_assessment": mitre_alignment["assessment"],
            "mitre_assessment_es": mitre_alignment["assessment_es"],
        })
        for i in indices:
            existing = enriched.at[i, "finding_ids"]
            enriched.at[i, "finding_ids"] = f"{existing}, {finding_id}".strip(", ")

    # Rule 1: brute-force-like authentication burst by source and account.
    failed = enriched[enriched["category"] == "Authentication failure"]
    if len(failed):
        group_cols = [c for c in ["source_ip", "username"] if failed[c].astype(str).str.len().gt(0).any()]
        if group_cols:
            for key, group in failed.groupby(group_cols, dropna=False):
                group = group.sort_values("timestamp")
                indices = group.index.tolist()
                burst_indices: list[int] = []
                valid_times = group[group["timestamp"].notna()].sort_values("timestamp")
                if len(valid_times):
                    event_times = valid_times["timestamp"]
                    for event_time in event_times:
                        window = valid_times[(valid_times["timestamp"] >= event_time - pd.Timedelta(minutes=10)) & (valid_times["timestamp"] <= event_time)]
                        if len(window) >= failed_threshold:
                            burst_indices = window.index.tolist()
                            break
                elif len(indices) >= failed_threshold:
                    # With no usable timestamps, retain a count-based signal but make the limitation explicit in the evidence.
                    burst_indices = indices
                if burst_indices:
                    label = " / ".join(str(x) for x in (key if isinstance(key, tuple) else (key,)) if x)
                    add_finding(
                        "AUTH-BURST", "Repeated authentication failures", "High",
                        f"Observed {len(burst_indices)} failed authentication events for {label or 'an account/source'} within a 10-minute window (or across the export when timestamps were unavailable). This pattern can indicate password spraying or brute-force activity.",
                        "A concentrated burst of rejected authentication attempts against the same account and/or source is a common credential-access signal. It may also be caused by a misconfigured service or stale credentials, so validate the source and business context.",
                        "Validate the source host and account owner; check for password-spray patterns across other accounts; enforce MFA and lockout/rate-limiting controls; block or contain the source only after confirming it is not a trusted service.",
                        burst_indices, affected=label, count=len(burst_indices),
                    )

    # Rule 2: successful login from the same source/account after failures.
    if len(failed) and logs["timestamp"].notna().any():
        successes = enriched[enriched["category"] == "Authentication success"]
        for _, success in successes.iterrows():
            if pd.isna(success["timestamp"]):
                continue
            candidates = failed
            if success["source_ip"]:
                candidates = candidates[candidates["source_ip"] == success["source_ip"]]
            if success["username"]:
                candidates = candidates[candidates["username"] == success["username"]]
            candidates = candidates[candidates["timestamp"].notna()]
            delta = success["timestamp"] - candidates["timestamp"]
            related = candidates[(delta >= pd.Timedelta(0)) & (delta <= pd.Timedelta(minutes=30))]
            if len(related) >= 3:
                idx = related.index.tolist() + [int(success.name)]
                add_finding(
                    "AUTH-SUCCESS-AFTER-FAIL", "Successful login after repeated failures", "Critical",
                    f"A successful authentication followed {len(related)} failed attempts within 30 minutes for {success['username'] or 'an account'} from {success['source_ip'] or 'a source not mapped'}.",
                    "A successful sign-in after repeated failures can indicate that a password was guessed or obtained. Correlate with MFA outcome, device identity, geolocation, and the user's normal behavior before concluding account compromise.",
                    "Immediately validate the sign-in with the account owner; review MFA and session/token activity; revoke active sessions and rotate credentials when unauthorized; inspect the endpoint and related authentication events.",
                    idx, affected=f"{success['username']} / {success['source_ip']}", count=len(idx),
                )
                break

    # Rule 3: suspicious command-line and LOLBin patterns.
    command_patterns = [
        (r"-enc(?:odedcommand)?\b|frombase64string", "Encoded PowerShell command"),
        (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\b", "PowerShell/script download cradle"),
        (r"certutil\s+.*-urlcache|bitsadmin\s+.*\/transfer", "Living-off-the-land download utility"),
        (r"\b(?:mshta|regsvr32|rundll32|wscript|cscript)\.exe\b", "Potential LOLBin execution"),
        (r"mimikatz|sekurlsa|lsass\.exe", "Credential-dumping indicator"),
        (r"vssadmin\s+.*delete\s+shadows|wbadmin\s+delete\s+catalog", "Shadow-copy or backup deletion command"),
    ]
    for pattern, label in command_patterns:
        mask = enriched["event_text"].str.contains(pattern, regex=True, na=False)
        indices = enriched.index[mask].tolist()
        if indices:
            severity = "Critical" if "Credential" in label or "Shadow-copy" in label else "High"
            add_finding(
                "EXEC-SUSPICIOUS", label, severity,
                f"Matched {len(indices)} event(s) containing a command or process pattern commonly associated with post-exploitation or defense evasion.",
                "The matched command is dual-use: administrators and software deployment tools may use similar utilities. The context, parent process, signer, user, destination, and execution chain determine whether it is malicious.",
                "Preserve the full process tree and command line; verify binary path, signer, parent process, user, and network destinations; isolate the endpoint if corroborating evidence indicates compromise; hunt for the same hash or command across the estate.",
                indices, count=len(indices),
            )

    # Rule 4: event log clearing.
    clear_mask = enriched["event_text"].str.contains(r"(?:1102|104).*log.*clear|audit log cleared|event log was cleared|cleared the security log", regex=True, na=False)
    clear_indices = enriched.index[clear_mask].tolist()
    if clear_indices:
        add_finding(
            "DEFENSE-EVASION-LOG-CLEAR", "Security event log cleared", "Critical",
            f"Detected {len(clear_indices)} event(s) indicating that an event or audit log may have been cleared.",
            "Clearing security logs can be an attempt to impair detection and remove evidence. Windows Security Event ID 1102 is a particularly relevant signal; other products use different identifiers and messages.",
            "Treat as a priority investigation: preserve centralized copies, identify the initiating account and host, correlate with privileged logons and preceding activity, and verify log forwarding and retention controls.",
            clear_indices,
        )

    # Rule 5: privileged access or security group changes.
    priv_mask = enriched.apply(
        lambda r: str(r["event_id"]).strip() in {"4672", "4728", "4732", "4756"} or any(
            t in str(r["event_text"]) for t in ["added to administrators", "added to privileged", "privileged group membership", "special privileges assigned"]
        ), axis=1,
    )
    priv_indices = enriched.index[priv_mask].tolist()
    if priv_indices:
        add_finding(
            "IDENTITY-PRIVILEGE", "Privileged access or group membership activity", "Medium",
            f"Observed {len(priv_indices)} event(s) related to privileged logon rights or privileged group membership changes.",
            "Administrative access is expected in many environments, but unexpected privilege assignment can enable persistence or broader access. This rule flags the activity for validation rather than treating every administrator action as malicious.",
            "Confirm the change against an approved ticket; verify the actor, target account, group, and time; remove unauthorized membership and review subsequent activity by the affected account.",
            priv_indices,
        )

    # Rule 6: network fan-out / possible scanning.
    if enriched["source_ip"].astype(str).str.len().gt(0).any() and enriched["destination_ip"].astype(str).str.len().gt(0).any():
        net = enriched[enriched["destination_ip"].astype(str).str.len().gt(0)]
        for src, group in net.groupby("source_ip"):
            if not src:
                continue
            unique_dests = group["destination_ip"].nunique()
            if unique_dests >= scan_threshold:
                add_finding(
                    "NETWORK-FANOUT", "High network destination fan-out", "High",
                    f"Source {src} contacted {unique_dests} distinct destination IPs in the supplied dataset.",
                    "A host contacting many unique destinations may be performing discovery, scanning, vulnerability assessment, or legitimate inventory/monitoring. The export's time span and event coverage affect interpretation.",
                    "Compare the source with approved scanners and asset-management systems; inspect destination ports and connection outcomes; review process-to-network telemetry and restrict traffic if activity is unauthorized.",
                    group.index.tolist(), affected=str(src), count=int(unique_dests),
                )

    # Rule 7: large outbound transfer.
    transfer_mask = enriched["bytes_out"] >= exfil_mb * 1024 * 1024
    transfer_indices = enriched.index[transfer_mask].tolist()
    if transfer_indices:
        add_finding(
            "DATA-LARGE-EGRESS", "Large outbound data transfer", "High",
            f"Detected {len(transfer_indices)} event(s) with outbound transfer values at or above {exfil_mb} MB.",
            "Large egress volume can be consistent with backups, synchronization, software distribution, or data exfiltration. Volume alone is not proof of data theft; destination, process, user, and baseline are essential.",
            "Validate the destination and business purpose; identify the process and data classification; compare the volume with normal baselines; preserve proxy, firewall, and endpoint evidence before blocking.",
            transfer_indices,
        )

    # Rule 8: vendor-labeled High/Critical events.
    if include_vendor_severity:
        vendor_mask = enriched["normalized_severity"].isin(["Critical", "High"])
        vendor_indices = enriched.index[vendor_mask].tolist()
        if vendor_indices:
            # Avoid duplicating all the same rows when they already have another detection.
            uncovered = [i for i in vendor_indices if not enriched.at[i, "finding_ids"]]
            if uncovered:
                sev = "Critical" if (enriched.loc[uncovered, "normalized_severity"] == "Critical").any() else "High"
                add_finding(
                    "VENDOR-HIGH-SEVERITY", "Vendor-classified high-severity events", sev,
                    f"The source SIEM classified {len(uncovered)} event(s) as High or Critical; no more specific local rule matched these rows.",
                    "The originating product's severity label is retained as a triage signal. Severity scales and semantics vary by vendor and should be interpreted alongside the original alert details.",
                    "Review the original alert context, rule name, affected asset, and vendor guidance; enrich with threat intelligence and correlate with adjacent events before closing.",
                    uncovered,
                )

    # Attach the most severe finding to each row for filtering / exploration.
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    row_sev: dict[int, str] = {}
    for finding in findings:
        for i in finding["indices"]:
            if severity_rank.get(finding["severity"], 0) > severity_rank.get(row_sev.get(i, ""), 0):
                row_sev[i] = finding["severity"]
    enriched["detection_severity"] = [row_sev.get(i, "None") for i in enriched.index]

    raw_score = sum(f["score_weight"] for f in findings)
    risk_score = min(100, int(round(raw_score)))
    if risk_score >= 75: risk_level = "Critical"
    elif risk_score >= 50: risk_level = "High"
    elif risk_score >= 25: risk_level = "Medium"
    elif risk_score > 0: risk_level = "Low"
    else: risk_level = "Informational"
    return findings, enriched, risk_score, risk_level


# -----------------------------------------------------------------------------
# PDF report generation
# -----------------------------------------------------------------------------
def make_pdf_report(
    findings: list[dict[str, Any]], logs: pd.DataFrame, score: int, level: str,
    source_name: str, language: str, metadata: dict[str, Any] | None = None,
) -> bytes:
    """Build a structured, multi-section analyst report with traceable evidence."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    from xml.sax.saxutils import escape

    metadata = metadata or {}
    t = TEXT[language]
    is_es = language == "es"
    buf = BytesIO()
    generated = datetime.now(timezone.utc)
    report_seed = f"{source_name}|{generated.isoformat()}|{score}|{len(findings)}"
    report_id = f"AEGIS-{generated.strftime('%Y%m%d-%H%M')}-{hashlib.sha1(report_seed.encode('utf-8')).hexdigest()[:6].upper()}"
    page_width, page_height = A4
    left_margin = right_margin = 17 * mm
    doc = SimpleDocTemplate(
        buf, pagesize=A4, rightMargin=right_margin, leftMargin=left_margin,
        topMargin=22 * mm, bottomMargin=20 * mm,
        title="Aegis SIEM Technical Security Analysis Report",
        author="Aegis SIEM",
        subject="Heuristic SIEM log analysis with evidence and candidate MITRE ATT&CK alignment",
    )

    ink = colors.HexColor("#172820")
    jade = colors.HexColor("#277553")
    jade_light = colors.HexColor("#EAF3ED")
    muted = colors.HexColor("#627268")
    line = colors.HexColor("#D5DED8")
    pale = colors.HexColor("#F4F7F4")
    navy = colors.HexColor("#20372B")
    severity_colors = {
        "Critical": colors.HexColor("#A72E43"),
        "High": colors.HexColor("#B45E28"),
        "Medium": colors.HexColor("#98781D"),
        "Low": colors.HexColor("#26765B"),
        "Informational": colors.HexColor("#48627D"),
    }

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="AegisKicker", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=7.5, leading=9, textColor=jade, spaceAfter=4, tracking=1.25))
    styles.add(ParagraphStyle(name="AegisTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=21, leading=25, textColor=ink, alignment=TA_LEFT, spaceAfter=4))
    styles.add(ParagraphStyle(name="AegisMeta", parent=styles["Normal"], fontName="Helvetica", fontSize=7.2, leading=9.5, textColor=muted, spaceAfter=4))
    styles.add(ParagraphStyle(name="AegisH1", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=ink, spaceBefore=10, spaceAfter=4, keepWithNext=1))
    styles.add(ParagraphStyle(name="AegisH2", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=jade, spaceBefore=6, spaceAfter=2.5, keepWithNext=1))
    styles.add(ParagraphStyle(name="AegisBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.9, leading=10.5, textColor=colors.HexColor("#34443A"), spaceAfter=3))
    styles.add(ParagraphStyle(name="AegisSmall", parent=styles["BodyText"], fontName="Helvetica", fontSize=7, leading=9, textColor=muted, spaceAfter=2))
    styles.add(ParagraphStyle(name="AegisTiny", parent=styles["BodyText"], fontName="Helvetica", fontSize=6.4, leading=8, textColor=muted, spaceAfter=1))
    styles.add(ParagraphStyle(name="AegisEvidence", parent=styles["BodyText"], fontName="Courier", fontSize=6.6, leading=8.5, textColor=colors.HexColor("#31473A"), leftIndent=7, spaceAfter=2, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="AegisCardLabel", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=6.7, leading=8, textColor=muted, spaceAfter=0))
    styles.add(ParagraphStyle(name="AegisCardValue", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=16, leading=18, textColor=ink, spaceAfter=0))
    styles.add(ParagraphStyle(name="AegisTableHead", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=6.7, leading=8, textColor=colors.white, spaceAfter=0))
    styles.add(ParagraphStyle(name="AegisTableCell", parent=styles["BodyText"], fontName="Helvetica", fontSize=6.6, leading=8.3, textColor=colors.HexColor("#34443A"), spaceAfter=0, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="AegisTableCellBold", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=6.6, leading=8.3, textColor=ink, spaceAfter=0))

    def P(text: Any, style: str = "AegisBody") -> Paragraph:
        return Paragraph(escape(str(text)).replace("\n", "<br/>") , styles[style])

    def cell(text: Any, bold: bool = False) -> Paragraph:
        return P(text, "AegisTableCellBold" if bold else "AegisTableCell")

    def head(text: Any) -> Paragraph:
        return P(text, "AegisTableHead")

    def make_table(data: list[list[Any]], widths: list[float], header: bool = True, font_size: float = 6.6) -> Table:
        table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        commands = [
            ("GRID", (0, 0), (-1, -1), 0.35, line),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.8),
        ]
        if header:
            commands += [
                ("BACKGROUND", (0, 0), (-1, 0), navy),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pale]),
            ]
        else:
            commands += [("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, pale])]
        table.setStyle(TableStyle(commands))
        return table

    story: list[Any] = []
    story.append(Paragraph("AEGIS / SECURITY OPERATIONS", styles["AegisKicker"]))
    story.append(Paragraph(escape(t["report_title"]), styles["AegisTitle"]))
    story.append(P(f"{t['generated']}: {generated.strftime('%Y-%m-%d %H:%M:%S UTC')}  |  Report ID: {report_id}", "AegisMeta"))
    story.append(P(f"{t['source_file']}: {source_name}  |  Worksheet: {metadata.get('sheet', 'Not recorded')}", "AegisMeta"))

    # High-level KPI strip.
    card_labels = [t["risk_score"], t["risk_level"], t["events"], t["findings_count"]]
    card_values = [f"{score}/100", localized_severity(level, language), f"{len(logs):,}", f"{len(findings):,}"]
    card_data = [
        [P(label, "AegisCardLabel") for label in card_labels],
        [P(value, "AegisCardValue") for value in card_values],
    ]
    card = Table(card_data, colWidths=[44*mm] * 4)
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), jade_light),
        ("BOX", (0, 0), (-1, -1), 0.7, line),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, line),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, 0), 7), ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("TOPPADDING", (0, 1), (-1, 1), 1), ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
        ("TEXTCOLOR", (1, 1), (1, 1), severity_colors.get(level, ink)),
    ]))
    story.extend([Spacer(1, 5), card])

    critical_high = sum(1 for f in findings if f.get("severity") in {"Critical", "High"})
    mapped_findings = sum(1 for f in findings if f.get("mitre"))
    if is_es:
        executive = (f"El análisis revisó {len(logs):,} eventos y generó {len(findings):,} hallazgos, incluidos "
                     f"{critical_high:,} de severidad Alta/Crítica. La clasificación agregada es {localized_severity(level, language)} "
                     f"con una puntuación heurística de {score}/100. {mapped_findings} hallazgos tienen una alineación ATT&CK candidata.")
        scope = ("La hoja seleccionada se normalizó mediante el mapeo de columnas confirmado por el analista. "
                 "El motor aplicó reglas locales para ráfagas de autenticación, inicios exitosos posteriores a fallos, patrones de comandos/procesos, "
                 "borrado de registros, cambios de privilegios, múltiples destinos de red, grandes transferencias salientes y severidad del proveedor. "
                 "Las detecciones son señales heurísticas para triaje y deben validarse con telemetría adicional.")
    else:
        executive = (f"The analysis reviewed {len(logs):,} events and generated {len(findings):,} findings, including "
                     f"{critical_high:,} High/Critical findings. The aggregate classification is {localized_severity(level, language)} "
                     f"with a heuristic score of {score}/100. {mapped_findings} findings have a candidate ATT&CK alignment.")
        scope = ("The selected worksheet was normalized through analyst-confirmed column mapping. The local engine reviewed authentication bursts, "
                 "successful logons after failures, suspicious command/process patterns, log clearing, privilege changes, network destination fan-out, "
                 "large outbound transfers, and vendor severity labels. Detections are heuristic triage signals and require validation using additional telemetry.")
    story.append(P(t["summary"], "AegisH1"))
    story.append(P(executive))
    story.append(P(t["scope"], "AegisH1"))
    story.append(P(scope))

    # Data time span and severity distribution.
    story.append(P("Dataset overview" if not is_es else "Resumen del conjunto de datos", "AegisH2"))
    valid_times = logs["timestamp"].dropna() if "timestamp" in logs else pd.Series(dtype="datetime64[ns, UTC]")
    if len(valid_times):
        time_span = f"{valid_times.min().strftime('%Y-%m-%d %H:%M UTC')} to {valid_times.max().strftime('%Y-%m-%d %H:%M UTC')}"
    else:
        time_span = "No usable timestamp mapped" if not is_es else "No se asignó una fecha utilizable"
    story.append(P(f"{('Observed time range' if not is_es else 'Rango temporal observado')}: {time_span}.  "
                   f"{('Worksheet rows' if not is_es else 'Filas de la hoja')}: {len(logs):,}.  "
                   f"{('Findings with ATT&CK candidates' if not is_es else 'Hallazgos con candidatos ATT&CK')}: {mapped_findings:,}.", "AegisSmall"))

    sev_col = "normalized_severity" if "normalized_severity" in logs.columns else "severity"
    sev_counts = logs[sev_col].fillna("Unknown").astype(str).value_counts().to_dict() if sev_col in logs else {}
    sev_order = ["Critical", "High", "Medium", "Low", "Unknown"]
    severity_rows = [[head("Severity" if not is_es else "Severidad"), head("Events" if not is_es else "Eventos"), head("Share" if not is_es else "Proporción")]]
    for sev in sev_order:
        n = int(sev_counts.get(sev, 0))
        if n:
            severity_rows.append([cell(localized_severity(sev, language)), cell(f"{n:,}"), cell(f"{n / max(1, len(logs)):.1%}")])
    if len(severity_rows) == 1:
        severity_rows.append([cell("No severity values" if not is_es else "Sin datos de severidad"), cell("0"), cell("0%")])
    story.append(make_table(severity_rows, [65*mm, 45*mm, 66*mm]))

    # Explain source-field coverage and the mapping that was applied.
    story.append(P("Field coverage & source mapping" if not is_es else "Cobertura de campos y mapeo de origen", "AegisH2"))
    field_labels = {
        "timestamp": "Timestamp / Fecha", "source_ip": "Source IP / IP origen", "destination_ip": "Destination IP / IP destino",
        "username": "Username / Usuario", "event_id": "Event ID", "event_name": "Event name / Tipo",
        "severity": "Severity / Severidad", "host": "Host / Activo", "process": "Process / Proceso",
        "command_line": "Command line / Comando", "bytes_out": "Outbound bytes / Bytes salida",
    }
    mapping = metadata.get("mapping", {}) or {}
    coverage_rows = [[head("Canonical field" if not is_es else "Campo estándar"), head("Source column" if not is_es else "Columna origen"), head("Records" if not is_es else "Registros"), head("Coverage" if not is_es else "Cobertura")]]
    for field, label in field_labels.items():
        if field not in logs.columns:
            continue
        series = logs[field]
        if field == "timestamp":
            populated = int(series.notna().sum())
        elif field == "bytes_out":
            populated = int((pd.to_numeric(series, errors="coerce").fillna(0) > 0).sum())
        else:
            populated = int(series.fillna("").astype(str).str.strip().ne("").sum())
        coverage_rows.append([cell(label), cell(mapping.get(field) or ("Not mapped" if not is_es else "Sin asignar")), cell(f"{populated:,}/{len(logs):,}"), cell(f"{populated / max(1, len(logs)):.1%}")])
    story.append(make_table(coverage_rows, [48*mm, 62*mm, 34*mm, 32*mm]))

    # Findings with each item separated so the story can flow cleanly across pages.
    story.append(P(t["findings"], "AegisH1"))
    if not findings:
        story.append(P(TEXT[language]["no_findings"]))
    severity_priority = {
        "Critical": ("P1", "Security Operations / Incident Response", "Immediate" if not is_es else "Inmediato"),
        "High": ("P2", "SOC / IT Operations", "24-48 hours" if not is_es else "24-48 horas"),
        "Medium": ("P3", "Identity / System Owner", "5 business days" if not is_es else "5 días hábiles"),
        "Low": ("P4", "Control Owner", "Next review cycle" if not is_es else "Próximo ciclo de revisión"),
    }
    for f in findings:
        sev = f.get("severity", "Unknown")
        sev_color = severity_colors.get(sev, muted).hexval()
        title_text = finding_text(f, "title", language)
        first_seen = f["first_seen"].strftime("%Y-%m-%d %H:%M UTC") if pd.notna(f.get("first_seen", pd.NaT)) else "—"
        last_seen = f["last_seen"].strftime("%Y-%m-%d %H:%M UTC") if pd.notna(f.get("last_seen", pd.NaT)) else "—"
        story.append(KeepTogether([
            Paragraph(f"<font color='{jade.hexval()}'><b>{escape(str(f.get('id', '')))} / {escape(str(f.get('rule', '')))}</b></font>", styles["AegisSmall"]),
            Paragraph(f"{escape(title_text)} <font color='{sev_color}'><b>[{escape(localized_severity(sev, language))}]</b></font>", styles["AegisH2"]),
            P(f"{t['criticality']}: {localized_severity(sev, language)}  |  {t['occurrences']}: {f.get('count', 0):,}  |  {t['affected']}: {str(f.get('affected', 'Not available'))[:220]}", "AegisSmall"),
            P(f"{t['first_seen']}: {first_seen}  |  {t['last_seen']}: {last_seen}", "AegisSmall"),
            P(f"{('Finding summary' if not is_es else 'Resumen del hallazgo')}: {finding_text(f, 'description', language)}", "AegisBody"),
        ]))
        story.append(P(f"{t['technical']}: {finding_text(f, 'explanation', language)}"))
        story.append(P(f"{t['finding_evidence']}:", "AegisSmall"))
        evidence = f.get("evidence") or []
        if evidence:
            for item in evidence[:5]:
                story.append(Paragraph("&#8226; " + escape(str(item)), styles["AegisEvidence"]))
        else:
            story.append(P("No representative event evidence was retained." if not is_es else "No se conservó evidencia representativa del evento.", "AegisSmall"))

        techniques = f.get("mitre") or []
        story.append(P("MITRE ATT&CK® alignment" if not is_es else "Alineación MITRE ATT&CK®", "AegisSmall"))
        if techniques:
            tech_text = "; ".join(f"{x['id']} {x['name']} ({', '.join(x['tactics'])})" for x in techniques)
            story.append(P(tech_text, "AegisSmall"))
            note_text = f.get("mitre_note_es" if is_es else "mitre_note", "")
            story.append(P(note_text, "AegisSmall"))
        else:
            story.append(P(f.get("mitre_note_es" if is_es else "mitre_note", "Not mapped."), "AegisSmall"))
        story.append(P(f"{t['action']}: {finding_text(f, 'recommendation', language)}"))
        story.append(Spacer(1, 5))

    # Technique register, with linked finding IDs and official tactic labels.
    technique_index: dict[str, dict[str, Any]] = {}
    technique_findings: dict[str, list[str]] = {}
    for f in findings:
        for technique in (f.get("mitre") or []):
            tid = technique["id"]
            technique_index[tid] = technique
            technique_findings.setdefault(tid, []).append(str(f.get("id", "")))
    story.append(P("MITRE ATT&CK® technique register" if not is_es else "Registro de técnicas MITRE ATT&CK®", "AegisH1"))
    if technique_index:
        mitre_rows = [[head("Technique ID"), head("Technique"), head("Tactic(s)"), head("Finding(s)"), head("Official reference" if not is_es else "Referencia oficial")]]
        for tid, technique in sorted(technique_index.items()):
            mitre_rows.append([
                cell(tid, True), cell(technique["name"]), cell(", ".join(technique["tactics"])),
                cell(", ".join(technique_findings.get(tid, []))),
                Paragraph(f'<link href="{escape(technique["url"])}" color="{jade.hexval()}">{"Open on MITRE" if not is_es else "Abrir en MITRE"}</link>', styles["AegisTableCell"]),
            ])
        story.append(make_table(mitre_rows, [23*mm, 44*mm, 43*mm, 22*mm, 44*mm]))
    else:
        story.append(P("No technique was assigned because the available evidence did not support a sufficiently specific mapping." if not is_es else "No se asignó una técnica porque la evidencia disponible no permite una correspondencia suficientemente específica."))
    attack_note = (
        "ATT&CK alignments are potential behavioral associations, not confirmed adversary techniques or attribution. The mapping does not change the Aegis risk score. "
        "The ATT&CK catalog reference used for this application was checked on 2026-10-31. Aegis is independent and is not affiliated with, sponsored by, or endorsed by MITRE."
        if not is_es else
        "Las alineaciones ATT&CK son asociaciones potenciales de comportamiento, no técnicas confirmadas ni atribución. El mapeo no modifica la puntuación de riesgo de Aegis. "
        "El catálogo ATT&CK utilizado por la aplicación se verificó el 31-10-2026. Aegis es independiente y no está afiliado, patrocinado ni respaldado por MITRE."
    )
    story.append(P(attack_note, "AegisSmall"))
    story.append(P("© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.", "AegisTiny"))

    # Prioritized plan of action.
    story.append(P(t["plan"], "AegisH1"))
    action_rows = [[head("ID"), head(t["priority"]), head(t["action"]), head(t["owner"]), head(t["target"])]]
    for f in sorted(findings, key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.get("severity"), 4)):
        priority, owner, target = severity_priority.get(f.get("severity"), ("P4", "Control Owner", "Next review cycle"))
        action_rows.append([
            cell(f.get("id", ""), True), cell(priority, True), cell(finding_text(f, "recommendation", language)),
            cell(owner), cell(target),
        ])
    if len(action_rows) == 1:
        action_rows.append([
            cell("—"), cell("P4"), cell("Review detection coverage and confirm log-source completeness." if not is_es else "Revisar la cobertura de detección y confirmar la integridad de las fuentes."),
            cell("Security Operations"), cell("Routine review" if not is_es else "Revisión rutinaria"),
        ])
    story.append(make_table(action_rows, [12*mm, 16*mm, 78*mm, 40*mm, 30*mm]))

    # Risk model and operational limitations.
    story.append(P("Risk scoring & interpretation" if not is_es else "Puntuación de riesgo e interpretación", "AegisH1"))
    if is_es:
        scoring = ("La puntuación se calcula sumando un peso por hallazgo: Crítico=30, Alto=22, Medio=13, Bajo=6 y otros=4. "
                   "Cada peso se multiplica por un factor de volumen min(1.7, 1 + log10(ocurrencias) × 0.18). La suma se redondea y limita a 100. "
                   "Los niveles son: 0 Informativo, 1-24 Bajo, 25-49 Medio, 50-74 Alto y 75-100 Crítico. Es una heurística de priorización, no una probabilidad calibrada de compromiso ni un riesgo financiero.")
        caveats = ("Las reglas no correlacionan árboles completos de procesos, telemetría de endpoint, puertos, protocolos, clasificación de datos o líneas base del entorno. "
                   "Los falsos positivos y negativos son posibles. La ausencia de hallazgos no demuestra que un entorno sea seguro. Revalida el mapeo de columnas, unidades y cobertura antes de tomar decisiones.")
    else:
        scoring = ("The score sums a per-finding weight: Critical=30, High=22, Medium=13, Low=6, and other=4. "
                   "Each weight is multiplied by a volume factor min(1.7, 1 + log10(occurrences) × 0.18). The sum is rounded and capped at 100. "
                   "Bands are: 0 Informational, 1-24 Low, 25-49 Medium, 50-74 High, and 75-100 Critical. This is a prioritization heuristic, not a calibrated probability of compromise or financial risk measure.")
        caveats = ("The rules do not correlate full process trees, endpoint telemetry, ports, protocols, data classification, or environment baselines. "
                   "False positives and false negatives are possible. No findings do not prove an environment is safe. Revalidate field mapping, units, and telemetry coverage before acting.")
    story.append(P(scoring))
    story.append(P(caveats))
    story.append(P(t["report_disclaimer"], "AegisSmall"))

    def page_decor(canvas, doc_obj):
        canvas.saveState()
        canvas.setFillColor(jade)
        canvas.rect(0, page_height - 4*mm, page_width, 4*mm, stroke=0, fill=1)
        canvas.setStrokeColor(line)
        canvas.setLineWidth(0.45)
        canvas.line(left_margin, 14*mm, page_width - right_margin, 14*mm)
        canvas.setFont("Helvetica-Bold", 6.8)
        canvas.setFillColor(ink)
        canvas.drawString(left_margin, page_height - 12*mm, "AEGIS SIEM  /  SECURITY ANALYSIS")
        canvas.setFont("Helvetica", 6.6)
        canvas.setFillColor(muted)
        canvas.drawRightString(page_width-right_margin, page_height - 12*mm, "CONFIDENTIAL - ANALYST WORK PRODUCT")
        canvas.drawString(left_margin, 8.5*mm, f"{report_id}  |  MITRE ATT&CK catalog checked {ATTACK_REFERENCE_AS_OF}")
        canvas.drawRightString(page_width-right_margin, 8.5*mm, f"Page {doc_obj.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page_decor, onLaterPages=page_decor)
    return buf.getvalue()


# -----------------------------------------------------------------------------
# Aegis SOC workspace shell
# -----------------------------------------------------------------------------

def ui_text(en: str, es: str) -> str:
    return es if st.session_state.get("language", "en") == "es" else en


def _severity_class(value: str) -> str:
    return {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}.get(value, "low")


# Keep navigation state independent from the visible language labels.
st.session_state.setdefault("active_page", "overview")
st.session_state.setdefault("language", "en")

with st.sidebar:
    st.markdown(
        "<div class='brand-lockup'><div class='brand-glyph'>A</div><div><div class='brand-name'>AEGIS</div><div class='brand-caption'>SECURITY OPERATIONS WORKSPACE</div></div></div>",
        unsafe_allow_html=True,
    )
    st.markdown(f"<div class='sidebar-section-label'>{tr('language')}</div>", unsafe_allow_html=True)
    language_choice = st.selectbox(
        "Language / Idioma", ["English", "Español"],
        index=0 if st.session_state.get("language", "en") == "en" else 1,
        label_visibility="collapsed", key="aegis_language_choice",
    )
    st.session_state["language"] = "es" if language_choice == "Español" else "en"

    st.markdown(f"<div class='sidebar-section-label' style='margin-top:18px'>{tr('appearance')}</div>", unsafe_allow_html=True)
    theme_options = list(PALETTES.keys())
    current_theme = st.session_state.get("ui_theme", "Graphite & Jade")
    if current_theme not in theme_options:
        current_theme = theme_options[0]
    theme_choice = st.selectbox(tr("appearance"), theme_options, index=theme_options.index(current_theme), label_visibility="collapsed", key="ui_theme")
    font_options = list(FONT_STACKS.keys())
    current_font = st.session_state.get("ui_font", font_options[0])
    if current_font not in font_options:
        current_font = font_options[0]
        # Clear legacy font values saved by earlier Aegis versions.
        st.session_state["ui_font"] = current_font
    language_code = st.session_state.get("language", "en")
    font_choice = st.selectbox(
        tr("typeface"), font_options, index=font_options.index(current_font),
        format_func=lambda value: FONT_LABELS.get(language_code, FONT_LABELS["en"]).get(value, value),
        label_visibility="collapsed", key="ui_font",
    )
    st.caption(tr("font_help"))
    selected_palette = PALETTES[theme_choice]
    selected_font_stack = FONT_STACKS[font_choice]

    st.markdown("---")
    with st.expander(tr("threshold"), expanded=False):
        failed_threshold = st.slider(tr("failed_threshold"), min_value=3, max_value=30, value=8, step=1, key="rule_failed_threshold")
        scan_threshold = st.slider(tr("scan_threshold"), min_value=5, max_value=100, value=20, step=5, key="rule_scan_threshold")
        exfil_mb = st.number_input(tr("exfil_threshold"), min_value=10, max_value=5000, value=100, step=10, key="rule_exfil_mb")
        include_vendor = st.toggle(tr("high_severity"), value=True, key="rule_include_vendor")
    st.markdown(
        "<div class='sidebar-footer'><span class='status-dot'></span>LOCAL ANALYSIS ACTIVE<br>RULE-BASED TRIAGE · XLSX INPUT<br>ANALYST-IN-THE-LOOP · PDF OUTPUT</div>",
        unsafe_allow_html=True,
    )

st.markdown(build_ui_css(selected_palette, selected_font_stack), unsafe_allow_html=True)

# Read analysis state early; all pages below are mutually exclusive, so only the selected page is rendered.
analysis = st.session_state.get("analysis")
nav_items = [
    ("overview", "◈  " + ui_text("Command Center", "Centro de mando")),
    ("findings", "◎  " + tr("findings")),
    ("events", "▤  " + tr("explorer")),
    ("reports", "▧  " + tr("report")),
    ("data", "＋  " + ui_text("Data & Rules", "Datos y reglas")),
]
page_titles = {
    "overview": (ui_text("SOC Command Center", "Centro de mando SOC"), ui_text("A single operational picture of the current log review.", "Una vista operativa unificada del análisis de registros actual.")),
    "findings": (ui_text("Detection & Findings", "Detecciones y hallazgos"), ui_text("Prioritize signals, inspect supporting evidence, and decide what to validate next.", "Prioriza señales, inspecciona la evidencia y decide qué validar a continuación.")),
    "events": (ui_text("Event Explorer", "Explorador de eventos"), ui_text("Search and pivot through normalized source events and detection-linked records.", "Busca y analiza eventos normalizados y registros vinculados a detecciones.")),
    "reports": (ui_text("Reporting Center", "Centro de informes"), ui_text("Review the technical summary and export a structured investigation report.", "Revisa el resumen técnico y exporta un informe de investigación estructurado.")),
    "data": (ui_text("Data Intake & Detection Controls", "Ingesta de datos y controles de detección"), ui_text("Bring in a SIEM workbook, confirm its schema, tune rule thresholds, and run the analysis.", "Importa un libro SIEM, confirma su estructura, ajusta las reglas y ejecuta el análisis.")),
}
active_page = st.session_state.get("active_page", "overview")
if active_page not in {item[0] for item in nav_items}:
    active_page = "overview"
    st.session_state["active_page"] = active_page

page_title, page_subtitle = page_titles[active_page]
source_name = analysis.get("source_name") if analysis else None
if analysis:
    status_text = ui_text(f"DATASET LOADED · {len(analysis['logs']):,} EVENTS", f"DATOS CARGADOS · {len(analysis['logs']):,} EVENTOS")
else:
    status_text = ui_text("AWAITING DATASET", "ESPERANDO DATOS")

st.markdown(
    f"""
    <div class="page-hero">
      <div class="page-hero-top">
        <div class="eyebrow">AEGIS / SECURITY OPERATIONS</div>
        <div class="session-chip"><span class="status-dot"></span>{status_text}</div>
      </div>
      <h1>{page_title}</h1>
      <p>{page_subtitle}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(f"<div class='nav-caption'>{ui_text('WORKSPACE NAVIGATION', 'NAVEGACIÓN DEL ESPACIO DE TRABAJO')}</div>", unsafe_allow_html=True)
nav_cols = st.columns(5)
for col, (page_key, label) in zip(nav_cols, nav_items):
    with col:
        if st.button(label, key=f"nav_{page_key}", type="primary" if active_page == page_key else "secondary", use_container_width=True):
            st.session_state["active_page"] = page_key
            st.rerun()

# Shared run settings. A changed configuration is explicitly flagged until the analyst reruns the analysis.
current_settings = {
    "failed_threshold": failed_threshold,
    "scan_threshold": scan_threshold,
    "exfil_mb": exfil_mb,
    "include_vendor": include_vendor,
}

# -----------------------------------------------------------------------------
# DATA INTAKE & RULES
# -----------------------------------------------------------------------------
if active_page == "data":
    st.markdown(f"<div class='section-kicker'>{ui_text('01 / IMPORT SIEM DATA', '01 / IMPORTAR DATOS SIEM')}</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='small-note'>{tr('upload_help')}</div>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader(tr("upload_label"), type=["xlsx", "xls"], key="aegis_workbook_upload")

    if uploaded_file is not None:
        incoming_bytes = uploaded_file.getvalue()
        incoming_fingerprint = hashlib.sha256(incoming_bytes).hexdigest()
        if incoming_fingerprint != st.session_state.get("workbook_fingerprint") or uploaded_file.name != st.session_state.get("workbook_name"):
            st.session_state["workbook_bytes"] = incoming_bytes
            st.session_state["workbook_fingerprint"] = incoming_fingerprint
            st.session_state["workbook_name"] = uploaded_file.name
            st.session_state.pop("selected_sheet", None)
            st.session_state.pop("analysis", None)
            st.session_state.pop("saved_mapping_key", None)

    workbook_bytes = st.session_state.get("workbook_bytes")
    workbook_name = st.session_state.get("workbook_name")
    workbook_fingerprint = st.session_state.get("workbook_fingerprint")

    if not workbook_bytes:
        st.markdown(
            f"""
            <div class="empty-state">
              <div class="empty-icon">⇧</div>
              <h3>{ui_text('Bring your SIEM telemetry into Aegis', 'Integra la telemetría SIEM en Aegis')}</h3>
              <p>{ui_text('Upload an Excel export. Aegis will suggest a field map, show you a preview, then apply transparent local detection rules. Your workbook is processed in this application session.', 'Carga una exportación de Excel. Aegis sugerirá un mapeo de campos, mostrará una vista previa y aplicará reglas locales transparentes. El libro se procesa dentro de esta sesión de la aplicación.')}</p>
              <span class="risk-pill risk-info">XLSX / XLS</span>
              <span class="risk-pill risk-low">{ui_text('LOCAL PROCESSING', 'PROCESAMIENTO LOCAL')}</span>
              <span class="risk-pill risk-info">{ui_text('ANALYST CONFIRMATION', 'VALIDACIÓN DEL ANALISTA')}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        sample_path = Path(__file__).with_name("sample_logs.xlsx")
        if sample_path.exists():
            with open(sample_path, "rb") as sample_file:
                st.download_button(ui_text("Download synthetic sample workbook", "Descargar libro de ejemplo sintético"), data=sample_file.read(), file_name="aegis_sample_logs.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    else:
        try:
            excel = pd.ExcelFile(BytesIO(workbook_bytes))
            sheet_names = excel.sheet_names
            previous_sheet = st.session_state.get("selected_sheet")
            if previous_sheet not in sheet_names:
                previous_sheet = sheet_names[0]
            sheet_key = "sheet_" + workbook_fingerprint[:10]
            sheet = st.selectbox(tr("select_sheet"), sheet_names, index=sheet_names.index(previous_sheet), key=sheet_key)
            if st.session_state.get("selected_sheet") != sheet:
                if st.session_state.get("selected_sheet") is not None:
                    st.session_state.pop("analysis", None)
                st.session_state["selected_sheet"] = sheet
            raw_df = pd.read_excel(BytesIO(workbook_bytes), sheet_name=sheet)
            raw_df.columns = [str(c) for c in raw_df.columns]
        except Exception as exc:
            st.error(tr("file_error"))
            st.caption(str(exc))
            raw_df = None

        if raw_df is not None:
            m1, m2, m3 = st.columns(3)
            with m1:
                st.markdown(f"<div class='metric-card'><div class='metric-label'>{ui_text('SOURCE WORKBOOK', 'LIBRO DE ORIGEN')}</div><div class='metric-value' style='font-size:1.05rem;overflow-wrap:anywhere'>{html_escape(str(workbook_name))}</div><div class='metric-note'>{html_escape(str(sheet))}</div></div>", unsafe_allow_html=True)
            with m2:
                st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('rows')}</div><div class='metric-value'>{len(raw_df):,}</div><div class='metric-note'>{ui_text('Rows available for analysis', 'Filas disponibles para análisis')}</div></div>", unsafe_allow_html=True)
            with m3:
                st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('columns')}</div><div class='metric-value'>{len(raw_df.columns):,}</div><div class='metric-note'>{ui_text('Detected worksheet columns', 'Columnas detectadas en la hoja')}</div></div>", unsafe_allow_html=True)

            st.markdown(f"<div class='section-kicker' style='margin-top:23px'>{ui_text('02 / CONFIRM FIELD MAPPING', '02 / CONFIRMAR MAPEO DE CAMPOS')}</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='small-note'>{tr('mapping_help')}</div>", unsafe_allow_html=True)
            columns = [str(c) for c in raw_df.columns]
            auto_map = suggest_mapping(columns)
            options = [None] + columns
            mapping_prefix = hashlib.sha256((workbook_fingerprint + str(sheet)).encode("utf-8")).hexdigest()[:10]
            saved_mapping_key = "aegis_mapping_" + mapping_prefix
            saved_mapping = st.session_state.get(saved_mapping_key, {})
            mapping: dict[str, str | None] = {}
            with st.expander(ui_text("Column mapping", "Mapeo de columnas"), expanded=True):
                left, right = st.columns(2)
                for idx, field in enumerate(CANONICAL_FIELDS):
                    target_col = left if idx % 2 == 0 else right
                    default_value = saved_mapping.get(field, auto_map.get(field))
                    if default_value not in options:
                        default_value = auto_map.get(field)
                    default_index = options.index(default_value) if default_value in options else 0
                    with target_col:
                        mapping[field] = st.selectbox(
                            tr(FIELD_LABELS[field]), options=options, index=default_index,
                            format_func=lambda x: tr("not_mapped") if x is None else str(x),
                            key=f"map_{mapping_prefix}_{field}",
                        )
            st.session_state[saved_mapping_key] = mapping

            if mapping.get("message") is None and mapping.get("event_name") is None and mapping.get("event_id") is None:
                st.warning(tr("missing_msg"))
            if mapping.get("timestamp") is None:
                st.info(tr("missing_time"))

            with st.expander(ui_text("Preview source rows", "Vista previa de filas de origen"), expanded=False):
                st.dataframe(raw_df.head(12), use_container_width=True, hide_index=True)

            st.markdown(f"<div class='section-kicker' style='margin-top:18px'>{ui_text('03 / EXECUTE ANALYSIS', '03 / EJECUTAR ANÁLISIS')}</div>", unsafe_allow_html=True)
            s1, s2 = st.columns([1.45, 1])
            with s1:
                st.caption(ui_text("Rules are configurable in the left sidebar. The engine is heuristic and explainable; review the generated evidence before treating a signal as an incident.", "Las reglas se configuran en la barra lateral. El motor es heurístico y explicable; revisa la evidencia antes de tratar una señal como incidente."))
            with s2:
                run_clicked = st.button(tr("run"), type="primary", use_container_width=True, key="run_aegis_analysis")
            if run_clicked:
                normalized = normalize_logs(raw_df, mapping)
                new_findings, enriched, risk_score, risk_level = analyze_logs(
                    normalized,
                    failed_threshold=int(failed_threshold),
                    scan_threshold=int(scan_threshold),
                    exfil_mb=int(exfil_mb),
                    include_vendor_severity=bool(include_vendor),
                )
                st.session_state["analysis"] = {
                    "logs": enriched,
                    "findings": new_findings,
                    "score": risk_score,
                    "level": risk_level,
                    "source_name": workbook_name,
                    "upload_fingerprint": workbook_fingerprint,
                    "sheet": sheet,
                    "mapping": mapping,
                    "mapping_state_key": saved_mapping_key,
                    "settings": dict(current_settings),
                }
                st.session_state["active_page"] = "overview"
                st.rerun()

            current_analysis = st.session_state.get("analysis")
            if current_analysis and current_analysis.get("upload_fingerprint") == workbook_fingerprint and current_analysis.get("sheet") == sheet:
                mapping_changed = current_analysis.get("mapping") != mapping
                settings_changed = current_analysis.get("settings") != current_settings
                if mapping_changed or settings_changed:
                    st.warning(ui_text("The current field mapping or detection settings differ from the last run. Rerun the analysis to apply your changes.", "El mapeo actual o la configuración de detección difieren de la última ejecución. Vuelve a ejecutar el análisis para aplicar los cambios."))
                else:
                    st.success(ui_text("An analysis exists for this workbook. Open the Command Center to review the results.", "Ya existe un análisis para este libro. Abre el Centro de mando para revisar los resultados."))

# Refresh the state after a potential analysis run.
analysis = st.session_state.get("analysis")

# -----------------------------------------------------------------------------
# COMMAND CENTER
# -----------------------------------------------------------------------------
if active_page == "overview":
    if not analysis:
        st.markdown(
            f"""
            <div class="empty-state">
              <div class="empty-icon">◈</div>
              <h3>{ui_text('Your SOC workspace is ready', 'Tu espacio SOC está listo')}</h3>
              <p>{ui_text('No analysis is loaded yet. Start by importing a SIEM Excel export, confirming the column mapping, and running the local detection rules. The Command Center will populate with risk posture, activity trends, and prioritized findings.', 'Todavía no hay un análisis cargado. Comienza importando una exportación SIEM de Excel, confirma el mapeo de columnas y ejecuta las reglas locales. El Centro de mando mostrará la postura de riesgo, las tendencias de actividad y los hallazgos priorizados.')}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        cta_col, _ = st.columns([1, 2])
        with cta_col:
            if st.button(ui_text("＋  Open Data & Rules", "＋  Abrir datos y reglas"), type="primary", use_container_width=True):
                st.session_state["active_page"] = "data"
                st.rerun()
    else:
        logs: pd.DataFrame = analysis["logs"]
        findings: list[dict[str, Any]] = analysis["findings"]
        score: int = analysis["score"]
        level: str = analysis["level"]
        critical_high = sum(1 for f in findings if f["severity"] in {"Critical", "High"})
        risk_class = {"Critical": "risk-critical", "High": "risk-high", "Medium": "risk-medium", "Low": "risk-low", "Informational": "risk-info"}.get(level, "risk-info")

        current_mapping_for_analysis = st.session_state.get(analysis.get("mapping_state_key", ""), analysis.get("mapping", {}))
        if analysis.get("settings") != current_settings or current_mapping_for_analysis != analysis.get("mapping", {}):
            st.warning(ui_text("The field mapping or detection settings have changed since this analysis. Visit Data & Rules and rerun to apply the updated configuration.", "El mapeo de campos o la configuración de detección cambiaron desde este análisis. Ve a Datos y reglas y vuelve a ejecutar para aplicar la configuración actualizada."))

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('risk_score')}</div><div class='metric-value'>{score}<span style='font-size:.78rem;color:var(--muted)'> / 100</span></div><div class='metric-note'>{ui_text('Heuristic aggregate score', 'Puntuación heurística agregada')}</div></div>", unsafe_allow_html=True)
        with k2:
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('risk_level')}</div><div style='margin-top:13px'><span class='risk-pill {risk_class}'>{localized_severity(level, st.session_state['language'])}</span></div><div class='metric-note'>{ui_text('Overall classification', 'Clasificación general')}</div></div>", unsafe_allow_html=True)
        with k3:
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('events')}</div><div class='metric-value'>{len(logs):,}</div><div class='metric-note'>{ui_text('Rows in selected worksheet', 'Filas de la hoja seleccionada')}</div></div>", unsafe_allow_html=True)
        with k4:
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('findings_count')}</div><div class='metric-value'>{len(findings):,}</div><div class='metric-note'>{critical_high} {tr('critical_high').lower()}</div></div>", unsafe_allow_html=True)

        left, right = st.columns([0.95, 1.55], gap="large")
        with left:
            st.markdown(f"<div class='content-header'><div><h2>{ui_text('Risk posture', 'Postura de riesgo')}</h2><p>{ui_text('Heuristic score based on triggered detections', 'Puntuación heurística basada en detecciones activadas')}</p></div></div>", unsafe_allow_html=True)
            gauge = go.Figure(go.Indicator(
                mode="gauge+number", value=score,
                number={"suffix": "/100", "font": {"size": 34, "color": selected_palette["text"], "family": selected_font_stack}},
                title={"text": localized_severity(level, st.session_state["language"]), "font": {"size": 13, "color": selected_palette["muted"]}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": selected_palette["muted"], "tickfont": {"color": selected_palette["muted"]}},
                    "bar": {"color": selected_palette["accent"], "thickness": 0.28},
                    "bgcolor": selected_palette["surface"], "borderwidth": 0,
                    "steps": [
                        {"range": [0, 25], "color": selected_palette["surface_2"]},
                        {"range": [25, 50], "color": selected_palette["surface_2"]},
                        {"range": [50, 75], "color": selected_palette["surface_2"]},
                        {"range": [75, 100], "color": selected_palette["surface_2"]},
                    ],
                },
            ))
            polish_chart(gauge, selected_palette, selected_font_stack, height=245, margin=dict(l=20, r=20, t=42, b=8))
            st.plotly_chart(gauge, use_container_width=True, config={"displayModeBar": False})
            st.caption(ui_text("This is a prioritization heuristic, not a probability of compromise.", "Es una heurística de priorización, no una probabilidad de compromiso."))

        with right:
            st.markdown(f"<div class='content-header'><div><h2>{ui_text('Priority queue', 'Cola de prioridad')}</h2><p>{ui_text('Highest criticality signals requiring analyst review', 'Señales de mayor criticidad que requieren revisión')}</p></div></div>", unsafe_allow_html=True)
            if findings:
                rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
                top_findings = sorted(findings, key=lambda f: (rank.get(f["severity"], 4), -f["count"]))[:4]
                for f in top_findings:
                    title = html_escape(finding_text(f, "title", st.session_state["language"]))
                    severity_label = html_escape(localized_severity(f["severity"], st.session_state["language"]))
                    st.markdown(
                        f"<div class='queue-row {_severity_class(f['severity'])}'><div style='display:flex;justify-content:space-between;gap:8px'><span class='queue-id'>{html_escape(f['id'])} · {html_escape(f['rule'])}</span><span class='risk-pill risk-{f['severity'].lower()}'>{severity_label}</span></div><div class='queue-title'>{title}</div><div class='queue-meta'>{tr('occurrences')}: {f['count']} · {tr('affected')}: {html_escape(str(f['affected'])[:95])}</div></div>",
                        unsafe_allow_html=True,
                    )
            else:
                st.info(tr("no_findings"))
            if st.button(ui_text("View all findings →", "Ver todos los hallazgos →"), use_container_width=True):
                st.session_state["active_page"] = "findings"
                st.rerun()

        st.markdown(f"<div class='section-kicker' style='margin-top:22px'>{ui_text('TELEMETRY OVERVIEW', 'VISTA GENERAL DE TELEMETRÍA')}</div>", unsafe_allow_html=True)
        f1, f2 = st.columns(2)
        with f1:
            sev_counts = logs["normalized_severity"].value_counts().rename_axis("Severity").reset_index(name="Events")
            sev_counts["Severity"] = sev_counts["Severity"].map(lambda x: localized_severity(x, st.session_state["language"]))
            localized_colors = {"Critical": "#ef6575", "High": "#f39a5b", "Medium": "#e8c66b", "Low": "#55c9b4", "Unknown": "#6f839a", "None": "#6f839a"}
            color_map = {localized_severity(k, st.session_state["language"]): v for k, v in localized_colors.items()}
            fig = px.pie(sev_counts, names="Severity", values="Events", hole=.66, color="Severity", color_discrete_map=color_map)
            fig.update_traces(textposition="inside", textinfo="percent")
            polish_chart(fig, selected_palette, selected_font_stack, height=310, title=ui_text("Event severity distribution", "Distribución de severidad"))
            st.plotly_chart(fig, use_container_width=True)
        with f2:
            cat_counts = logs["category"].value_counts().head(9).rename_axis("Category").reset_index(name="Events")
            cat_counts["Category"] = cat_counts["Category"].map(lambda x: localized_category(x, st.session_state["language"]))
            fig = px.bar(cat_counts, x="Events", y="Category", orientation="h", color="Events", color_continuous_scale=[selected_palette["surface_2"], selected_palette["accent"]])
            polish_chart(fig, selected_palette, selected_font_stack, coloraxis_showscale=False, yaxis={"categoryorder": "total ascending"}, height=310, title=ui_text("Top event categories", "Principales categorías de eventos"))
            st.plotly_chart(fig, use_container_width=True)

        f3, f4 = st.columns([1.3, 1])
        with f3:
            timed = logs.dropna(subset=["timestamp"])
            if len(timed):
                freq = "h" if (timed["timestamp"].max() - timed["timestamp"].min()) <= pd.Timedelta(days=3) else "D"
                trend = timed.set_index("timestamp").resample(freq).size().reset_index(name="Events")
                fig = px.area(trend, x="timestamp", y="Events")
                fig.update_traces(line_color=selected_palette["accent"], fillcolor=selected_palette["accent_soft"])
                polish_chart(fig, selected_palette, selected_font_stack, xaxis_title="UTC", yaxis_title="Events", height=300, title=tr("timeline"))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info(tr("missing_time"))
        with f4:
            src_counts = logs[logs["source_ip"].astype(str).str.len().gt(0)]["source_ip"].value_counts().head(8).rename_axis("Source IP").reset_index(name="Events")
            if len(src_counts):
                fig = px.bar(src_counts, x="Events", y="Source IP", orientation="h")
                fig.update_traces(marker_color=selected_palette["accent"])
                polish_chart(fig, selected_palette, selected_font_stack, yaxis={"categoryorder": "total ascending"}, height=300, title=tr("top_sources"))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info(ui_text("No source IP values are available in this worksheet.", "No hay valores de IP de origen en esta hoja."))

        technique_rows = []
        technique_seen = {}
        for finding in findings:
            for technique in finding.get("mitre", []):
                entry = technique_seen.setdefault(technique["id"], {"Technique ID": technique["id"], "Technique": technique["name"], "Tactics": ", ".join(technique["tactics"]), "Findings": []})
                entry["Findings"].append(finding["id"])
        for entry in technique_seen.values():
            technique_rows.append({**entry, "Findings": ", ".join(entry["Findings"])})
        if technique_rows:
            st.markdown(f"<div class='section-kicker' style='margin-top:22px'>{ui_text('MITRE ATT&CK® COVERAGE (POTENTIAL)', 'COBERTURA MITRE ATT&CK® (POTENCIAL)')}</div>", unsafe_allow_html=True)
            st.caption(ui_text("Candidate technique alignments from the triggered rules. Mappings are contextual and are not proof of adversary activity.", "Alineaciones candidatas de técnicas a partir de las reglas activadas. Son contextuales y no prueban actividad adversaria."))
            st.dataframe(pd.DataFrame(technique_rows), use_container_width=True, hide_index=True)

# -----------------------------------------------------------------------------
# FINDINGS WORKSPACE
# -----------------------------------------------------------------------------
elif active_page == "findings":
    if not analysis:
        st.info(ui_text("No analysis is loaded. Import a workbook from Data & Rules first.", "No hay un análisis cargado. Primero importa un libro desde Datos y reglas."))
        if st.button(ui_text("Open Data & Rules", "Abrir datos y reglas"), type="primary"):
            st.session_state["active_page"] = "data"
            st.rerun()
    else:
        findings: list[dict[str, Any]] = analysis["findings"]
        if not findings:
            st.info(tr("no_findings"))
        else:
            rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_findings = sorted(findings, key=lambda f: (rank.get(f["severity"], 4), -f["count"]))
            severity_values = ["Critical", "High", "Medium", "Low"]
            filter_col, search_col = st.columns([1, 1.5])
            with filter_col:
                selected_internal = st.multiselect(
                    tr("criticality"), severity_values, default=severity_values,
                    format_func=lambda value: localized_severity(value, st.session_state["language"]),
                    key="finding_severity_filter",
                )
            with search_col:
                finding_query = st.text_input(ui_text("Search findings", "Buscar hallazgos"), placeholder="Rule, IP, account, ID...", key="finding_search")
            filtered_findings = [f for f in sorted_findings if f["severity"] in selected_internal]
            if finding_query:
                q = finding_query.casefold()
                filtered_findings = [f for f in filtered_findings if q in " ".join([f["id"], f["rule"], finding_text(f, "title", st.session_state["language"]), str(f["affected"])]).casefold()]

            st.markdown(f"<div class='section-kicker'>{ui_text('FINDING REGISTER', 'REGISTRO DE HALLAZGOS')} · {len(filtered_findings)} / {len(findings)}</div>", unsafe_allow_html=True)
            if not filtered_findings:
                st.info(ui_text("No findings match the current filters.", "Ningún hallazgo coincide con los filtros actuales."))
            else:
                left, right = st.columns([1.05, 1.5], gap="large")
                finding_ids = [f["id"] for f in filtered_findings]
                with left:
                    st.markdown(f"### {ui_text('Investigation queue', 'Cola de investigación')}")
                    for f in filtered_findings:
                        title = html_escape(finding_text(f, "title", st.session_state["language"]))
                        sev = html_escape(localized_severity(f["severity"], st.session_state["language"]))
                        st.markdown(
                            f"<div class='queue-row {_severity_class(f['severity'])}'><div style='display:flex;justify-content:space-between;gap:8px'><span class='queue-id'>{html_escape(f['id'])} · {html_escape(f['rule'])}</span><span class='risk-pill risk-{f['severity'].lower()}'>{sev}</span></div><div class='queue-title'>{title}</div><div class='queue-meta'>{tr('occurrences')}: {f['count']} · {tr('first_seen')}: {f['first_seen'] if pd.notna(f['first_seen']) else '—'}</div></div>",
                            unsafe_allow_html=True,
                        )
                with right:
                    if st.session_state.get("active_finding_detail") not in finding_ids:
                        st.session_state.pop("active_finding_detail", None)
                    chosen_id = st.selectbox(
                        ui_text("Open finding", "Abrir hallazgo"), finding_ids,
                        format_func=lambda fid: next(f"{f['id']} · {finding_text(f, 'title', st.session_state['language'])}" for f in filtered_findings if f["id"] == fid),
                        key="active_finding_detail",
                    )
                    f = next(item for item in filtered_findings if item["id"] == chosen_id)
                    risk_class = {"Critical": "risk-critical", "High": "risk-high", "Medium": "risk-medium", "Low": "risk-low"}.get(f["severity"], "risk-info")
                    st.markdown(
                        f"<div class='surface-card'><div class='queue-id'>{html_escape(f['id'])} · {html_escape(f['rule'])}</div><h2 style='margin:.4rem 0 .55rem'>{html_escape(finding_text(f, 'title', st.session_state['language']))}</h2><span class='risk-pill {risk_class}'>{html_escape(localized_severity(f['severity'], st.session_state['language']))}</span></div>",
                        unsafe_allow_html=True,
                    )
                    d1, d2, d3 = st.columns(3)
                    d1.metric(tr("occurrences"), f"{f['count']:,}")
                    d2.metric(tr("first_seen"), f["first_seen"].strftime("%Y-%m-%d %H:%M") if pd.notna(f["first_seen"]) else "—")
                    d3.metric(tr("last_seen"), f["last_seen"].strftime("%Y-%m-%d %H:%M") if pd.notna(f["last_seen"]) else "—")

                    st.markdown(f"<div class='detail-label'>{tr('affected')}</div>", unsafe_allow_html=True)
                    st.write(f["affected"])
                    st.markdown(f"<div class='detail-label'>{ui_text('Finding summary', 'Resumen del hallazgo')}</div>", unsafe_allow_html=True)
                    st.write(finding_text(f, "description", st.session_state["language"]))
                    st.markdown(f"<div class='detail-label'>{tr('technical')}</div>", unsafe_allow_html=True)
                    st.write(finding_text(f, "explanation", st.session_state["language"]))
                    st.markdown(f"<div class='detail-label'>{tr('finding_evidence')}</div>", unsafe_allow_html=True)
                    for evidence_item in f["evidence"]:
                        st.code(evidence_item, language="text")

                    st.markdown(f"<div class='detail-label'>{ui_text('MITRE ATT&CK® alignment', 'Alineación MITRE ATT&CK®')}</div>", unsafe_allow_html=True)
                    if f.get("mitre"):
                        st.caption(ui_text("Potential behavioral alignment - not confirmation of adversary activity. These mappings do not affect the Aegis risk score.", "Alineación potencial de comportamiento; no confirma actividad adversaria. Estas asignaciones no modifican la puntuación de riesgo de Aegis."))
                        for technique in f["mitre"]:
                            tactic_text = ", ".join(technique.get("tactics", []))
                            st.markdown(f"**{technique['id']} - {technique['name']}**  \n`{tactic_text}`  \n[Official MITRE ATT&CK reference]({technique['url']})")
                    else:
                        st.caption(f.get("mitre_note_es" if st.session_state["language"] == "es" else "mitre_note", ui_text("No specific mapping supported by the available evidence.", "La evidencia disponible no respalda una asignación específica.")))
                    st.caption(ui_text(f"ATT&CK catalog checked {ATTACK_REFERENCE_AS_OF}.", f"Catálogo ATT&CK verificado el {ATTACK_REFERENCE_AS_OF}."))

                    st.markdown(f"<div class='detail-label'>{tr('action')}</div>", unsafe_allow_html=True)
                    st.info(finding_text(f, "recommendation", st.session_state["language"]))

            finding_export_rows = []
            for finding in findings:
                export_row = {k: v for k, v in finding.items() if k not in {"indices", "evidence", "sources", "users", "mitre"}}
                export_row["evidence"] = " || ".join(finding.get("evidence", []))
                export_row["mitre_ids"] = "; ".join(x["id"] for x in finding.get("mitre", []))
                export_row["mitre_techniques"] = "; ".join(x["name"] for x in finding.get("mitre", []))
                export_row["mitre_tactics"] = "; ".join(sorted({t for x in finding.get("mitre", []) for t in x.get("tactics", [])}))
                finding_export_rows.append(export_row)
            finding_export = pd.DataFrame(finding_export_rows)
            st.download_button(tr("download_findings"), data=finding_export.to_csv(index=False).encode("utf-8-sig"), file_name="aegis_findings.csv", mime="text/csv")

# -----------------------------------------------------------------------------
# EVENT EXPLORER
# -----------------------------------------------------------------------------
elif active_page == "events":
    if not analysis:
        st.info(ui_text("No analysis is loaded. Import a workbook from Data & Rules first.", "No hay un análisis cargado. Primero importa un libro desde Datos y reglas."))
        if st.button(ui_text("Open Data & Rules", "Abrir datos y reglas"), type="primary"):
            st.session_state["active_page"] = "data"
            st.rerun()
    else:
        logs: pd.DataFrame = analysis["logs"]
        st.markdown(f"<div class='section-kicker'>{ui_text('SEARCH & PIVOT', 'BÚSQUEDA Y PIVOTAJE')}</div>", unsafe_allow_html=True)
        q_col, sev_col, det_col = st.columns([1.5, 1, 1])
        with q_col:
            query = st.text_input(tr("search"), placeholder="IP, username, event ID, process...", key="event_search")
        with sev_col:
            available = sorted([s for s in logs["normalized_severity"].dropna().unique().tolist()])
            event_severity = st.multiselect(
                tr("severity_filter"), available,
                format_func=lambda value: localized_severity(value, st.session_state["language"]),
                key="event_severity_filter",
            )
        with det_col:
            show_only_detected = st.toggle(ui_text("Detected only", "Solo detectados"), value=False, key="event_detected_only")

        event_view = logs.copy()
        searchable_cols = [c for c in ["source_ip", "destination_ip", "username", "event_id", "event_name", "message", "host", "process", "command_line", "finding_ids"] if c in event_view.columns]
        if query and searchable_cols:
            mask = event_view[searchable_cols].astype(str).apply(lambda col: col.str.contains(re.escape(query), case=False, na=False)).any(axis=1)
            event_view = event_view[mask]
        if event_severity:
            event_view = event_view[event_view["normalized_severity"].isin(event_severity)]
        if show_only_detected:
            event_view = event_view[event_view["finding_ids"].astype(str).str.len().gt(0)]

        event_count_col, matched_col, _ = st.columns([1, 1, 2])
        event_count_col.metric(ui_text("Visible events", "Eventos visibles"), f"{len(event_view):,}")
        matched_col.metric(ui_text("Events with detections", "Eventos con detecciones"), f"{event_view['finding_ids'].astype(str).str.len().gt(0).sum():,}" if len(event_view) else "0")

        view_cols = [c for c in ["timestamp", "normalized_severity", "detection_severity", "category", "source_ip", "destination_ip", "username", "event_id", "event_name", "host", "finding_ids", "message"] if c in event_view.columns]
        display_view = event_view[view_cols].copy()
        if st.session_state["language"] == "es":
            if "normalized_severity" in display_view:
                display_view["normalized_severity"] = display_view["normalized_severity"].map(lambda x: localized_severity(x, "es"))
            if "detection_severity" in display_view:
                display_view["detection_severity"] = display_view["detection_severity"].map(lambda x: localized_severity(x, "es"))
            if "category" in display_view:
                display_view["category"] = display_view["category"].map(lambda x: localized_category(x, "es"))
        st.dataframe(display_view, use_container_width=True, hide_index=True, height=520)
        st.download_button(tr("download_csv"), data=event_view.to_csv(index=False).encode("utf-8-sig"), file_name="aegis_filtered_events.csv", mime="text/csv")

# -----------------------------------------------------------------------------
# REPORTING CENTER
# -----------------------------------------------------------------------------
elif active_page == "reports":
    if not analysis:
        st.info(ui_text("No analysis is loaded. Import a workbook from Data & Rules first.", "No hay un análisis cargado. Primero importa un libro desde Datos y reglas."))
        if st.button(ui_text("Open Data & Rules", "Abrir datos y reglas"), type="primary"):
            st.session_state["active_page"] = "data"
            st.rerun()
    else:
        logs: pd.DataFrame = analysis["logs"]
        findings: list[dict[str, Any]] = analysis["findings"]
        score: int = analysis["score"]
        level: str = analysis["level"]
        st.markdown(f"<div class='section-kicker'>{ui_text('REPORT METADATA', 'METADATOS DEL INFORME')}</div>", unsafe_allow_html=True)
        meta1, meta2, meta3 = st.columns([1.4, 1, 1])
        with meta1:
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('source_file')}</div><div class='metric-value' style='font-size:1rem;overflow-wrap:anywhere'>{html_escape(str(analysis['source_name']))}</div><div class='metric-note'>{html_escape(str(analysis.get('sheet', '')))}</div></div>", unsafe_allow_html=True)
        with meta2:
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('events')}</div><div class='metric-value'>{len(logs):,}</div><div class='metric-note'>{ui_text('Events reviewed', 'Eventos revisados')}</div></div>", unsafe_allow_html=True)
        with meta3:
            risk_class = {"Critical": "risk-critical", "High": "risk-high", "Medium": "risk-medium", "Low": "risk-low", "Informational": "risk-info"}.get(level, "risk-info")
            st.markdown(f"<div class='metric-card'><div class='metric-label'>{tr('risk_level')}</div><div style='margin-top:13px'><span class='risk-pill {risk_class}'>{localized_severity(level, st.session_state['language'])}</span></div><div class='metric-note'>{tr('risk_score')}: {score}/100</div></div>", unsafe_allow_html=True)

        st.markdown(f"### {tr('summary')}")
        if st.session_state["language"] == "en":
            st.write(f"The analysis reviewed {len(logs):,} events and generated {len(findings)} findings. The aggregate heuristic risk score is {score}/100 ({level}).")
        else:
            st.write(f"El análisis revisó {len(logs):,} eventos y generó {len(findings)} hallazgos. La puntuación heurística agregada es {score}/100 ({level}).")

        st.markdown(f"### {tr('findings')}")
        if findings:
            rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            action_items = []
            for f in sorted(findings, key=lambda x: (rank.get(x["severity"], 4), -x["count"])):
                action_items.append({
                    tr("priority"): {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(f["severity"], "P4"),
                    "ID": f["id"],
                    tr("criticality"): localized_severity(f["severity"], st.session_state["language"]),
                    tr("finding_evidence"): finding_text(f, "title", st.session_state["language"]),
                    tr("action"): finding_text(f, "recommendation", st.session_state["language"]),
                })
            st.dataframe(pd.DataFrame(action_items), use_container_width=True, hide_index=True)
        else:
            st.info(tr("no_findings"))

        st.markdown(f"### {tr('scope')}")
        st.caption(tr("report_disclaimer"))
        try:
            pdf_bytes = make_pdf_report(findings, logs, score, level, analysis["source_name"], st.session_state["language"], metadata=analysis)
            st.download_button(tr("download_pdf"), data=pdf_bytes, file_name="aegis_siem_technical_report.pdf", mime="application/pdf", type="primary", use_container_width=True)
        except Exception as exc:
            st.error(f"PDF generation failed: {exc}")

st.markdown("<div style='text-align:center;color:var(--muted);font-size:.66rem;letter-spacing:.09em;margin-top:34px'>AEGIS SIEM · ANALYST-IN-THE-LOOP · LOCAL SESSION PROCESSING</div>", unsafe_allow_html=True)
