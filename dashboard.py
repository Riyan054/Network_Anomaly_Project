"""
dashboard.py — Streamlit real-time dashboard.

Run with:
    streamlit run dashboard.py
(No sudo needed — it only reads from the database.)
"""

import os
import subprocess
import time
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from config import LIVE_LOG_LIMIT, REFRESH_INTERVAL, CHART_WINDOW, STOP_FLAG, SNIFFER_PID
from database import (
    fetch_recent_packets,
    fetch_status_counts,
    fetch_packets_per_second,
    fetch_top_threat_ips,
    fetch_total_count,
    fetch_recent_dangerous,
    init_db,
    clear_db,
)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Network Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

init_db()

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"], .main {
    background-color: #060B18 !important;
    color: #CBD5E1 !important;
    font-family: 'Inter', sans-serif !important;
}
section[data-testid="stSidebar"] { display: none; }
#MainMenu, footer, [data-testid="stToolbar"],
[data-testid="stDecoration"] { display: none !important; }
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="block-container"] { padding: 1.2rem 1.8rem !important; }
[data-testid="stVerticalBlock"] > div { gap: 0 !important; }

::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #0B1120; }
::-webkit-scrollbar-thumb { background: #1E3A5F; border-radius: 4px; }

/* ── HEADER ──────────────────────────────────────────────────────────────── */
.nads-header {
    background: linear-gradient(135deg, #0D1B35 0%, #091525 100%);
    border: 1px solid #1a3456;
    border-radius: 14px;
    padding: 16px 26px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 18px;
    box-shadow: 0 4px 30px rgba(0,80,255,.08), inset 0 1px 0 rgba(255,255,255,.04);
}
.nads-title {
    font-size: 1.45rem; font-weight: 800;
    color: #F1F5F9; letter-spacing: -.02em;
    display: flex; align-items: center; gap: 10px;
}
.nads-title small { font-size: .85rem; font-weight: 400; color: #64748B; }
.header-right { display: flex; gap: 12px; align-items: center; }
.live-badge {
    display: flex; align-items: center; gap: 7px;
    background: rgba(16,185,129,.12);
    border: 1px solid rgba(16,185,129,.3);
    border-radius: 20px; padding: 5px 14px;
    font-size: .78rem; font-weight: 600; color: #10B981; letter-spacing: .05em;
}
.live-dot {
    width: 8px; height: 8px; background: #10B981;
    border-radius: 50%; animation: pgreen 1.5s infinite;
}
@keyframes pgreen {
    0%,100% { box-shadow: 0 0 0 0 rgba(16,185,129,.7); }
    50%      { box-shadow: 0 0 0 6px rgba(16,185,129,0); }
}
.meta-pill {
    background: rgba(255,255,255,.04);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 8px; padding: 5px 14px;
    font-size: .8rem; color: #64748B;
}
.meta-pill b { color: #94A3B8; font-family: 'JetBrains Mono', monospace; font-weight: 500; }

/* ── CONTROL BAR ─────────────────────────────────────────────────────────── */
.ctrl-bar {
    display: flex; align-items: center; gap: 8px;
    margin-bottom: 14px;
    background: rgba(13,20,33,.8);
    border: 1px solid #1a2e4a;
    border-radius: 10px;
    padding: 8px 14px;
    width: fit-content;
}
/* Hide all default Streamlit button wrappers in control zone */
.ctrl-zone { display: none; }

/* Shared button base */
.ctrl-bar button, [data-testid="stButton"].ctrl-real > button {
    display: inline-flex !important;
    align-items: center !important;
    gap: 6px !important;
    padding: 6px 18px !important;
    border-radius: 7px !important;
    font-size: .8rem !important;
    font-weight: 700 !important;
    letter-spacing: .04em !important;
    cursor: pointer !important;
    border: none !important;
    transition: all .15s ease !important;
    box-shadow: 0 2px 8px rgba(0,0,0,.35) !important;
    text-transform: uppercase !important;
}

/* Start — solid green */
.start-btn > button {
    background: linear-gradient(135deg, #059669, #10B981) !important;
    color: #fff !important;
}
.start-btn > button:hover { filter: brightness(1.15) !important; transform: translateY(-1px) !important; box-shadow: 0 4px 14px rgba(16,185,129,.4) !important; }
.start-btn > button:active { transform: translateY(0) !important; filter: brightness(.95) !important; }
.start-btn > button:disabled { background: rgba(16,185,129,.2) !important; color: rgba(16,185,129,.45) !important; box-shadow: none !important; cursor: not-allowed !important; transform: none !important; }

/* Stop — solid amber */
.stop-btn > button {
    background: linear-gradient(135deg, #D97706, #F59E0B) !important;
    color: #000 !important;
}
.stop-btn > button:hover { filter: brightness(1.12) !important; transform: translateY(-1px) !important; box-shadow: 0 4px 14px rgba(245,158,11,.4) !important; }
.stop-btn > button:active { transform: translateY(0) !important; }
.stop-btn > button:disabled { background: rgba(245,158,11,.2) !important; color: rgba(245,158,11,.35) !important; box-shadow: none !important; cursor: not-allowed !important; transform: none !important; }

/* Reset — solid red */
.reset-btn > button {
    background: linear-gradient(135deg, #DC2626, #EF4444) !important;
    color: #fff !important;
}
.reset-btn > button:hover { filter: brightness(1.12) !important; transform: translateY(-1px) !important; box-shadow: 0 4px 14px rgba(239,68,68,.4) !important; }
.reset-btn > button:active { transform: translateY(0) !important; }

/* Divider between buttons and status */
.ctrl-divider {
    width: 1px; height: 26px; background: #1E3A5F; margin: 0 6px;
}

/* ── KPI CARDS ───────────────────────────────────────────────────────────── */
.kpi-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 18px; }
.kpi-card {
    background: rgba(13,20,33,.95);
    border-radius: 14px; padding: 22px 20px;
    border: 1px solid; position: relative; overflow: hidden;
}
.kpi-card::after {
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
}
.kpi-total  { border-color: rgba(96,165,250,.25); box-shadow: 0 4px 20px rgba(96,165,250,.05); }
.kpi-total::after  { background: linear-gradient(90deg,#3B82F6,#60A5FA); }
.kpi-safe   { border-color: rgba(16,185,129,.25); box-shadow: 0 4px 20px rgba(16,185,129,.05); }
.kpi-safe::after   { background: linear-gradient(90deg,#059669,#10B981); }
.kpi-sus    { border-color: rgba(245,158,11,.25);  box-shadow: 0 4px 20px rgba(245,158,11,.05);  }
.kpi-sus::after    { background: linear-gradient(90deg,#D97706,#F59E0B); }
.kpi-danger { border-color: rgba(239,68,68,.3);   box-shadow: 0 4px 20px rgba(239,68,68,.08);   }
.kpi-danger::after { background: linear-gradient(90deg,#DC2626,#EF4444); }

.kpi-label {
    font-size: .75rem; font-weight: 600; letter-spacing: .08em;
    text-transform: uppercase; color: #64748B; margin-bottom: 10px;
    display: flex; align-items: center; gap: 6px;
}
.kpi-value {
    font-size: 2.2rem; font-weight: 800; letter-spacing: -.03em;
    font-family: 'JetBrains Mono', monospace; line-height: 1;
}
.kpi-total  .kpi-value { color: #60A5FA; }
.kpi-safe   .kpi-value { color: #10B981; }
.kpi-sus    .kpi-value { color: #F59E0B; }
.kpi-danger .kpi-value { color: #EF4444; animation: pulse-red 2s infinite; }
@keyframes pulse-red {
    0%,100% { text-shadow: 0 0 0 rgba(239,68,68,0); }
    50%      { text-shadow: 0 0 14px rgba(239,68,68,.6); }
}
.kpi-sub { font-size: .73rem; color: #475569; margin-top: 6px; }

/* ── SECTION CARDS ───────────────────────────────────────────────────────── */
.chart-card {
    background: rgba(13,20,33,.9);
    border: 1px solid #1a2e4a;
    border-radius: 14px; padding: 18px 20px;
    margin-bottom: 16px;
    box-shadow: 0 2px 16px rgba(0,0,0,.3);
}
.card-title {
    font-size: .85rem; font-weight: 700; letter-spacing: .05em;
    text-transform: uppercase; color: #94A3B8; margin-bottom: 14px;
    display: flex; align-items: center; gap: 8px;
}

/* ── STATUS BADGES ───────────────────────────────────────────────────────── */
.badge {
    display: inline-block; padding: 2px 10px;
    border-radius: 20px; font-size: .72rem; font-weight: 700;
    letter-spacing: .06em; text-transform: uppercase;
}
.badge-safe    { background: rgba(16,185,129,.15); color: #10B981; border: 1px solid rgba(16,185,129,.3); }
.badge-suspicious { background: rgba(245,158,11,.15); color: #F59E0B; border: 1px solid rgba(245,158,11,.3); }
.badge-dangerous  { background: rgba(239,68,68,.15);  color: #EF4444; border: 1px solid rgba(239,68,68,.4);  }

/* ── ALERT BANNER ────────────────────────────────────────────────────────── */
.alert-banner {
    background: linear-gradient(135deg, rgba(239,68,68,.12), rgba(220,38,38,.06));
    border: 1px solid rgba(239,68,68,.4);
    border-radius: 10px; padding: 12px 20px;
    font-size: .85rem; color: #FCA5A5;
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 14px; animation: alert-pulse 2s infinite;
}
@keyframes alert-pulse {
    0%,100% { border-color: rgba(239,68,68,.4); box-shadow: 0 0 0 0 rgba(239,68,68,0); }
    50%      { border-color: rgba(239,68,68,.7); box-shadow: 0 0 16px rgba(239,68,68,.15); }
}

/* ── TABLE ───────────────────────────────────────────────────────────────── */
.stDataFrame { border-radius: 10px; overflow: hidden; }
[data-testid="stDataFrame"] th {
    background: #0D1421 !important; color: #64748B !important;
    font-size: .72rem !important; font-weight: 700 !important;
    text-transform: uppercase !important; letter-spacing: .06em !important;
}
[data-testid="stDataFrame"] td { font-size: .8rem !important; }

/* ── WAITING STATE ───────────────────────────────────────────────────────── */
.waiting {
    text-align: center; padding: 60px 20px;
    color: #475569; font-size: .95rem;
}
.waiting h3 { color: #64748B; margin-bottom: 8px; font-size: 1.1rem; }
</style>
""", unsafe_allow_html=True)


# ── Helper: format timestamp ──────────────────────────────────────────────────
def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# ── Helper: status badge html ─────────────────────────────────────────────────
def badge(status: str) -> str:
    cls = {"safe": "badge-safe", "suspicious": "badge-suspicious",
           "dangerous": "badge-dangerous"}.get(status, "badge-safe")
    return f'<span class="badge {cls}">{status}</span>'


# ── Fetch all data ─────────────────────────────────────────────────────────────
counts    = fetch_status_counts()
total     = fetch_total_count()
n_safe    = counts.get("safe", 0)
n_sus     = counts.get("suspicious", 0)
n_danger  = counts.get("dangerous", 0)
pps_rows  = fetch_packets_per_second(CHART_WINDOW)
top_ips   = fetch_top_threat_ips(10)
recent    = fetch_recent_packets(LIVE_LOG_LIMIT)
dangerous = fetch_recent_dangerous(3)

uptime_key = "start_time"
if uptime_key not in st.session_state:
    st.session_state[uptime_key] = time.time()
elapsed = int(time.time() - st.session_state[uptime_key])
uptime  = f"{elapsed//3600:02d}:{(elapsed%3600)//60:02d}:{elapsed%60:02d}"

# ── Sniffer status check ─────────────────────────────────────────────────────
def sniffer_is_running() -> bool:
    """Returns True if the sniffer process is alive (PID file exists & process lives)."""
    if not os.path.exists(SNIFFER_PID):
        return False
    try:
        with open(SNIFFER_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)   # signal 0 = existence check only
        return True
    except (ValueError, ProcessLookupError, PermissionError):
        return False

def start_sniffer():
    """Open a new Terminal window and run the sniffer via run_sniffer.sh."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(project_dir, "run_sniffer.sh")
    cmd = f"cd '{project_dir}' && bash '{script_path}'"
    apple_script = f'tell application "Terminal" to do script "{cmd}"'
    subprocess.Popen(["osascript", "-e", apple_script])



# ── Control bar (compact inline row) ─────────────────────────────────────────
_running = sniffer_is_running()

if _running:
    _status_html = (
        '<span style="background:rgba(16,185,129,.15);border:1px solid rgba(16,185,129,.4);'
        'border-radius:20px;padding:4px 12px;font-size:.75rem;font-weight:700;color:#10B981;'
        'display:inline-flex;align-items:center;gap:6px;letter-spacing:.05em;">'
        '<span style="width:7px;height:7px;background:#10B981;border-radius:50%;'
        'display:inline-block;animation:pgreen 1.5s infinite"></span>RUNNING</span>'
    )
else:
    _status_html = (
        '<span style="background:rgba(100,116,139,.1);border:1px solid rgba(100,116,139,.3);'
        'border-radius:20px;padding:4px 12px;font-size:.75rem;font-weight:700;color:#64748B;'
        'display:inline-flex;align-items:center;gap:6px;letter-spacing:.05em;">'
        '<span style="width:7px;height:7px;background:#64748B;border-radius:50%;'
        'display:inline-block"></span>STOPPED</span>'
    )

_btn_cols = st.columns([1, 1, 1, 7])
with _btn_cols[0]:
    st.markdown('<div class="start-btn">', unsafe_allow_html=True)
    if st.button("▶️ Start", key="start_btn", disabled=_running,
                 help="Launch sniffer in a new Terminal window"):
        start_sniffer()
        time.sleep(0.8)
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

with _btn_cols[1]:
    st.markdown('<div class="stop-btn">', unsafe_allow_html=True)
    if st.button("⏹️ Stop", key="stop_btn", disabled=not _running,
                 help="Signal the sniffer to stop capturing"):
        with open(STOP_FLAG, "w") as _f:
            _f.write("stop")
        time.sleep(0.5)
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

with _btn_cols[2]:
    st.markdown('<div class="reset-btn">', unsafe_allow_html=True)
    if st.button("🔄 Reset", key="reset_btn",
                 help="Clear all captured data and restart from 0"):
        clear_db()
        st.session_state[uptime_key] = time.time()
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

with _btn_cols[3]:
    st.markdown(
        f'<div style="display:flex;align-items:center;height:38px;padding-left:4px">'
        f'{_status_html}</div>',
        unsafe_allow_html=True
    )


# ── HEADER ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="nads-header">
  <div class="nads-title">
    🛡️ Network Anomaly Detection System
    <small>real-time traffic analysis</small>
  </div>
  <div class="header-right">
    <div class="live-badge"><div class="live-dot"></div> LIVE</div>
    <div class="meta-pill">⏱ Uptime <b>{uptime}</b></div>
    <div class="meta-pill">📡 Interface <b>en0</b></div>
  </div>
</div>
""", unsafe_allow_html=True)


# ── ALERT BANNERS ─────────────────────────────────────────────────────────────
for d in dangerous:
    st.markdown(
        f'<div class="alert-banner">🚨 <b>CRITICAL:</b> {d["reason"] or "Dangerous packet"} '
        f'— from <b>{d["src_ip"]}</b> → <b>{d["dst_ip"]}</b> '
        f'at {fmt_time(d["timestamp"])}</div>',
        unsafe_allow_html=True,
    )


# ── KPI CARDS ─────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="kpi-grid">
  <div class="kpi-card kpi-total">
    <div class="kpi-label">📦 Total Packets</div>
    <div class="kpi-value">{total:,}</div>
    <div class="kpi-sub">all captured packets</div>
  </div>
  <div class="kpi-card kpi-safe">
    <div class="kpi-label">✅ Safe</div>
    <div class="kpi-value">{n_safe:,}</div>
    <div class="kpi-sub">{(n_safe/total*100 if total else 0):.1f}% of traffic</div>
  </div>
  <div class="kpi-card kpi-sus">
    <div class="kpi-label">⚠️ Suspicious</div>
    <div class="kpi-value">{n_sus:,}</div>
    <div class="kpi-sub">{(n_sus/total*100 if total else 0):.1f}% of traffic</div>
  </div>
  <div class="kpi-card kpi-danger">
    <div class="kpi-label">🔴 Dangerous</div>
    <div class="kpi-value">{n_danger:,}</div>
    <div class="kpi-sub">{(n_danger/total*100 if total else 0):.1f}% of traffic</div>
  </div>
</div>
""", unsafe_allow_html=True)


# ── CHARTS ROW ────────────────────────────────────────────────────────────────
col_line, col_pie = st.columns([6, 4], gap="medium")

with col_line:
    st.markdown('<div class="chart-card"><div class="card-title">📈 Packets Per Second (Live — last 60 s)</div>', unsafe_allow_html=True)
    if pps_rows:
        df_pps = pd.DataFrame(pps_rows)
        pivot  = df_pps.pivot_table(index="second", columns="status", values="count", aggfunc="sum", fill_value=0)
        for col in ["safe", "suspicious", "dangerous"]:
            if col not in pivot.columns:
                pivot[col] = 0
        pivot = pivot.sort_index()
        xs    = [datetime.fromtimestamp(s) for s in pivot.index]

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=xs, y=pivot["safe"], name="Safe",
            fill="tozeroy", line=dict(color="#10B981", width=2),
            fillcolor="rgba(16,185,129,0.15)",
        ))
        fig.add_trace(go.Scatter(
            x=xs, y=pivot["suspicious"], name="Suspicious",
            fill="tozeroy", line=dict(color="#F59E0B", width=2),
            fillcolor="rgba(245,158,11,0.15)",
        ))
        fig.add_trace(go.Scatter(
            x=xs, y=pivot["dangerous"], name="Dangerous",
            fill="tozeroy", line=dict(color="#EF4444", width=2),
            fillcolor="rgba(239,68,68,0.15)",
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=0, r=0, t=0, b=0), height=230,
            legend=dict(orientation="h", yanchor="bottom", y=1.02,
                        font=dict(color="#94A3B8", size=11),
                        bgcolor="rgba(0,0,0,0)"),
            xaxis=dict(gridcolor="#1E2D45", tickfont=dict(color="#64748B", size=10), showline=False),
            yaxis=dict(gridcolor="#1E2D45", tickfont=dict(color="#64748B", size=10), showline=False),
            hovermode="x unified",
        )
        st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})
    else:
        st.markdown('<div class="waiting"><h3>⏳ Waiting for packets…</h3>Start the sniffer: <code>sudo python3 sniffer.py</code></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_pie:
    st.markdown('<div class="chart-card"><div class="card-title">🍩 Traffic Distribution</div>', unsafe_allow_html=True)
    if total > 0:
        fig2 = go.Figure(go.Pie(
            labels=["Safe", "Suspicious", "Dangerous"],
            values=[n_safe, n_sus, n_danger],
            hole=0.62,
            marker=dict(colors=["#10B981", "#F59E0B", "#EF4444"],
                        line=dict(color="#060B18", width=3)),
            textinfo="label+percent",
            textfont=dict(color="#CBD5E1", size=12),
            hovertemplate="<b>%{label}</b><br>%{value:,} packets<br>%{percent}<extra></extra>",
        ))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=0, b=0),
            height=230,
            legend=dict(font=dict(color="#94A3B8", size=11), bgcolor="rgba(0,0,0,0)",
                        orientation="h", yanchor="bottom", y=-0.15),
            annotations=[dict(text=f"<b>{total:,}</b><br><span style='font-size:10px'>packets</span>",
                              x=0.5, y=0.5, showarrow=False,
                              font=dict(color="#CBD5E1", size=14))],
        )
        st.plotly_chart(fig2, width='stretch', config={"displayModeBar": False})
    else:
        st.markdown('<div class="waiting"><h3>No data yet</h3></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ── BOTTOM ROW: Top IPs + Live Log ────────────────────────────────────────────
col_ips, col_log = st.columns([4, 6], gap="medium")

with col_ips:
    st.markdown('<div class="chart-card"><div class="card-title">⚠️ Top Threat IPs</div>', unsafe_allow_html=True)
    if top_ips:
        rows_html = ""
        for i, r in enumerate(top_ips, 1):
            status = r.get("worst_status", "suspicious")
            b      = badge(status)
            last   = fmt_time(r["last_seen"])
            rows_html += f"""
            <tr style="border-bottom:1px solid #0D1B2A;">
              <td style="padding:8px 6px;color:#64748B;width:28px">{i}</td>
              <td style="padding:8px 6px;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:#CBD5E1">{r['src_ip']}</td>
              <td style="padding:8px 6px;color:#EF4444;font-weight:700;text-align:center">{r['anomaly_count']}</td>
              <td style="padding:8px 6px;color:#64748B;font-size:.75rem">{last}</td>
              <td style="padding:8px 6px">{b}</td>
            </tr>"""
        st.markdown(f"""
        <table style="width:100%;border-collapse:collapse;">
          <thead><tr style="border-bottom:1px solid #1E3A5F;">
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left;letter-spacing:.06em">#</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left;letter-spacing:.06em">SOURCE IP</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:center;letter-spacing:.06em">COUNT</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left;letter-spacing:.06em">LAST SEEN</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left;letter-spacing:.06em">STATUS</th>
          </tr></thead>
          <tbody>{rows_html}</tbody>
        </table>""", unsafe_allow_html=True)
    else:
        st.markdown('<div class="waiting"><h3>No threats detected yet</h3></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_log:
    st.markdown('<div class="chart-card"><div class="card-title">🔴 Live Packet Log</div>', unsafe_allow_html=True)
    if recent:
        rows_html = ""
        for r in recent[:40]:
            b    = badge(r["status"])
            t    = fmt_time(r["timestamp"])
            proto_color = {"TCP": "#60A5FA", "UDP": "#A78BFA", "ICMP": "#34D399"}.get(r["protocol"], "#94A3B8")
            rows_html += f"""
            <tr style="border-bottom:1px solid #0D1B2A;">
              <td style="padding:7px 6px;color:#64748B;font-family:'JetBrains Mono',monospace;font-size:.75rem">{t}</td>
              <td style="padding:7px 6px;font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#CBD5E1">{r['src_ip'] or '—'}</td>
              <td style="padding:7px 6px;font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#94A3B8">{r['dst_ip'] or '—'}</td>
              <td style="padding:7px 6px"><span style="color:{proto_color};font-size:.75rem;font-weight:600">{r['protocol']}</span></td>
              <td style="padding:7px 6px;color:#94A3B8;font-size:.75rem">{r['size']} B</td>
              <td style="padding:7px 6px">{b}</td>
            </tr>"""
        st.markdown(f"""
        <div style="max-height:340px;overflow-y:auto">
        <table style="width:100%;border-collapse:collapse;">
          <thead><tr style="border-bottom:1px solid #1E3A5F;position:sticky;top:0;background:#0D1421">
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left">TIME</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left">SRC IP</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left">DST IP</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left">PROTO</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left">SIZE</th>
            <th style="padding:6px;color:#475569;font-size:.7rem;font-weight:700;text-align:left">STATUS</th>
          </tr></thead>
          <tbody>{rows_html}</tbody>
        </table></div>""", unsafe_allow_html=True)
    else:
        st.markdown('<div class="waiting"><h3>⏳ No packets yet</h3>Run <code>sudo python3 sniffer.py</code> in a second terminal.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ── AUTO-REFRESH ──────────────────────────────────────────────────────────────
time.sleep(REFRESH_INTERVAL)
st.rerun()
