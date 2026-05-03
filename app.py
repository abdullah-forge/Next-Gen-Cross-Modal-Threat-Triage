import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
from PIL import Image
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LinearRegression
from agents import analyze_visuals, analyze_linguistics, generate_firewall_rule, generate_incident_summary
 
st.set_page_config(
    page_title="SOC Triage Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)
 
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; background: #060b12; color: #cdd6f4; }
.stApp { background: #060b12; }
.top-bar { display:flex; align-items:center; justify-content:space-between; padding:0.9rem 1.5rem; background:linear-gradient(90deg,#0b1623,#0d1e35); border-bottom:1px solid #1a2d4a; margin:-4rem -4rem 1.5rem -4rem; }
.top-bar-left { display:flex; align-items:center; gap:12px; }
.top-bar-logo { width:36px; height:36px; background:linear-gradient(135deg,#1e40af,#3b82f6); border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:18px; }
.top-bar-title { font-family:'JetBrains Mono',monospace; font-size:0.9rem; font-weight:600; color:#e2e8f0; letter-spacing:1.5px; text-transform:uppercase; }
.top-bar-sub { font-size:0.65rem; color:#4a6080; letter-spacing:1px; text-transform:uppercase; }
.top-bar-right { display:flex; align-items:center; gap:12px; }
.status-pill { display:flex; align-items:center; gap:6px; background:rgba(0,200,100,0.08); border:1px solid rgba(0,200,100,0.2); border-radius:20px; padding:3px 10px; font-size:0.65rem; color:#00c864; letter-spacing:1.5px; font-family:'JetBrains Mono',monospace; }
.status-dot { width:6px; height:6px; border-radius:50%; background:#00c864; animation:blink 1.5s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.version-tag { font-size:0.62rem; color:#2d4a6b; font-family:'JetBrains Mono',monospace; letter-spacing:1px; }
section[data-testid="stSidebar"] { background:#080e18 !important; border-right:1px solid #111e30; }
section[data-testid="stSidebar"] > div { padding-top:1rem; }
.sidebar-section-title { font-family:'JetBrains Mono',monospace; font-size:0.65rem; color:#3b82f6; letter-spacing:2px; text-transform:uppercase; margin-bottom:0.8rem; }
.panel { background:#0b1622; border:1px solid #142033; border-radius:10px; padding:1.2rem 1.4rem; margin-bottom:1rem; position:relative; overflow:hidden; }
.panel::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,#1e40af,#3b82f6,transparent); }
.panel-title { font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#3b82f6; letter-spacing:2px; text-transform:uppercase; margin-bottom:1rem; }
.metrics-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:1.2rem; }
.metric-tile { background:#0b1622; border:1px solid #142033; border-radius:8px; padding:0.9rem 1rem; position:relative; overflow:hidden; }
.metric-tile::after { content:''; position:absolute; bottom:0; left:0; right:0; height:2px; }
.metric-tile.blue::after { background:#3b82f6; }
.metric-tile.red::after { background:#ef4444; }
.metric-tile.amber::after { background:#f59e0b; }
.metric-tile.green::after { background:#10b981; }
.metric-label { font-size:0.62rem; color:#3d5a7a; letter-spacing:1.5px; text-transform:uppercase; font-family:'JetBrains Mono',monospace; margin-bottom:6px; }
.metric-value { font-family:'JetBrains Mono',monospace; font-size:1.3rem; font-weight:600; color:#e2e8f0; line-height:1; }
.metric-sub { font-size:0.65rem; color:#2d4a6b; margin-top:4px; font-family:'JetBrains Mono',monospace; }
.verdict-wrap { display:flex; align-items:center; gap:10px; margin:0.6rem 0; }
.verdict-badge { font-family:'JetBrains Mono',monospace; font-size:0.7rem; font-weight:600; letter-spacing:1.5px; padding:4px 12px; border-radius:4px; }
.badge-MALICIOUS  { background:rgba(239,68,68,0.15);  color:#f87171; border:1px solid rgba(239,68,68,0.3); }
.badge-SUSPICIOUS { background:rgba(245,158,11,0.15); color:#fbbf24; border:1px solid rgba(245,158,11,0.3); }
.badge-BENIGN     { background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); }
.badge-UNKNOWN, .badge-ERROR { background:rgba(100,116,139,0.15); color:#94a3b8; border:1px solid rgba(100,116,139,0.3); }
.conf-badge { font-size:0.62rem; color:#3d5a7a; font-family:'JetBrains Mono',monospace; letter-spacing:1px; border:1px solid #142033; padding:3px 8px; border-radius:3px; }
.findings-text { font-size:0.83rem; color:#8ba3bf; line-height:1.6; margin-top:0.5rem; padding:0.6rem 0.8rem; background:#060b12; border-left:2px solid #1e3a5f; border-radius:0 4px 4px 0; }
.risk-track { background:#0d1825; border-radius:3px; height:4px; margin-top:6px; overflow:hidden; }
.risk-fill { height:4px; border-radius:3px; }
.welcome-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-top:1.2rem; }
.agent-card { background:#0b1622; border:1px solid #142033; border-radius:8px; padding:1.1rem; }
.agent-icon { font-size:1.5rem; margin-bottom:0.6rem; }
.agent-name { font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#3b82f6; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:0.4rem; }
.agent-desc { font-size:0.8rem; color:#3d5a7a; line-height:1.5; }
.instruction-row { display:flex; align-items:flex-start; gap:12px; padding:0.5rem 0; border-bottom:1px solid #0d1825; }
.instruction-row:last-child { border-bottom:none; }
.step-num { font-family:'JetBrains Mono',monospace; font-size:0.65rem; color:#3b82f6; background:rgba(59,130,246,0.1); border:1px solid rgba(59,130,246,0.2); width:22px; height:22px; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0; margin-top:2px; }
.step-text { font-size:0.83rem; color:#4a6b8a; line-height:1.5; }
.step-text strong { color:#6b90b0; }
.evidence-label { font-family:'JetBrains Mono',monospace; font-size:0.6rem; color:#2d4a6b; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:4px; }
.text-evidence { font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#3d5a7a; background:#060b12; border:1px solid #0d1825; border-radius:6px; padding:0.7rem; max-height:110px; overflow-y:auto; line-height:1.6; white-space:pre-wrap; word-break:break-word; }
.incident-text { font-size:0.83rem; color:#7a9ab8; line-height:1.8; }
.success-line { font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#10b981; letter-spacing:1px; margin-top:0.5rem; }
div.stButton > button { background:linear-gradient(135deg,#1e3a6e,#1d4ed8) !important; color:#bfdbfe !important; border:1px solid #2563eb !important; border-radius:6px !important; font-family:'JetBrains Mono',monospace !important; font-size:0.78rem !important; letter-spacing:1.5px !important; font-weight:600 !important; padding:0.65rem 1rem !important; text-transform:uppercase !important; }
div.stButton > button:hover { background:linear-gradient(135deg,#1d4ed8,#2563eb) !important; color:#fff !important; }
.stTextArea textarea { background:#060b12 !important; border:1px solid #142033 !important; border-radius:6px !important; color:#8ba3bf !important; font-family:'JetBrains Mono',monospace !important; font-size:0.78rem !important; }
.stFileUploader > div { background:#060b12 !important; border:1px dashed #1a2d4a !important; border-radius:6px !important; }
.stSelectbox > div > div { background:#060b12 !important; border:1px solid #142033 !important; color:#8ba3bf !important; }
.stSlider > div > div > div { background:#1d4ed8 !important; }
label, .stSlider label { color:#3d5a7a !important; font-size:0.72rem !important; }
.stCodeBlock { background:#060b12 !important; border:1px solid #142033 !important; border-radius:6px !important; }
hr { border-color:#0d1825 !important; }
[data-testid="stDownloadButton"] > button { background:transparent !important; border:1px solid #1a2d4a !important; color:#4a6b8a !important; font-size:0.72rem !important; letter-spacing:1px !important; }
[data-testid="stDownloadButton"] > button:hover { border-color:#3b82f6 !important; color:#3b82f6 !important; }
</style>
""", unsafe_allow_html=True)
 
st.markdown("""
<div class="top-bar">
  <div class="top-bar-left">
    <div class="top-bar-logo">🛡️</div>
    <div>
      <div class="top-bar-title">SOC Triage Command Center</div>
      <div class="top-bar-sub">Next-Gen Cross-Modal Threat Intelligence Platform</div>
    </div>
  </div>
  <div class="top-bar-right">
    <span class="version-tag">v2.1.0</span>
    <div class="status-pill"><div class="status-dot"></div>SYSTEM ONLINE</div>
  </div>
</div>
""", unsafe_allow_html=True)
 
 
@st.cache_resource
def load_models():
    try:
        rf  = joblib.load('models/rf_attack_vector.pkl')
        mlr = joblib.load('models/mlr_risk_score.pkl')
        return rf, mlr
    except FileNotFoundError:
        np.random.seed(42)
        n = 500
        df = pd.DataFrame({
            'Domain_Age_Days':        np.random.randint(1, 3000, n),
            'Sender_IP_Reputation':   np.random.randint(1, 100, n),
            'Time_of_Day_Hour':       np.random.randint(0, 24, n),
            'Target_Clearance_Level': np.random.randint(1, 6, n),
            'Attack_Vector':          np.random.choice(['Mass Spam','Spear Phishing','Whaling'], n),
            'Financial_Risk_Score':   np.random.randint(10, 100, n),
        })
        rf = RandomForestClassifier(n_estimators=150, random_state=42)
        rf.fit(df[['Domain_Age_Days','Sender_IP_Reputation','Time_of_Day_Hour','Target_Clearance_Level']], df['Attack_Vector'])
        mlr = LinearRegression()
        mlr.fit(df[['Domain_Age_Days','Sender_IP_Reputation','Target_Clearance_Level']], df['Financial_Risk_Score'])
        os.makedirs("models", exist_ok=True)
        joblib.dump(rf,  'models/rf_attack_vector.pkl')
        joblib.dump(mlr, 'models/mlr_risk_score.pkl')
        return rf, mlr
 
rf_model, mlr_model = load_models()
 
with st.sidebar:
    st.markdown('<div class="sidebar-section-title">📥 Threat Input</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload Suspicious Screenshot", type=["png","jpg","jpeg"])
    phishing_text = st.text_area("Paste Suspicious Email / SMS / URL", height=130,
                                  placeholder="e.g. Dear user, your account will be suspended...\nVerify now: http://secure-login-xyz.com")
    st.markdown("---")
    st.markdown('<div class="sidebar-section-title">🌐 Network Metadata</div>', unsafe_allow_html=True)
    domain_age  = st.slider("Domain Age (Days)", 1, 3000, 15)
    ip_rep      = st.slider("Sender IP Reputation (1–100)", 1, 100, 20)
    clearance   = st.selectbox("Target Clearance Level", [1,2,3,4,5],
                                format_func=lambda x: f"L{x} — {'Executive' if x==5 else 'Senior Mgr' if x==4 else 'Mid-level' if x==3 else 'Junior' if x==2 else 'Intern'}")
    time_of_day = st.slider("Time Received (24h)", 0, 23, 2)
    attacker_ip = st.text_input("Attacker / Sender IP", value="192.168.105.1")
    st.markdown("---")
    analyze_btn = st.button("🚀  RUN MULTI-AGENT TRIAGE", use_container_width=True)
 
 
def verdict_block(result):
    if not isinstance(result, dict):
        return f'<div class="findings-text">{result}</div>'
    v = result.get("verdict","UNKNOWN")
    c = result.get("confidence","—")
    f = result.get("findings","No findings.")
    cls = f"badge-{v}" if v in ["MALICIOUS","SUSPICIOUS","BENIGN"] else "badge-UNKNOWN"
    return f'<div class="verdict-wrap"><span class="verdict-badge {cls}">{v}</span><span class="conf-badge">CONF: {c}</span></div><div class="findings-text">{f}</div>'
 
def risk_bar(score):
    color = "#ef4444" if score>=70 else "#f59e0b" if score>=40 else "#10b981"
    return f'<div class="risk-track"><div class="risk-fill" style="width:{min(score,100)}%;background:{color}"></div></div>'
 
def tile_color(score):
    return "red" if score>=70 else "amber" if score>=40 else "green"
 
 
if not analyze_btn:
    st.markdown("""
    <div class="panel">
      <div class="panel-title">◈ System Ready — Awaiting Threat Input</div>
      <div class="instruction-row"><div class="step-num">1</div><div class="step-text">Upload a <strong>suspicious screenshot</strong> in the sidebar (optional)</div></div>
      <div class="instruction-row"><div class="step-num">2</div><div class="step-text">Paste any <strong>suspicious email, SMS, or URL</strong> text (optional)</div></div>
      <div class="instruction-row"><div class="step-num">3</div><div class="step-text">Configure <strong>network metadata</strong> using the sliders</div></div>
      <div class="instruction-row"><div class="step-num">4</div><div class="step-text">Enter the <strong>attacker IP address</strong> for firewall rule generation</div></div>
      <div class="instruction-row"><div class="step-num">5</div><div class="step-text">Click <strong>RUN MULTI-AGENT TRIAGE</strong> to launch all agents</div></div>
    </div>
    <div class="welcome-grid">
      <div class="agent-card"><div class="agent-icon">👁️</div><div class="agent-name">Visual Forensics</div><div class="agent-desc">Gemini Vision detects spoofed UIs, fake login pages, logo manipulation, and suspicious URL patterns in screenshots.</div></div>
      <div class="agent-card"><div class="agent-icon">🧠</div><div class="agent-name">Linguistic Analysis</div><div class="agent-desc">NLP model identifies social engineering, artificial urgency, authority impersonation, and financial manipulation in text.</div></div>
      <div class="agent-card"><div class="agent-icon">🛡️</div><div class="agent-name">Mitigation Agent</div><div class="agent-desc">Generates production-ready iptables firewall scripts to block attacker infrastructure. Always review before deploying.</div></div>
    </div>
    """, unsafe_allow_html=True)
 
else:
    if not phishing_text and not uploaded_file:
        st.error("⚠️ Provide at least one input — upload a screenshot or paste suspicious text.")
        st.stop()
 
    inp_rf  = pd.DataFrame([[domain_age, ip_rep, time_of_day, clearance]],
                            columns=['Domain_Age_Days','Sender_IP_Reputation','Time_of_Day_Hour','Target_Clearance_Level'])
    inp_mlr = pd.DataFrame([[domain_age, ip_rep, clearance]],
                            columns=['Domain_Age_Days','Sender_IP_Reputation','Target_Clearance_Level'])
    predicted_vector = rf_model.predict(inp_rf)[0]
    predicted_risk   = max(0, int(mlr_model.predict(inp_mlr)[0]))
    img_obj = Image.open(uploaded_file) if uploaded_file else None
 
    with st.spinner("🔍 Multi-agent analysis in progress..."):
        visual_result    = analyze_visuals(img_obj)           if img_obj        else None
        text_result      = analyze_linguistics(phishing_text) if phishing_text  else None
        firewall_code    = generate_firewall_rule(attacker_ip, predicted_vector)
        incident_summary = generate_incident_summary(visual_result, text_result, predicted_vector, predicted_risk, attacker_ip)
 
    clearance_label = {5:'Executive',4:'Senior Mgr',3:'Mid-level',2:'Junior',1:'Intern'}.get(clearance,'')
    st.markdown(f"""
    <div class="metrics-grid">
      <div class="metric-tile blue">
        <div class="metric-label">Attack Vector</div>
        <div class="metric-value" style="font-size:0.95rem;">{predicted_vector}</div>
        <div class="metric-sub">ML Classification</div>
      </div>
      <div class="metric-tile {tile_color(predicted_risk)}">
        <div class="metric-label">Financial Risk</div>
        <div class="metric-value">${predicted_risk}k</div>
        {risk_bar(predicted_risk)}
      </div>
      <div class="metric-tile amber">
        <div class="metric-label">Attacker IP</div>
        <div class="metric-value" style="font-size:0.9rem;">{attacker_ip}</div>
        <div class="metric-sub">Flagged Source</div>
      </div>
      <div class="metric-tile blue">
        <div class="metric-label">Target Clearance</div>
        <div class="metric-value">L{clearance}</div>
        <div class="metric-sub">{clearance_label}</div>
      </div>
    </div>
    """, unsafe_allow_html=True)
 
    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="panel"><div class="panel-title">👁️ Visual Forensics Agent</div>', unsafe_allow_html=True)
        if img_obj:
            st.image(img_obj, width=600, caption="Evidence submitted")
            if visual_result:
                st.markdown(verdict_block(visual_result), unsafe_allow_html=True)
        else:
            st.markdown('<p style="color:#2d4a6b;font-size:0.82rem;font-family:JetBrains Mono,monospace;">— No image submitted —</p>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
 
    with col2:
        st.markdown('<div class="panel"><div class="panel-title">🧠 Linguistic Analysis Agent</div>', unsafe_allow_html=True)
        if phishing_text:
            st.markdown(f'<div class="evidence-label">Submitted Text</div><div class="text-evidence">{phishing_text[:600]}{"..." if len(phishing_text)>600 else ""}</div>', unsafe_allow_html=True)
            if text_result:
                st.markdown(verdict_block(text_result), unsafe_allow_html=True)
        else:
            st.markdown('<p style="color:#2d4a6b;font-size:0.82rem;font-family:JetBrains Mono,monospace;">— No text submitted —</p>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
 
    col3, col4 = st.columns(2)
    with col3:
        st.markdown('<div class="panel"><div class="panel-title">🛡️ Auto-Generated Mitigation Script</div>', unsafe_allow_html=True)
        st.code(firewall_code, language="bash")
        st.markdown('<div class="success-line">✓ Rule generated — review before deploying to production</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
 
    with col4:
        st.markdown('<div class="panel"><div class="panel-title">📋 Executive Incident Report</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="incident-text">{incident_summary}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
 
    v_str = visual_result.get("findings","N/A") if isinstance(visual_result, dict) else str(visual_result or "N/A")
    t_str = text_result.get("findings","N/A")   if isinstance(text_result,  dict) else str(text_result  or "N/A")
    report = f"""SOC TRIAGE — INCIDENT REPORT
{"="*50}
Timestamp:       {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Attacker IP:     {attacker_ip}
Attack Vector:   {predicted_vector}
Financial Risk:  ${predicted_risk}k
Domain Age:      {domain_age} days
IP Reputation:   {ip_rep}/100
Target Level:    {clearance}
Time of Attack:  {time_of_day:02d}:00
 
VISUAL FORENSICS:
{v_str}
 
LINGUISTIC ANALYSIS:
{t_str}
 
EXECUTIVE SUMMARY:
{incident_summary}
 
FIREWALL MITIGATION SCRIPT:
{firewall_code}
{"="*50}
"""
    st.download_button(
        label="⬇️  Download Full Incident Report (.txt)",
        data=report,
        file_name=f"soc_incident_{attacker_ip.replace('.','_')}.txt",
        mime="text/plain",
        use_container_width=True,
    )
