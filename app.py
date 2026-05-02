import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
from PIL import Image
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LinearRegression
from agents import analyze_visuals, analyze_linguistics, generate_firewall_rule

# --- Page Configuration ---
st.set_page_config(page_title="SOC Triage Dashboard", layout="wide", page_icon="🛡️")

# --- SELF-HEALING MODEL LOADER ---
@st.cache_resource
def load_models():
    try:
        rf_model = joblib.load('models/rf_attack_vector.pkl')
        mlr_model = joblib.load('models/mlr_risk_score.pkl')
        return rf_model, mlr_model
    except FileNotFoundError:
        # FIXED: Using a safe background print instead of UI toast to avoid CacheReplayClosureError
        print("⚠️ Models not found! Auto-generating new models in the background...")
        
        # 1. Generate Mock Data
        np.random.seed(42)
        n_samples = 200
        data = {
            'Domain_Age_Days': np.random.randint(1, 3000, n_samples),
            'Sender_IP_Reputation': np.random.randint(1, 100, n_samples),
            'Time_of_Day_Hour': np.random.randint(0, 24, n_samples),
            'Target_Clearance_Level': np.random.randint(1, 6, n_samples),
            'Attack_Vector': np.random.choice(['Mass Spam', 'Spear Phishing', 'Whaling'], n_samples),
            'Financial_Risk_Score': np.random.randint(10, 100, n_samples)
        }
        df = pd.DataFrame(data)

        # 2. Train Models
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(df[['Domain_Age_Days', 'Sender_IP_Reputation', 'Time_of_Day_Hour', 'Target_Clearance_Level']], df['Attack_Vector'])

        mlr_model = LinearRegression()
        mlr_model.fit(df[['Domain_Age_Days', 'Sender_IP_Reputation', 'Target_Clearance_Level']], df['Financial_Risk_Score'])

        # 3. Save for later
        os.makedirs("models", exist_ok=True)
        joblib.dump(rf_model, 'models/rf_attack_vector.pkl')
        joblib.dump(mlr_model, 'models/mlr_risk_score.pkl')
        
        return rf_model, mlr_model

# Load the models (this will now auto-train if missing seamlessly)
rf_model, mlr_model = load_models()

# --- Main Dashboard UI ---
st.title("🛡️ Next-Gen Cross-Modal Threat Triage")
st.markdown("Autonomous multi-agent SOC dashboard for detecting zero-day phishing.")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("1. Threat Input")
    uploaded_file = st.file_uploader("Upload Suspicious Screenshot", type=["png", "jpg", "jpeg"])
    phishing_text = st.text_area("Paste Suspicious Text (Email/SMS)", height=150)
    
    st.markdown("---")
    st.header("2. Network Metadata")
    domain_age = st.slider("Domain Age (Days)", 1, 3000, 15)
    ip_rep = st.slider("Sender IP Reputation (1-100)", 1, 100, 20)
    clearance = st.selectbox("Target Employee Clearance Level", [1, 2, 3, 4, 5])
    time_of_day = st.slider("Time of Day (Hour)", 0, 23, 2)
    
    attacker_ip = "192.168.105.1"
    
    analyze_btn = st.button("🚀 Run Multi-Agent Triage", use_container_width=True)

with col2:
    st.header("Triage Results")
    if analyze_btn:
        if not phishing_text and not uploaded_file:
            st.warning("Please upload an image or enter text to analyze.")
        else:
            img_to_analyze = None
            if uploaded_file is not None:
                img_to_analyze = Image.open(uploaded_file)
                st.image(img_to_analyze, caption="Evidence Logged", width=250)

            with st.spinner("Agents are analyzing the threat..."):
                visual_report = analyze_visuals(img_to_analyze) if img_to_analyze else "No visual data provided."
                text_report = analyze_linguistics(phishing_text) if phishing_text else "No text data provided."
                
                predicted_vector = "Unknown"
                predicted_risk = 0
                
                if rf_model and mlr_model:
                    input_rf = pd.DataFrame([[domain_age, ip_rep, time_of_day, clearance]], 
                                            columns=['Domain_Age_Days', 'Sender_IP_Reputation', 'Time_of_Day_Hour', 'Target_Clearance_Level'])
                    input_mlr = pd.DataFrame([[domain_age, ip_rep, clearance]], 
                                             columns=['Domain_Age_Days', 'Sender_IP_Reputation', 'Target_Clearance_Level'])
                    
                    predicted_vector = rf_model.predict(input_rf)[0]
                    predicted_risk = abs(int(mlr_model.predict(input_mlr)[0]))
                
                mitigation_code = generate_firewall_rule(attacker_ip, predicted_vector)

            st.subheader("📊 Threat Assessment")
            metric_col1, metric_col2 = st.columns(2)
            metric_col1.metric("Predicted Attack Vector", predicted_vector)
            metric_col2.metric("Financial Risk Score", f"${predicted_risk}k")
            
            st.markdown("---")
            st.subheader("👁️ Agent Forensics")
            st.info(f"**Visual Agent:** {visual_report}")
            st.warning(f"**Linguistic Agent:** {text_report}")
            
            st.markdown("---")
            st.subheader("🛡️ Automated Mitigation Script")
            st.code(mitigation_code, language="bash")
            st.success("Firewall rule successfully generated by the Mitigation Agent.")
