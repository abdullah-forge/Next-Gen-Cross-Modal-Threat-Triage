import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load API Key
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

# Initialize the Gemini Model
try:
    model = genai.GenerativeModel('gemini-2.5-flash')
except Exception as e:
    model = None

def analyze_visuals(image):
    if not model or not image: 
        return "System Error: Vision model unavailable."
    
    prompt = """You are a cybersecurity visual forensics expert. 
    Analyze this screenshot. Is it a fake login page, a spoofed receipt, or a phishing attempt? 
    Look for pixelation, misaligned logos, weird URLs, or poor UI formatting. 
    Keep your analysis strictly to 2 short sentences."""
    
    try: 
        return model.generate_content([prompt, image]).text
    except Exception as e: 
        return f"Vision Analysis Failed: {e}"

def analyze_linguistics(text):
    if not model or not text: 
        return "System Error: NLP model unavailable."
    
    prompt = f"""You are a psychological threat analyst. 
    Analyze the following message for social engineering, artificial urgency, and financial manipulation tactics. 
    Message: '{text}'. 
    Keep your analysis strictly to 2 short sentences."""
    
    try: 
        return model.generate_content(prompt).text
    except Exception as e: 
        return f"Linguistic Analysis Failed: {e}"

def generate_firewall_rule(ip_address, attack_type):
    if not model: 
        return "# System Error: Model unavailable."
    
    prompt = f"""Act as a senior network security engineer. 
    We just detected a {attack_type} attack originating from IP: {ip_address}. 
    Write a Bash script using 'iptables' to permanently drop all traffic from this IP. 
    Only output the raw code, no markdown formatting or explanations."""
    
    try: 
        response_text = model.generate_content(prompt).text
        # Clean up markdown formatting for the UI
        clean_text = response_text.replace("```bash", "").replace("```", "").strip()
        return clean_text
    except Exception as e: 
        return f"# Code Generation Failed: {e}"
