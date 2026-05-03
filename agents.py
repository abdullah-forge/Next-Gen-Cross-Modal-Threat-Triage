import os
import google.generativeai as genai
from dotenv import load_dotenv
 
# Load API Key
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
 
model = None
if api_key:
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
    except Exception as e:
        print(f"Warning: Could not initialize Gemini model: {e}")
        model = None
 
 
def analyze_visuals(image):
    """Analyze an uploaded image for phishing/visual threat indicators."""
    if not model:
        return "⚠️ Vision model unavailable. Check GEMINI_API_KEY in your environment."
    if not image:
        return "No image provided for visual analysis."
 
    prompt = """You are a cybersecurity visual forensics expert.
Analyze this screenshot for phishing indicators. Look for:
- Fake login pages or spoofed UI elements
- Misaligned or low-quality logos
- Suspicious URLs or domain names visible
- Poor UI formatting, pixelation, or unusual fonts
- Receipt/invoice spoofing patterns
 
Respond ONLY in this exact format:
VERDICT: [MALICIOUS / SUSPICIOUS / BENIGN]
CONFIDENCE: [HIGH / MEDIUM / LOW]
FINDINGS: [2 sentences describing what you found]"""
 
    try:
        response = model.generate_content([prompt, image])
        return _parse_agent_response(response.text)
    except Exception as e:
        return {"verdict": "ERROR", "confidence": "N/A", "findings": f"Vision Analysis Failed: {e}"}
 
 
def analyze_linguistics(text):
    """Analyze text for social engineering and phishing language patterns."""
    if not model:
        return "⚠️ NLP model unavailable. Check GEMINI_API_KEY in your environment."
    if not text or not text.strip():
        return "No text provided for linguistic analysis."
 
    prompt = f"""You are a psychological threat analyst specializing in social engineering detection.
Analyze the following message for:
- Artificial urgency or fear tactics
- Impersonation of authority figures or brands
- Financial manipulation or reward lures
- Grammar/spelling inconsistencies typical of phishing
- Suspicious links or call-to-action patterns
 
Message to analyze:
\"\"\"{text}\"\"\"
 
Respond ONLY in this exact format:
VERDICT: [MALICIOUS / SUSPICIOUS / BENIGN]
CONFIDENCE: [HIGH / MEDIUM / LOW]
FINDINGS: [2 sentences describing the social engineering tactics found]"""
 
    try:
        response = model.generate_content(prompt)
        return _parse_agent_response(response.text)
    except Exception as e:
        return {"verdict": "ERROR", "confidence": "N/A", "findings": f"Linguistic Analysis Failed: {e}"}
 
 
def generate_firewall_rule(ip_address, attack_type):
    """Generate an iptables mitigation script for a given attacker IP."""
    if not model:
        return "# ERROR: Gemini model unavailable. Set GEMINI_API_KEY to enable this feature."
 
    prompt = f"""Act as a senior network security engineer.
A {attack_type} attack was detected from IP: {ip_address}.
 
Generate a production-ready Bash script using iptables to:
1. Immediately drop all inbound/outbound traffic from this IP
2. Log the block action to syslog
3. Make the rule persistent across reboots (using iptables-save)
4. Add a comment explaining why the IP was blocked
 
Output ONLY raw Bash code. No markdown, no backticks, no explanation."""
 
    try:
        response_text = model.generate_content(prompt).text
        # Strip any markdown code fences the model might include
        clean = response_text.replace("```bash", "").replace("```sh", "").replace("```", "").strip()
        return clean
    except Exception as e:
        return f"# Code Generation Failed: {e}"
 
 
def generate_incident_summary(visual_result, text_result, predicted_vector, predicted_risk, attacker_ip):
    """Generate a professional incident report summary using Gemini."""
    if not model:
        return "Incident summary unavailable — Gemini model not configured."
 
    # Handle both dict and string results
    visual_str = visual_result.get("findings", str(visual_result)) if isinstance(visual_result, dict) else str(visual_result)
    text_str = text_result.get("findings", str(text_result)) if isinstance(text_result, dict) else str(text_result)
 
    prompt = f"""You are a SOC (Security Operations Center) analyst writing an executive incident report.
 
THREAT DATA:
- Attacker IP: {attacker_ip}
- Predicted Attack Vector: {predicted_vector}
- Estimated Financial Risk: ${predicted_risk}k
- Visual Forensics Finding: {visual_str}
- Linguistic Analysis Finding: {text_str}
 
Write a concise 3-paragraph executive incident summary:
1. Threat overview (what happened)
2. Impact assessment (who/what is at risk)
3. Recommended immediate actions
 
Use professional security language. Be concise and actionable."""
 
    try:
        return model.generate_content(prompt).text
    except Exception as e:
        return f"Summary generation failed: {e}"
 
 
def _parse_agent_response(text):
    """Parse structured agent responses into a dict."""
    result = {"verdict": "UNKNOWN", "confidence": "LOW", "findings": text}
    try:
        lines = text.strip().split("\n")
        for line in lines:
            if line.startswith("VERDICT:"):
                result["verdict"] = line.replace("VERDICT:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                result["confidence"] = line.replace("CONFIDENCE:", "").strip()
            elif line.startswith("FINDINGS:"):
                result["findings"] = line.replace("FINDINGS:", "").strip()
    except Exception:
        pass
    return result
