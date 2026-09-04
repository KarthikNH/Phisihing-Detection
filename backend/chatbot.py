import os
import json

def generate_chatbot_response(user_query: str, analysis_context: dict = None) -> dict:
    """
    PHISHGUARD AI Threat Intelligence Assistant.
    Understands current URL scan context and answers cybersecurity queries.
    Uses Gemini API if GEMINI_API_KEY is configured, else executes local Security Analyst Engine fallback.
    """
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    
    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
You are PHISHGUARD AI, an expert cybersecurity analyst assistant.
User Query: "{user_query}"

Current URL Scan Context:
{json.dumps(analysis_context, indent=2) if analysis_context else "No active URL scan context."}

Instructions:
1. Explain why the URL was flagged or declared safe based on features.
2. Reference the ML phishing probability, anomaly score, and risk level.
3. Provide clear, actionable security steps.
"""
            res = model.generate_content(prompt)
            return {
                "response": res.text,
                "engine": "Gemini 1.5 Flash (Cloud LLM)",
                "is_fallback": False
            }
        except Exception:
            pass

    # ----------------------------------------------------
    # LOCAL SECURITY ANALYST FALLBACK ENGINE
    # ----------------------------------------------------
    if not analysis_context:
        return {
            "response": (
                "### 🛡️ PHISHGUARD AI Analyst\n\n"
                "I am ready to assist you. Please enter a web link in the target scanner above and click **ANALYZE THREAT →**.\n\n"
                "Once analyzed, I will break down the **risk score**, **phishing probability**, **Isolation Forest anomaly index**, and **flagged feature indicators** for your target URL."
            ),
            "engine": "PhishGuard Security Analyst (Local Rule Engine)",
            "is_fallback": True
        }
        
    url = analysis_context.get('url', 'Target URL')
    risk_score = analysis_context.get('risk_score', 0)
    risk_level = str(analysis_context.get('risk_level', 'UNKNOWN')).upper()
    
    raw_prob = analysis_context.get('phishing_probability', 0)
    try:
        phish_prob = float(raw_prob) * 100.0 if float(raw_prob) <= 1.0 else float(raw_prob)
    except (ValueError, TypeError):
        phish_prob = 0.0
        
    try:
        anomaly_score = float(analysis_context.get('anomaly_score', 0) or 0)
    except (ValueError, TypeError):
        anomaly_score = 0.0
        
    reasons = analysis_context.get('reasons', []) or []
    features = analysis_context.get('features', {}) or {}
    
    pred_val = analysis_context.get('prediction_label') or analysis_context.get('prediction') or 'Unknown'
    prediction_label = str(pred_val).title()
    
    query_lower = user_query.lower()
    
    # 1. Why flagged / reasons
    if "why" in query_lower or "flag" in query_lower or "reason" in query_lower or "threat" in query_lower:
        section_reasons = "\n".join([f"• **{r}**" for r in reasons]) if reasons else "• No active threat flags detected."
        reply = (
            f"### 🔍 Threat Analysis Breakdown for `{url}`\n\n"
            f"**Overall Assessment:** **{risk_level} RISK** ({risk_score}/100 Composite Score)\n"
            f"**Model Verdict:** `{prediction_label}` ({phish_prob:.1f}% Phishing Probability)\n\n"
            f"**Key Flagged Factors:**\n{section_reasons}\n\n"
            f"**Extracted Lexical Indicators:**\n"
            f"- **Domain Length:** `{features.get('DomainLength', 'N/A')} chars` | **Subdomains:** `{int(features.get('NoOfSubDomain', 0))}`\n"
            f"- **Entropy Score:** `{features.get('Entropy', 0):.2f}` | **HTTPS Encryption:** `{'YES' if features.get('IsHTTPS') == 1 else 'NO (Insecure)'}`\n"
            f"- **Suspicious Keywords:** `{int(features.get('SuspiciousKeywordCount', 0))}` | **Obfuscation Chars:** `{int(features.get('NoOfObfuscatedChar', 0))}`"
        )
    # 2. What should I do / advice
    elif "do" in query_lower or "action" in query_lower or "should" in query_lower or "recommend" in query_lower:
        if risk_level in ["HIGH", "CRITICAL"]:
            actions = (
                "1. 🚫 **DO NOT VISIT THIS LINK**: Do not enter credentials, passwords, or payment details.\n"
                "2. 🛡️ **Report Security Incident**: Forward this URL to your IT/SOC security department.\n"
                "3. 🔑 **Credential Safety**: If you already visited or entered credentials, change your passwords immediately and enable Multi-Factor Authentication (MFA)."
            )
        elif risk_level == "MEDIUM":
            actions = (
                "1. ⚠️ **Exercise Extreme Caution**: Verify sender authenticity before interacting.\n"
                "2. 🔒 **Check Address Bar**: Ensure official domain spelling and valid SSL lock.\n"
                "3. ❌ **Avoid Credential Input**: Do not submit sensitive forms."
            )
        else:
            actions = (
                "1. ✅ **Safe to Proceed**: This URL exhibits standard lexical patterns and zero suspicious flags.\n"
                "2. 🔒 **Standard Hygiene**: Always verify HTTPS encryption before logging in."
            )
            
        reply = (
            f"### 📋 Recommended Action Plan for `{url}`\n\n"
            f"**Risk Severity:** **{risk_level}**\n\n"
            f"**Action Steps:**\n{actions}"
        )
    # 3. Anomaly score explanation
    elif "anomaly" in query_lower or "isolation" in query_lower or "forest" in query_lower:
        reply = (
            f"### 🧪 Isolation Forest Anomaly Index Breakdown\n\n"
            f"**Target URL:** `{url}`\n"
            f"**Isolation Forest Anomaly Score:** **{anomaly_score:.2f}** (Scale: 0.00 = Normal, 1.00 = Highly Anomalous)\n\n"
            f"**How It Works:**\n"
            f"Isolation Forest evaluates structural URL string patterns against thousands of legitimate baseline websites. " + (
                "This URL exhibits **high structural anomaly**, indicating atypical character distributions, excessive subdomain layering, or unusual tokenization common in zero-day phishing spoofs."
                if anomaly_score >= 0.50 else
                "This URL falls within the expected structural distribution of verified legitimate domains."
            )
        )
    # 4. Is safe check
    elif "safe" in query_lower or "legitimate" in query_lower or "clean" in query_lower:
        if risk_level in ["HIGH", "CRITICAL"]:
            reply = (
                f"### ❌ NO, THIS LINK IS NOT SAFE!\n\n"
                f"The target `{url}` has been classified as **{prediction_label.upper()}** with a **{risk_level} RISK** level ({risk_score}/100).\n"
                f"Classifier indicates a **{phish_prob:.1f}%** probability of phishing threat. Avoid interacting with this link."
            )
        else:
            reply = (
                f"### ✅ YES, THIS LINK APPEARS SAFE\n\n"
                f"The target `{url}` is classified as **LEGITIMATE** with a **{risk_level} RISK** score of **{risk_score}/100**.\n"
                f"Phishing probability is extremely low (**{phish_prob:.1f}%**) and structure matches normal web domain conventions."
            )
    else:
        # Default comprehensive threat summary
        reasons_formatted = "\n".join([f"• {r}" for r in reasons]) if reasons else "• Standard baseline parameters."
        reply = (
            f"### 🛡️ PHISHGUARD Threat Intelligence Summary\n\n"
            f"**Target Link:** `{url}`\n"
            f"**Composite Risk Index:** **{risk_score}/100** ({risk_level} RISK)\n"
            f"**ML Classifier Probability:** **{phish_prob:.1f}%** ({prediction_label})\n"
            f"**Anomaly Index:** **{anomaly_score:.2f}**\n\n"
            f"**Triggered Threat Signals:**\n{reasons_formatted}\n\n"
            f"**Guidance:** " + (
                "⚠️ **HIGH DANGER**: Do not visit or enter credentials on this site."
                if risk_level in ["HIGH", "CRITICAL"] else
                "✅ **SAFE**: Link passes machine learning and anomaly detection checks."
            )
        )
        
    return {
        "response": reply,
        "engine": "PhishGuard Security Analyst (Local Rule Engine)",
        "is_fallback": True
    }
