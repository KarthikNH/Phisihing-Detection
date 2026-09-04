import os
import json

def generate_chatbot_response(user_query: str, analysis_context: dict = None) -> dict:
    """
    PhishGuard AI Chat Assistant.
    Provides context-aware security advice based on current URL analysis.
    Uses LLM API if GEMINI_API_KEY is configured, else falls back to local Security Analyst Engine.
    """
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    
    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
You are PHISHGUARD AI, an expert cybersecurity assistant specializing in phishing URL detection and threat analysis.
User Query: "{user_query}"

Current URL Scan Context:
{json.dumps(analysis_context, indent=2) if analysis_context else "No active URL scan context."}

Provide a concise, professional, clear response explaining:
1. Threat summary of the URL
2. Why it was flagged (or declared safe) based on features
3. Anomaly and Phishing score breakdown
4. Actionable steps the user should take immediately.
"""
            res = model.generate_content(prompt)
            return {
                "response": res.text,
                "engine": "Gemini 1.5 Flash (Cloud LLM)",
                "is_fallback": False
            }
        except Exception as e:
            # Fall back cleanly if cloud call fails
            pass

    # ----------------------------------------------------
    # LOCAL FALLBACK ENGINE (Rule-based Security Analyst Engine)
    # Transparently identified as rule-based fallback, not claimed to be ML.
    # ----------------------------------------------------
    if not analysis_context:
        return {
            "response": "Hello! I am PHISHGUARD AI. Please enter a URL above and click Analyze. I will explain the risk score, anomaly metrics, flagged features, and recommended security actions for your link.",
            "engine": "PhishGuard Rule-Based Analyst (Local Fallback)",
            "is_fallback": True
        }
        
    url = analysis_context.get('url', 'Unknown URL')
    risk_score = analysis_context.get('risk_score', 0)
    risk_level = analysis_context.get('risk_level', 'UNKNOWN')
    phish_prob = analysis_context.get('phishing_probability', 0) * 100
    anomaly_score = analysis_context.get('anomaly_score', 0)
    reasons = analysis_context.get('reasons', [])
    features = analysis_context.get('features', {})
    
    query_lower = user_query.lower()
    
    # Custom query matching
    if "why" in query_lower or "flag" in query_lower or "reason" in query_lower:
        section_reasons = "\n".join([f"• {r}" for r in reasons])
        reply = (
            f"### Threat Analysis for `{url}`\n\n"
            f"**Risk Level:** {risk_level} (Score: {risk_score}/100)\n\n"
            f"**Key Flagged Factors:**\n{section_reasons}\n\n"
            f"**Technical Details:**\n"
            f"- **Domain Length:** {features.get('DomainLength', 'N/A')} chars\n"
            f"- **Suspicious Keywords:** {int(features.get('SuspiciousKeywordCount', 0))}\n"
            f"- **Subdomains:** {int(features.get('NoOfSubDomain', 0))}\n"
            f"- **Entropy:** {features.get('Entropy', 0):.2f}\n"
        )
    elif "action" in query_lower or "do" in query_lower or "should" in query_lower or "safe" in query_lower:
        if risk_level in ["HIGH", "CRITICAL"]:
            actions = (
                "1. **DO NOT VISIT THIS LINK**: Do not enter credentials, credit cards, or passwords.\n"
                "2. **Report Link**: Forward to your organization's IT security team or abuse@domain.\n"
                "3. **Clear Session**: If you already clicked, change your passwords immediately and activate Multi-Factor Authentication (MFA)."
            )
        elif risk_level == "MEDIUM":
            actions = (
                "1. **Exercise Caution**: Verify the sender identity before clicking.\n"
                "2. **Check Certificate**: Ensure the browser address bar displays a valid SSL padlock and official domain name.\n"
                "3. **Avoid Login Inputs**: Do not enter sensitive credentials."
            )
        else:
            actions = (
                "1. **Safe to Proceed**: URL displays standard lexical patterns and zero suspicious flags.\n"
                "2. **Standard Hygiene**: Always verify HTTPS lock icon before submitting credentials."
            )
            
        reply = (
            f"### Recommended Security Protocol for `{url}`\n\n"
            f"**Assessment:** {risk_level} Risk detected.\n\n"
            f"**Action Steps:**\n{actions}"
        )
    else:
        # Default comprehensive explanation
        reasons_formatted = "\n".join([f"- {r}" for r in reasons]) if reasons else "- Standard baseline features."
        reply = (
            f"### PhishGuard Security Breakdown\n\n"
            f"**Target URL:** `{url}`\n"
            f"**Risk Level:** **{risk_level}** ({risk_score}/100 Composite Score)\n"
            f"**Phishing Probability (ML Classifier):** **{phish_prob:.1f}%**\n"
            f"**Isolation Forest Anomaly Index:** **{anomaly_score:.2f}**\n\n"
            f"**Detection Reasons:**\n{reasons_formatted}\n\n"
            f"**Guidance:** " + (
                "⚠️ **DANGER**: Highly suspicious link. Avoid visiting or submitting personal details."
                if risk_level in ["HIGH", "CRITICAL"] else
                "✅ **SAFE**: Link appears legitimate and passes statistical anomaly checks."
            )
        )
        
    return {
        "response": reply,
        "engine": "PhishGuard Security Analyst (Local Rule Engine)",
        "is_fallback": True
    }
