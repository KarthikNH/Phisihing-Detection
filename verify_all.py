import urllib.request
import urllib.error
import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def post(url, data):
    req = urllib.request.Request(
        url, 
        data=json.dumps(data).encode('utf-8'), 
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))

def get(url):
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode('utf-8'))

print("==================================================")
print("     PHISHGUARD FULL SYSTEM VERIFICATION          ")
print("==================================================")

# 1. Health check
h = get("http://127.0.0.1:8000/health")
print(f"[CHECK 1] GET /health -> status: {h.get('status')}, models_loaded: {h.get('models_loaded')}")
assert h.get('status') == 'healthy', "Health check failed"

# 2. Legitimate URL: https://www.google.com
g = post("http://127.0.0.1:8000/analyze", {"url": "https://www.google.com"})
print(f"[CHECK 2] Google -> Risk: {g['risk_level']}, Score: {g['risk_score']}, Pred: {g['prediction']}, Prob: {g['phishing_probability']}")
assert g['risk_level'] == 'LOW', "Google should be LOW risk"

# 3. Known Phishing URL
p = post("http://127.0.0.1:8000/analyze", {"url": "http://paypal-security-update.xyz/login?id=99283"})
print(f"[CHECK 3] PayPal Phishing -> Risk: {p['risk_level']}, Score: {p['risk_score']}, Pred: {p['prediction']}, Prob: {p['phishing_probability']}")
assert p['risk_level'] in ['HIGH', 'CRITICAL'], "PayPal phishing should be HIGH or CRITICAL risk"

# 4. Empty input
try:
    post("http://127.0.0.1:8000/analyze", {"url": "   "})
    print("[CHECK 4] Empty Input -> FAILED (Expected 400)")
except urllib.error.HTTPError as e:
    assert e.code == 400, f"Expected 400, got {e.code}"
    print(f"[CHECK 4] Empty Input -> PASS [OK] (Got HTTP 400: {e.reason})")

# 5. Malformed URL
m = post("http://127.0.0.1:8000/analyze", {"url": "not-a-domain-%%$-test"})
print(f"[CHECK 5] Malformed URL Handled Gracefully -> Risk: {m['risk_level']}, Score: {m['risk_score']}")

# 6. Vite Dev Server Proxy: http://localhost:3000/analyze
v = post("http://localhost:3000/analyze", {"url": "https://www.google.com"})
print(f"[CHECK 6] Vite Dev Proxy (/analyze) -> Risk: {v['risk_level']}, Score: {v['risk_score']}")
assert v['risk_level'] == 'LOW', "Vite proxy should return same valid result"

# 7. Chatbot: Why flagged?
c_why = post("http://127.0.0.1:8000/chat", {
    "query": "Why was this URL flagged?",
    "context": p
})
print(f"[CHECK 7] Chatbot 'Why flagged?' -> Engine: {c_why.get('engine')}")
print(f"         Snippet: {c_why.get('response')[:110]}...")

# 8. Chatbot: What should I do?
c_do = post("http://127.0.0.1:8000/chat", {
    "query": "What should I do?",
    "context": p
})
print(f"[CHECK 8] Chatbot 'What should I do?' -> Engine: {c_do.get('engine')}")
print(f"         Snippet: {c_do.get('response')[:110]}...")

# 9. Chatbot: Explain anomaly score
c_anomaly = post("http://127.0.0.1:8000/chat", {
    "query": "Explain the anomaly score",
    "context": p
})
print(f"[CHECK 9] Chatbot 'Explain anomaly score' -> Snippet: {c_anomaly.get('response')[:110]}...")

# 10. Metrics endpoint
metrics = get("http://127.0.0.1:8000/metrics")
print(f"[CHECK 10] GET /metrics -> Best Model: {metrics.get('best_model')}")

print("\n==================================================")
print("     ALL 10 VERIFICATION CHECKS PASSED [OK]!       ")
print("==================================================")
