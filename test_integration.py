import sys
import json
import urllib.request
import urllib.error

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("==================================================")
    print("   PHISHGUARD SYSTEM INTEGRATION TEST SUITE       ")
    print("==================================================")
    
    passed = 0
    total = 0

    # 1. Health Endpoint Test
    total += 1
    print("\n[TEST 1] GET /health Endpoint...")
    try:
        req = urllib.request.urlopen(f"{BASE_URL}/health")
        res = json.loads(req.read().decode('utf-8'))
        print(f"  Response: {res}")
        if res.get('status') == 'healthy' and res.get('models_loaded') is True:
            print("  --> PASS [OK]")
            passed += 1
        else:
            print("  --> FAIL [X] (Unexpected health status)")
    except Exception as e:
        print(f"  --> FAIL [X] Error: {e}")

    # 2. Legitimate URL Test
    total += 1
    print("\n[TEST 2] POST /analyze - Legitimate URL (https://www.netflix.com/)...")
    try:
        payload = json.dumps({'url': 'https://www.netflix.com/'}).encode('utf-8')
        req = urllib.request.Request(f"{BASE_URL}/analyze", data=payload, headers={'Content-Type': 'application/json'})
        res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
        print(f"  Risk Level : {res['risk_level']}")
        print(f"  Risk Score : {res['risk_score']}/100")
        print(f"  Prediction : {res['prediction_label']}")
        if (res['prediction'] in [0, 'Legitimate', 'legitimate'] or res.get('prediction_code') == 0) and res['risk_level'] == 'LOW':
            print("  --> PASS [OK]")
            passed += 1
        else:
            print(f"  --> FAIL [X] (Expected Legitimate/LOW, got {res['risk_level']})")
    except Exception as e:
        print(f"  --> FAIL [X] Error: {e}")

    # 3. Suspicious / Phishing URL Test
    total += 1
    print("\n[TEST 3] POST /analyze - Suspicious URL (http://paypal-security-update.xyz/login?id=99283)...")
    try:
        payload = json.dumps({'url': 'http://paypal-security-update.xyz/login?id=99283'}).encode('utf-8')
        req = urllib.request.Request(f"{BASE_URL}/analyze", data=payload, headers={'Content-Type': 'application/json'})
        res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
        print(f"  Risk Level : {res['risk_level']}")
        print(f"  Risk Score : {res['risk_score']}/100")
        print(f"  Reasons    : {res['reasons'][:2]}")
        if (res['prediction'] in [1, 'Phishing', 'phishing'] or res.get('prediction_code') == 1) and res['risk_level'] in ['HIGH', 'CRITICAL']:
            print("  --> PASS [OK]")
            passed += 1
        else:
            print(f"  --> FAIL [X] (Expected Phishing/CRITICAL, got {res['risk_level']})")
    except Exception as e:
        print(f"  --> FAIL [X] Error: {e}")

    # 4. Malformed / Empty URL Handling Test
    total += 1
    print("\n[TEST 4] POST /analyze - Empty/Malformed URL Handling...")
    try:
        payload = json.dumps({'url': '   '}).encode('utf-8')
        req = urllib.request.Request(f"{BASE_URL}/analyze", data=payload, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
        print("  --> FAIL [X] (Server accepted empty URL instead of returning 400)")
    except urllib.error.HTTPError as e:
        if e.code == 400:
            print("  Server returned HTTP 400 Bad Request as expected.")
            print("  --> PASS [OK]")
            passed += 1
        else:
            print(f"  --> FAIL [X] (Expected 400 error, got {e.code})")
    except Exception as e:
        print(f"  --> FAIL [X] Error: {e}")

    # 5. Metrics Endpoint Test
    total += 1
    print("\n[TEST 5] GET /metrics Endpoint...")
    try:
        req = urllib.request.urlopen(f"{BASE_URL}/metrics")
        res = json.loads(req.read().decode('utf-8'))
        print(f"  Best Model : {res.get('best_model')}")
        print(f"  Visuals    : {list(res.get('visualizations', {}).keys())}")
        if res.get('best_model') and 'visualizations' in res:
            print("  --> PASS [OK]")
            passed += 1
        else:
            print("  --> FAIL [X] (Missing metrics fields)")
    except Exception as e:
        print(f"  --> FAIL [X] Error: {e}")

    # 6. Chatbot Service Test
    total += 1
    print("\n[TEST 6] POST /chat - Context-Aware Chatbot...")
    try:
        chat_payload = json.dumps({
            'query': 'Why was this URL flagged?',
            'context': {
                'url': 'http://paypal-security-update.xyz/login',
                'risk_score': 87.5,
                'risk_level': 'CRITICAL',
                'phishing_probability': 0.99,
                'anomaly_score': 0.85,
                'reasons': ['Critical ML Threat Flag', 'Suspicious keyword count'],
                'features': {'DomainLength': 25, 'SuspiciousKeywordCount': 2}
            }
        }).encode('utf-8')
        req = urllib.request.Request(f"{BASE_URL}/chat", data=chat_payload, headers={'Content-Type': 'application/json'})
        res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
        print(f"  Engine Used: {res.get('engine')}")
        print(f"  Snippet    : {res.get('response')[:120]}...")
        if 'response' in res and res.get('engine'):
            print("  --> PASS [OK]")
            passed += 1
        else:
            print("  --> FAIL [X] (Invalid chat response)")
    except Exception as e:
        print(f"  --> FAIL [X] Error: {e}")

    print("\n==================================================")
    print(f"  TOTAL TESTS PASSED: {passed}/{total}")
    print("==================================================")

if __name__ == '__main__':
    run_tests()
