import sys
import os
import json
import urllib.request
import urllib.error

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.risk_engine import analyze_url

BASE_URL = "http://127.0.0.1:8000"

def run_regression_tests():
    print("==================================================")
    print("   PHISHGUARD REGRESSION & ACCURACY TEST SUITE    ")
    print("==================================================")
    
    passed = 0
    total = 0

    # 1. Netflix Classification Test (https://www.netflix.com/)
    total += 1
    print("\n[TEST 1] Netflix URL Analysis (https://www.netflix.com/)...")
    res1 = analyze_url("https://www.netflix.com/")
    print(f"  Prediction : {res1['prediction']}")
    print(f"  Risk Level : {res1['risk_level']}")
    print(f"  Risk Score : {res1['risk_score']}/100")
    print(f"  Phish Prob : {res1['phishing_probability']*100:.1f}%")
    if res1['prediction'] == 'Legitimate' and res1['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {res1['prediction']}/{res1['risk_level']}")

    # 2. Netflix Root URL Analysis (https://netflix.com)
    total += 1
    print("\n[TEST 2] Netflix Root URL Analysis (https://netflix.com)...")
    res2 = analyze_url("https://netflix.com")
    print(f"  Prediction : {res2['prediction']}")
    print(f"  Risk Level : {res2['risk_level']}")
    print(f"  Risk Score : {res2['risk_score']}/100")
    if res2['prediction'] == 'Legitimate' and res2['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {res2['prediction']}/{res2['risk_level']}")

    # 3. Google URL Analysis (https://www.google.com/)
    total += 1
    print("\n[TEST 3] Google URL Analysis (https://www.google.com/)...")
    res3 = analyze_url("https://www.google.com/")
    print(f"  Prediction : {res3['prediction']}")
    print(f"  Risk Level : {res3['risk_level']}")
    if res3['prediction'] == 'Legitimate' and res3['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {res3['prediction']}/{res3['risk_level']}")

    # 4. Microsoft URL Analysis (https://www.microsoft.com/)
    total += 1
    print("\n[TEST 4] Microsoft URL Analysis (https://www.microsoft.com/)...")
    res4 = analyze_url("https://www.microsoft.com/")
    print(f"  Prediction : {res4['prediction']}")
    print(f"  Risk Level : {res4['risk_level']}")
    if res4['prediction'] == 'Legitimate' and res4['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {res4['prediction']}/{res4['risk_level']}")

    # 5. GitHub URL Analysis (https://www.github.com/)
    total += 1
    print("\n[TEST 5] GitHub URL Analysis (https://www.github.com/)...")
    res5 = analyze_url("https://www.github.com/")
    print(f"  Prediction : {res5['prediction']}")
    print(f"  Risk Level : {res5['risk_level']}")
    if res5['prediction'] == 'Legitimate' and res5['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {res5['prediction']}/{res5['risk_level']}")

    # 6. Synthetic Phishing URL Test 1
    total += 1
    print("\n[TEST 6] Synthetic Phishing (http://secure-login-verify-account.example.invalid/login)...")
    res6 = analyze_url("http://secure-login-verify-account.example.invalid/login")
    print(f"  Prediction : {res6['prediction']}")
    print(f"  Risk Level : {res6['risk_level']}")
    print(f"  Phish Prob : {res6['phishing_probability']*100:.1f}%")
    if res6['prediction'] == 'Phishing' and res6['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Phishing/CRITICAL, got {res6['prediction']}/{res6['risk_level']}")

    # 7. Synthetic Phishing URL Test 2
    total += 1
    print("\n[TEST 7] Synthetic Phishing (http://paypal-security-update.xyz/login?id=99283)...")
    res7 = analyze_url("http://paypal-security-update.xyz/login?id=99283")
    print(f"  Prediction : {res7['prediction']}")
    print(f"  Risk Level : {res7['risk_level']}")
    if res7['prediction'] == 'Phishing' and res7['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Phishing/CRITICAL, got {res7['prediction']}/{res7['risk_level']}")

    # 8. Malformed / Empty URL Handling
    total += 1
    print("\n[TEST 8] Malformed / Empty Input Handling...")
    res8 = analyze_url("   ")
    if res8['url'] == "   ":
        print("  Handled whitespace string safely.")
        print("  --> PASS [OK]")
        passed += 1
    else:
        print("  --> FAIL [X]")

    print("\n==================================================")
    print(f"  TOTAL TESTS PASSED: {passed}/{total}")
    print("==================================================")
    
    return passed == total

if __name__ == '__main__':
    success = run_regression_tests()
    sys.exit(0 if success else 1)
