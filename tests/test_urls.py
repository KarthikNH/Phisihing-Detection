import sys
import os
import json

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.risk_engine import analyze_url

def run_regression_tests():
    print("==================================================")
    print("   PHISHGUARD REGRESSION & ACCURACY TEST SUITE    ")
    print("   (Verifying Both Root & Deep/Long URLs)         ")
    print("==================================================")
    
    passed = 0
    total = 0

    # 1. Netflix Root URL (https://www.netflix.com/)
    total += 1
    print("\n[TEST 1] Netflix Root (https://www.netflix.com/)...")
    r1 = analyze_url("https://www.netflix.com/")
    print(f"  Prediction : {r1['prediction']}, Risk: {r1['risk_level']}, Score: {r1['risk_score']}, Prob: {r1['phishing_probability']*100:.1f}%")
    if r1['prediction'] == 'Legitimate' and r1['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {r1['prediction']}/{r1['risk_level']}")

    # 2. Netflix Root without www (https://netflix.com)
    total += 1
    print("\n[TEST 2] Netflix Root No-WWW (https://netflix.com)...")
    r2 = analyze_url("https://netflix.com")
    print(f"  Prediction : {r2['prediction']}, Risk: {r2['risk_level']}, Score: {r2['risk_score']}, Prob: {r2['phishing_probability']*100:.1f}%")
    if r2['prediction'] == 'Legitimate' and r2['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {r2['prediction']}/{r2['risk_level']}")

    # 3. Long Netflix Browse URL with Genre ID and Parameters
    total += 1
    print("\n[TEST 3] Long Netflix Browse URL (https://www.netflix.com/browse/genre/839338?so=su)...")
    r3 = analyze_url("https://www.netflix.com/browse/genre/839338?so=su")
    print(f"  Prediction : {r3['prediction']}, Risk: {r3['risk_level']}, Score: {r3['risk_score']}, Prob: {r3['phishing_probability']*100:.1f}%")
    if r3['prediction'] == 'Legitimate' and r3['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate/LOW, got {r3['prediction']}/{r3['risk_level']}")

    # 4. Long Netflix Title URL with 16-digit trackId
    total += 1
    print("\n[TEST 4] Long Netflix Title URL (https://www.netflix.com/title/80057281?trackId=14170286)...")
    r4 = analyze_url("https://www.netflix.com/title/80057281?trackId=14170286")
    print(f"  Prediction : {r4['prediction']}, Risk: {r4['risk_level']}, Score: {r4['risk_score']}, Prob: {r4['phishing_probability']*100:.1f}%")
    if r4['prediction'] == 'Legitimate' and r4['risk_level'] in ['LOW', 'MEDIUM']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X] Expected Legitimate, got {r4['prediction']}/{r4['risk_level']}")

    # 5. Google Root (https://www.google.com/)
    total += 1
    print("\n[TEST 5] Google Root (https://www.google.com/)...")
    r5 = analyze_url("https://www.google.com/")
    print(f"  Prediction : {r5['prediction']}, Risk: {r5['risk_level']}, Score: {r5['risk_score']}")
    if r5['prediction'] == 'Legitimate' and r5['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 6. Long Google Search URL
    total += 1
    print("\n[TEST 6] Long Google Search URL (https://www.google.com/search?q=machine+learning+phishing+detection)...")
    r6 = analyze_url("https://www.google.com/search?q=machine+learning+phishing+detection")
    print(f"  Prediction : {r6['prediction']}, Risk: {r6['risk_level']}, Score: {r6['risk_score']}")
    if r6['prediction'] == 'Legitimate' and r6['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 7. Long Wikipedia Article URL
    total += 1
    print("\n[TEST 7] Long Wikipedia Article (https://en.wikipedia.org/wiki/Distributed_systems_consensus_protocols_and_algorithms)...")
    r7 = analyze_url("https://en.wikipedia.org/wiki/Distributed_systems_consensus_protocols_and_algorithms")
    print(f"  Prediction : {r7['prediction']}, Risk: {r7['risk_level']}, Score: {r7['risk_score']}")
    if r7['prediction'] == 'Legitimate' and r7['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 8. Long GitHub Repository File URL
    total += 1
    print("\n[TEST 8] Long GitHub Source File (https://github.com/torvalds/linux/blob/master/include/linux/compiler.h)...")
    r8 = analyze_url("https://github.com/torvalds/linux/blob/master/include/linux/compiler.h")
    print(f"  Prediction : {r8['prediction']}, Risk: {r8['risk_level']}, Score: {r8['risk_score']}")
    if r8['prediction'] == 'Legitimate' and r8['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 9. Long Amazon Product URL
    total += 1
    print("\n[TEST 9] Long Amazon Product URL (https://www.amazon.com/Apple-iPhone-13-128GB-Midnight/dp/B09G9HD6PD?ref_=Oct_DLandingS_D_123)...")
    r9 = analyze_url("https://www.amazon.com/Apple-iPhone-13-128GB-Midnight/dp/B09G9HD6PD?ref_=Oct_DLandingS_D_123")
    print(f"  Prediction : {r9['prediction']}, Risk: {r9['risk_level']}, Score: {r9['risk_score']}")
    if r9['prediction'] == 'Legitimate' and r9['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 10. Long YouTube Video URL
    total += 1
    print("\n[TEST 10] Long YouTube Video (https://www.youtube.com/watch?v=dQw4w9WgXcQ&feature=youtu.be&t=10s)...")
    r10 = analyze_url("https://www.youtube.com/watch?v=dQw4w9WgXcQ&feature=youtu.be&t=10s")
    print(f"  Prediction : {r10['prediction']}, Risk: {r10['risk_level']}, Score: {r10['risk_score']}")
    if r10['prediction'] == 'Legitimate' and r10['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 11. Long StackOverflow Question URL (120+ chars)
    total += 1
    print("\n[TEST 11] Long StackOverflow (120+ chars)...")
    r11 = analyze_url("https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array")
    print(f"  Prediction : {r11['prediction']}, Risk: {r11['risk_level']}, Score: {r11['risk_score']}")
    if r11['prediction'] == 'Legitimate' and r11['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 11b. Real-World Long Google Search Query (170+ chars, multiple parameters)
    total += 1
    print("\n[TEST 11b] Real-World Long Google Search Query (170+ chars)...")
    r11b = analyze_url("https://www.google.com/search?q=machine+learning+in+cybersecurity+and+phishing+detection+benchmarks&oq=machine+learning&aqs=chrome..69i57j0i512l9.3401j0j7&sourceid=chrome&ie=UTF-8")
    print(f"  Prediction : {r11b['prediction']}, Risk: {r11b['risk_level']}, Score: {r11b['risk_score']}, Prob: {r11b['phishing_probability']*100:.1f}%")
    if r11b['prediction'] == 'Legitimate' and r11b['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 11c. Real-World Long Amazon Product URL with ASIN, ref, and keywords (130+ chars)
    total += 1
    print("\n[TEST 11c] Real-World Long Amazon Product URL (130+ chars)...")
    r11c = analyze_url("https://www.amazon.com/Apple-MacBook-16-inch-512GB-Storage/dp/B08N5M7S6K/ref=sr_1_1?dchild=1&keywords=macbook&qid=1608123456&sr=8-1")
    print(f"  Prediction : {r11c['prediction']}, Risk: {r11c['risk_level']}, Score: {r11c['risk_score']}, Prob: {r11c['phishing_probability']*100:.1f}%")
    if r11c['prediction'] == 'Legitimate' and r11c['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 11d. Real-World Long GitHub Commit SHA URL
    total += 1
    print("\n[TEST 11d] Real-World Long GitHub Commit SHA URL...")
    r11d = analyze_url("https://github.com/torvalds/linux/commit/a1b2c3d4e5f67890abcdef1234567890abcdef12")
    print(f"  Prediction : {r11d['prediction']}, Risk: {r11d['risk_level']}, Score: {r11d['risk_score']}, Prob: {r11d['phishing_probability']*100:.1f}%")
    if r11d['prediction'] == 'Legitimate' and r11d['risk_level'] == 'LOW':
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 12. Synthetic Phishing URL 1: Credential Harvester
    total += 1
    print("\n[TEST 12] Synthetic Phishing (http://secure-login-verify-account.example.invalid/login)...")
    r12 = analyze_url("http://secure-login-verify-account.example.invalid/login")
    print(f"  Prediction : {r12['prediction']}, Risk: {r12['risk_level']}, Score: {r12['risk_score']}, Prob: {r12['phishing_probability']*100:.1f}%")
    if r12['prediction'] == 'Phishing' and r12['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 13. Synthetic Phishing URL 2: Brand Spoof with Suspicious TLD
    total += 1
    print("\n[TEST 13] Brand Spoof Phishing (http://paypal-security-update.xyz/login?id=99283)...")
    r13 = analyze_url("http://paypal-security-update.xyz/login?id=99283")
    print(f"  Prediction : {r13['prediction']}, Risk: {r13['risk_level']}, Score: {r13['risk_score']}, Prob: {r13['phishing_probability']*100:.1f}%")
    if r13['prediction'] == 'Phishing' and r13['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 14. Phishing URL 3: IP Address Host
    total += 1
    print("\n[TEST 14] IP Address Host Phishing (http://192.168.1.1/admin/login.php)...")
    r14 = analyze_url("http://192.168.1.1/admin/login.php")
    print(f"  Prediction : {r14['prediction']}, Risk: {r14['risk_level']}, Score: {r14['risk_score']}")
    if r14['prediction'] == 'Phishing' and r14['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 15. Phishing URL 4: Russian TLD Account Verification
    total += 1
    print("\n[TEST 15] Abuse TLD Phishing (http://bank-account-verification.suspicious.ru/update-credentials)...")
    r15 = analyze_url("http://bank-account-verification.suspicious.ru/update-credentials")
    print(f"  Prediction : {r15['prediction']}, Risk: {r15['risk_level']}, Score: {r15['risk_score']}")
    if r15['prediction'] == 'Phishing' and r15['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 16. Phishing URL 5: Deep Subdomain Brand Spoof on .xyz
    total += 1
    print("\n[TEST 16] Subdomain Spoof (https://appleid.apple.com.verify-login-security.xyz/signin)...")
    r16 = analyze_url("https://appleid.apple.com.verify-login-security.xyz/signin")
    print(f"  Prediction : {r16['prediction']}, Risk: {r16['risk_level']}, Score: {r16['risk_score']}")
    if r16['prediction'] == 'Phishing' and r16['risk_level'] in ['HIGH', 'CRITICAL']:
        print("  --> PASS [OK]")
        passed += 1
    else:
        print(f"  --> FAIL [X]")

    # 17. Malformed / Empty Input Handling
    total += 1
    print("\n[TEST 17] Malformed / Empty Input Handling...")
    r17 = analyze_url("   ")
    if r17['url'] == "   ":
        print("  Handled whitespace input safely.")
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
