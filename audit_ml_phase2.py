"""
PHISHGUARD AUDIT PHASE 2 — ROOT CAUSE ANALYSIS
================================================
Investigate WHY short, legitimate URLs get classified as phishing.
Compare feature values of legit vs phishing URLs in training data,
and compare them to inference-time features.
"""
import os, sys, json
import numpy as np
import pandas as pd
import joblib

if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except: pass

os.chdir('D:\\Phisihing-Detection')
sys.path.insert(0, '.')

from backend.feature_extractor import extract_url_features

# Load model and metadata
with open('models/metadata.json') as f:
    meta = json.load(f)
feature_names = meta['feature_names']
model = joblib.load('models/best_model.joblib')
scaler = joblib.load('models/scaler.joblib')

print("=" * 70)
print("ROOT CAUSE ANALYSIS: Why do legit URLs get flagged?")
print("=" * 70)

# 1. Feature comparison: legitimate short URLs
print("\n[1] FEATURE COMPARISON: Short legit URLs vs. known phishing URLs")
legit_urls = [
    "https://www.netflix.com/",
    "https://github.com/",
    "https://www.microsoft.com/",
]
phish_urls = [
    "http://secure-login-verify-account.example.invalid/login",
    "http://paypal-login.example.invalid/verify",
    "http://account-security.example.invalid/update",
]

for label, urls in [("LEGITIMATE", legit_urls), ("PHISHING", phish_urls)]:
    print(f"\n  --- {label} URLs ---")
    for u in urls:
        f = extract_url_features(u)
        print(f"  {u}")
        print(f"    URLLength={f['URLLength']}, DomainLen={f['DomainLength']}, HTTPS={f['IsHTTPS']}")
        print(f"    Letters={f['NoOfLettersInURL']}, Digits={f['NoOfDegitsInURL']}")
        print(f"    Entropy={f['Entropy']:.3f}, CharContRate={f['CharContinuationRate']:.3f}")
        print(f"    SubDomains={f['NoOfSubDomain']}, TLDLen={f['TLDLength']}")
        print(f"    Hyphens={f['HyphensInDomain']}, SpecialRatio={f['SpacialCharRatioInURL']:.3f}")
        print(f"    SuspKeywords={f['SuspiciousKeywordCount']}, AtSign={f['HasAtSymbol']}")
        
        # Get model internals 
        vec = pd.DataFrame([f])[feature_names].values
        prob = model.predict_proba(vec)[0][1]
        print(f"    -> Model phishing_prob: {prob:.4f}")

# 2. Dataset-level statistics
print("\n\n[2] DATASET-LEVEL FEATURE STATISTICS:")
df = pd.read_csv('data/phishing_dataset.csv')

# Extract features for a sample from each class
np.random.seed(42)
legit_sample = df[df['label'] == 1].sample(500)
phish_sample = df[df['label'] == 0].sample(500)

def extract_batch(urls):
    feats_list = []
    for u in urls:
        try:
            feats_list.append(extract_url_features(u))
        except:
            pass
    return pd.DataFrame(feats_list)

print("Extracting features from 500 legitimate URLs...")
legit_feats = extract_batch(legit_sample['URL'].tolist())
print("Extracting features from 500 phishing URLs...")
phish_feats = extract_batch(phish_sample['URL'].tolist())

print("\n  Feature comparison (MEAN values):")
print(f"  {'Feature':<30} {'Legit':>10} {'Phishing':>10} {'Delta':>10}")
print(f"  {'-'*30} {'-'*10} {'-'*10} {'-'*10}")
for feat in feature_names:
    l_mean = legit_feats[feat].mean()
    p_mean = phish_feats[feat].mean()
    delta = p_mean - l_mean
    marker = " ***" if abs(delta) > 0.5 * max(abs(l_mean), abs(p_mean), 0.01) else ""
    print(f"  {feat:<30} {l_mean:>10.3f} {p_mean:>10.3f} {delta:>+10.3f}{marker}")

# 3. Feature importance from XGBoost
print("\n\n[3] XGBOOST FEATURE IMPORTANCES:")
importances = model.feature_importances_
sorted_idx = np.argsort(importances)[::-1]
for i, idx in enumerate(sorted_idx):
    print(f"  {i+1:>2}. {feature_names[idx]:<30} importance={importances[idx]:.4f}")

# 4. Where does Netflix fall in the training distribution?
print("\n\n[4] WHERE DOES NETFLIX FALL IN TRAINING DATA DISTRIBUTION?")
netflix_feats = extract_url_features("https://www.netflix.com/")
netflix_vec = pd.DataFrame([netflix_feats])[feature_names]

# Combine all features to see percentiles
all_feats = pd.concat([legit_feats, phish_feats], ignore_index=True)
for feat in feature_names:
    val = netflix_vec[feat].iloc[0]
    pct = (all_feats[feat] < val).mean() * 100
    l_pct = (legit_feats[feat] < val).mean() * 100
    p_pct = (phish_feats[feat] < val).mean() * 100
    if abs(pct - 50) > 30:  # Only show extreme percentiles
        print(f"  {feat:<30} netflix_val={val:>10.3f}  overall_percentile={pct:>5.1f}%  legit_pct={l_pct:>5.1f}%  phish_pct={p_pct:>5.1f}%")

# 5. The real problem: CharContinuationRate for short URLs
print("\n\n[5] CRITICAL FINDING: CharContinuationRate FOR SHORT URLS")
for url in ["https://www.netflix.com/", "https://github.com/", "https://www.google.com/",
            "http://malicious-phishing-login.evil.xyz/steal/creds?token=abc123def456"]:
    f = extract_url_features(url)
    print(f"  {url}")
    print(f"    CharContRate={f['CharContinuationRate']:.4f} (max consecutive run / URL length)")
    # Let's compute it manually
    s = url
    max_run = 1
    current_run = 1
    max_char = s[0]
    for i in range(1, len(s)):
        if s[i] == s[i-1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
                max_char = s[i]
        else:
            current_run = 1
    print(f"    max_consecutive_run={max_run} (char='{max_char}'), url_len={len(s)}, ratio={max_run/len(s):.4f}")

# 6. Check training data CharContinuationRate
print("\n\n[6] CharContinuationRate DISTRIBUTION IN TRAINING DATA:")
print(f"  Legitimate: mean={legit_feats['CharContinuationRate'].mean():.4f}, "
      f"median={legit_feats['CharContinuationRate'].median():.4f}, "
      f"std={legit_feats['CharContinuationRate'].std():.4f}")
print(f"  Phishing:   mean={phish_feats['CharContinuationRate'].mean():.4f}, "
      f"median={phish_feats['CharContinuationRate'].median():.4f}, "
      f"std={phish_feats['CharContinuationRate'].std():.4f}")

# The dataset column has different computation!
print(f"\n  DATASET PRE-COMPUTED VALUES:")
print(f"  Legitimate: mean={legit_sample['CharContinuationRate'].mean():.4f}, "
      f"median={legit_sample['CharContinuationRate'].median():.4f}")
print(f"  Phishing:   mean={phish_sample['CharContinuationRate'].mean():.4f}, "
      f"median={phish_sample['CharContinuationRate'].median():.4f}")

print("\n" + "=" * 70)
print("ROOT CAUSE ANALYSIS COMPLETE")
print("=" * 70)
