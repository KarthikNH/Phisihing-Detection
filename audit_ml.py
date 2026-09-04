"""
PHISHGUARD ML PIPELINE AUDIT SCRIPT
====================================
1. Inspect dataset columns vs. extracted features
2. Check class distribution, duplicates
3. Test current model against known legitimate & suspicious URLs
4. Check feature consistency between training data columns and extract_url_features()
"""
import os
import sys
import json
import numpy as np
import pandas as pd
import joblib

if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except: pass

os.chdir('D:\\Phisihing-Detection')
sys.path.insert(0, '.')

from backend.feature_extractor import extract_url_features

print("=" * 70)
print("PHISHGUARD ML AUDIT — DATASET & FEATURE CONSISTENCY CHECK")
print("=" * 70)

# 1. Load dataset
data_path = 'data/phishing_dataset.csv'
df = pd.read_csv(data_path, nrows=5)
print(f"\n[1] DATASET COLUMNS ({len(df.columns)}):")
for c in df.columns:
    print(f"    {c}: dtype={df[c].dtype}, sample={df[c].iloc[0]}")

# Check label mapping
df_full = pd.read_csv(data_path)
print(f"\n[2] DATASET SHAPE: {df_full.shape}")
print(f"    Label distribution:")
print(f"    {df_full['label'].value_counts().to_dict()}")
print(f"    Label=0 means: {'Phishing' if True else ''} (mapped to is_phishing=1 in training)")
print(f"    Label=1 means: {'Legitimate' if True else ''} (mapped to is_phishing=0 in training)")

# Check for URL column and duplicates
if 'URL' in df_full.columns:
    n_unique_urls = df_full['URL'].nunique()
    n_total = len(df_full)
    n_dups = n_total - n_unique_urls
    print(f"\n[3] URL DUPLICATES:")
    print(f"    Total rows:  {n_total}")
    print(f"    Unique URLs: {n_unique_urls}")
    print(f"    Duplicates:  {n_dups}")
    
    # Check if duplicate URLs have conflicting labels
    if n_dups > 0:
        dup_urls = df_full[df_full.duplicated(subset='URL', keep=False)]
        conflicting = dup_urls.groupby('URL')['label'].nunique()
        n_conflict = (conflicting > 1).sum()
        print(f"    Conflicting labels on same URL: {n_conflict}")

# 4. Feature consistency audit
print(f"\n[4] FEATURE EXTRACTION AUDIT:")
# Load metadata
with open('models/metadata.json') as f:
    meta = json.load(f)
training_features = meta['feature_names']
print(f"    Training feature names ({len(training_features)}): {training_features}")

# Extract features for a test URL
test_features = extract_url_features("https://www.netflix.com/")
extracted_names = list(test_features.keys())
print(f"    Extracted feature names ({len(extracted_names)}): {extracted_names}")

# Check match
if training_features == extracted_names:
    print("    MATCH: Feature names and order are IDENTICAL")
else:
    print("    MISMATCH DETECTED!")
    missing_in_extract = set(training_features) - set(extracted_names)
    extra_in_extract = set(extracted_names) - set(training_features)
    if missing_in_extract:
        print(f"    Missing in extraction: {missing_in_extract}")
    if extra_in_extract:
        print(f"    Extra in extraction: {extra_in_extract}")

# 5. Test current model on diagnostic URLs
print(f"\n[5] CURRENT MODEL PREDICTIONS ON DIAGNOSTIC URLS:")
scaler = joblib.load('models/scaler.joblib')
model = joblib.load('models/best_model.joblib')
iso = joblib.load('models/iso_forest.joblib')

test_urls = [
    "https://www.google.com/",
    "https://www.microsoft.com/",
    "https://github.com/",
    "https://www.netflix.com/",
    "https://www.amazon.com/",
    "https://www.wikipedia.org/",
    "https://www.python.org/",
    "http://secure-login-verify-account.example.invalid/login",
    "http://paypal-login.example.invalid/verify",
    "http://account-security.example.invalid/update",
    "http://192.168.1.1/admin/login",
]

for url in test_urls:
    feats = extract_url_features(url)
    df_feat = pd.DataFrame([feats])[training_features]
    vec = df_feat.values
    
    if meta['best_model'] == 'Logistic Regression':
        prob = model.predict_proba(scaler.transform(vec))[0][1]
    else:
        prob = model.predict_proba(vec)[0][1]
    
    iso_raw = iso.decision_function(vec)[0]
    
    label = "PHISHING" if prob >= 0.5 else "LEGIT"
    print(f"    {url:<65} prob={prob:.4f} [{label:>8}]  iso_raw={iso_raw:.4f}")

# 6. Inspect dataset for feature patterns
print(f"\n[6] DATASET FEATURE PATTERN ANALYSIS:")

# Check if the dataset has pre-computed columns matching our feature names
dataset_cols = set(df_full.columns)
feature_cols = set(training_features)
overlap = dataset_cols & feature_cols
print(f"    Dataset columns overlapping with extracted features: {len(overlap)}/{len(feature_cols)}")
if overlap:
    print(f"    Overlapping columns: {sorted(overlap)}")

# Check whether URL column contains scheme info
sample_urls = df_full['URL'].head(10).tolist()
print(f"\n    Sample URLs from dataset:")
for u in sample_urls[:5]:
    print(f"      {u[:120]}")

# 7. Check the dataset columns that the training pipeline actually uses
print(f"\n[7] COLUMNS USED BY TRAINING PIPELINE:")
print(f"    The pipeline calls extract_url_features() on each URL from column 'URL'")
print(f"    Target label column: 'label' (0=phishing, 1=legitimate)")
print(f"    This means the model is trained on re-extracted features, NOT on dataset pre-computed columns")
print(f"    This is GOOD for consistency — same extractor used for train and inference")

# 8. Check class balance
n_phish = (df_full['label'] == 0).sum()
n_legit = (df_full['label'] == 1).sum()
print(f"\n[8] CLASS BALANCE:")
print(f"    Phishing (label=0):   {n_phish} ({n_phish/len(df_full)*100:.1f}%)")
print(f"    Legitimate (label=1): {n_legit} ({n_legit/len(df_full)*100:.1f}%)")
print(f"    Ratio phish:legit = {n_phish/n_legit:.2f}")

print("\n" + "=" * 70)
print("AUDIT COMPLETE")
print("=" * 70)
