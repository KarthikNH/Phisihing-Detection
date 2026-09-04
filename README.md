# PHISHGUARD 🛡️ — End-to-End ML Phishing URL Threat Intelligence Platform

**Project Theme**: Cybersecurity & Machine Learning Phishing Detection  
**Team Name**: Team PHISHGUARD  
**Team Members**: `[Member 1 Name]`, `[Member 2 Name]`, `[Member 3 Name]`  
**Repository & Local Host**: `http://127.0.0.1:8000`  

---

## 📌 Executive Summary & Problem Statement

Phishing remains the #1 initial attack vector in global cybercrime, responsible for over 80% of reported security incidents. Cybercriminals rapidly generate ephemeral, highly realistic domain spoofs, credential harvesters, and malicious redirects to trick unsuspecting users into yielding sensitive credentials or financial assets.

### The Victim Perspective
When a target victim receives a deceptive link via email, SMS (smishing), or social media:
1. **Visual Trickery**: Obfuscated URLs use subtle typosquatting (e.g. `paypaI-verify.com`), subdomains, or encoded characters to mimic trusted brands.
2. **Delayed Reaction**: Traditional blacklist databases (Google Safe Browsing, PhishTank) suffer from zero-day latency, often taking hours or days to register a fresh phishing link.
3. **Catastrophic Outcome**: The victim submits login details or credit card information before security teams can revoke access.

**PHISHGUARD** solves this fundamental latency gap by evaluating zero-day URLs deterministically in **< 5 milliseconds** using a multi-model ML pipeline, Isolation Forest anomaly scoring, and 24 lexical features extracted directly from the target link string.

---

## 📊 Dataset & Feature Engineering

### Dataset Overview
- **Dataset Name**: PhiUSIIL Phishing URL Dataset
- **Total Records**: **235,795** URL instances
- **Class Balance**: 134,850 Legitimate URLs (57.2%) vs. 100,945 Phishing URLs (42.8%)
- **Data Source**: UCI Machine Learning Repository / Kaggle

### 24 Extracted Lexical & Statistical Features
`extract_url_features(url)` parses raw URLs into 24 numerical feature vectors:

1. `URLLength`: Total character length of the URL string.
2. `DomainLength`: Character length of the netloc domain name.
3. `IsDomainIP`: Flag (0/1) indicating IPv4 address domain usage.
4. `TLDLength`: Character length of top-level domain suffix.
5. `NoOfSubDomain`: Count of subdomains preceding root domain.
6. `HasObfuscation`: Flag (0/1) indicating hex encoding (`%20`) or `@` symbols.
7. `NoOfObfuscatedChar`: Count of obfuscated characters.
8. `ObfuscationRatio`: Ratio of obfuscated characters to total URL length.
9. `NoOfLettersInURL`: Count of alphabetic characters.
10. `LetterRatioInURL`: Ratio of alphabetic characters.
11. `NoOfDegitsInURL`: Count of numeric digits.
12. `DegitRatioInURL`: Ratio of numeric digits.
13. `NoOfEqualsInURL`: Count of `=` parameter characters.
14. `NoOfQMarkInURL`: Count of `?` query parameters.
15. `NoOfAmpersandInURL`: Count of `&` query concatenators.
16. `NoOfOtherSpecialCharsInURL`: Count of non-alphanumeric special characters.
17. `SpacialCharRatioInURL`: Ratio of special characters to URL length.
18. `IsHTTPS`: Flag (0/1) indicating SSL/TLS HTTPS protocol usage.
19. `CharContinuationRate`: Maximum consecutive repeating character ratio.
20. `Entropy`: Shannon character entropy ($-\sum p \log_2 p$).
21. `HasAtSymbol`: Flag (0/1) indicating presence of `@` host obscuration.
22. `HasDoubleSlashInPath`: Flag (0/1) indicating `//` in path string.
23. `HyphensInDomain`: Count of hyphens in domain string.
24. `SuspiciousKeywordCount`: Count of credential/financial keywords (`login`, `verify`, `bank`, `paypal`, `account`, `signin`, `admin`).

---

## ⚙️ Machine Learning Pipeline & Empirical Metrics

The dataset was split into **80% Training (80,000 samples)** and **20% Stratified Validation (20,000 samples)**. Standard scaling was applied using `StandardScaler`.

### Empirical Benchmark Results

| Model Architecture | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost Classifier** | **99.69%** | **99.96%** | **99.30%** | **99.63%** | **0.9984** | **SELECTED BEST** |
| **Random Forest** | 99.58% | 99.89% | 99.12% | 99.51% | 0.9984 | Model Saved |
| **Logistic Regression** | 99.32% | 99.89% | 98.53% | 99.21% | 0.9964 | Baseline |

### Anomaly Detection (Isolation Forest)
- **Model**: `IsolationForest(n_estimators=100, contamination=0.05)`
- **Training**: Trained exclusively on legitimate URL distributions to establish baseline normal behavior.
- **Anomaly Score**: Normalizes decision boundary scores into a `0.00 – 1.00` anomaly index.

---

## 📈 Visual Analytics & Plots

All visualization artifacts are generated automatically by `train_pipeline.py` and saved to `results/`:

1. **Confusion Matrix (`results/confusion_matrix.png`)**: Demonstrates near-zero false positive rates on holdout test sets.
2. **ROC Curve Comparison (`results/roc_curve.png`)**: Overlaid ROC curves comparing Logistic Regression (0.9964), Random Forest (0.9984), and XGBoost (0.9984).
3. **Feature Importance Ranking (`results/feature_importance.png`)**: Identifies top predictive features including `SuspiciousKeywordCount`, `Entropy`, `IsHTTPS`, `ObfuscationRatio`, and `URLLength`.
4. **Isolation Forest Distribution (`results/anomaly_visual.png`)**: Kernel density estimation comparing score distributions between legitimate and anomalous phishing links.

---

## 🎨 User Interface & Cyberpunk Aesthetic

PHISHGUARD's user interface is built with React, Vite, and custom CSS:
- **Obsidian Dark Canvas**: Deep black background (`#050508`) with subtle grid mesh.
- **Radial Scanner Visual**: Real-time rotating radar overlay during target URL analysis.
- **Composite Risk Score Gauge**: Interactive SVG circular gauge (0–100 score) with color-coded risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Model Intelligence Dashboard**: Embedded high-res visual plots and dynamic metrics comparison matrix.

---

## 🤖 PHISHGUARD AI Chatbot Assistant

Embedded directly into the dashboard, **PHISHGUARD AI** accepts the current scan context:
- Explains **why** a URL was flagged.
- Decodes **phishing probability** and **anomaly index**.
- Details specific suspicious features.
- Provides immediate **actionable user guidance** (e.g., password resets, reporting, MFA activation).
- Includes **Local Rule-Based Security Analyst Engine** fallback when no cloud LLM API key is configured (with zero false claims of being an ML model).

---

## 🧩 Chrome Extension (Manifest V3)

Located in `extension/`:
- **Manifest V3 Specification**: Lightweight and privacy-focused (`permissions: ["activeTab"]`).
- **Active Tab Inspection**: Queries active browser tab URL and posts to `http://localhost:8000/analyze`.
- **Display**: Shows active URL, composite risk score, risk level badge, phishing probability, anomaly index, and reasons list.
- **Detailed Analysis Link**: "Open Detailed Analysis" button launches `http://localhost:8000`.

---

## 💡 Key Findings & Innovation

1. **Sub-5ms Real-Time Inference**: Pure URL feature extraction eliminates slow, dangerous network scraping delays during URL inspection.
2. **Dual-Layered Defense**: Combines supervised gradient boosting (XGBoost) for known threat patterns with unsupervised anomaly detection (Isolation Forest) for novel zero-day obfuscation techniques.
3. **Transparent Risk Engine**: Replaces opaque binary outputs with a composite 0–100 Risk Index and actionable human-readable explanations.

---

## 🛠️ Step-by-Step Installation & Run Guide

### 1. Prerequisites
- Python 3.10+
- Node.js v18+ & npm

### 2. Environment Setup & Dependencies
```bash
# Clone or navigate to project workspace
cd "d:\SIC\Phisihing Detection"

# Install Python requirements
pip install -r requirements.txt
```

### 3. Run Machine Learning Pipeline (Optional / Pre-trained Included)
```bash
python train_pipeline.py
```

### 4. Build Frontend & Launch Unified Server
```bash
# Build React frontend
cd frontend
npm install
npm run build
cd ..

# Launch FastAPI backend & server
python -m uvicorn backend.main:app --port 8000 --host 127.0.0.1
```

### 5. Open PHISHGUARD Application
Open your browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### 6. Load Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `d:\SIC\Phisihing Detection\extension` directory.
4. Click the PHISHGUARD shield icon in your browser toolbar to scan the active tab!
