# PHISHGUARD 🛡️ — End-to-End ML Phishing URL Detection System

PHISHGUARD is a state-of-the-art machine learning cybersecurity platform designed to detect, analyze, and flag phishing URLs in real time. Built with a dark cyberpunk visual design system, PHISHGUARD combines multi-model ML classification, Isolation Forest anomaly scoring, lexical feature extraction, and an interactive AI threat assistant.

---

## 🌟 Key Features

1. **Multi-Model Machine Learning Pipeline**
   - Trained on **235,795** URL records from the PhiUSIIL Phishing URL Dataset.
   - Evaluates **Logistic Regression**, **Random Forest**, and **XGBoost Classifier**.
   - Achieves **99.71% Accuracy**, **99.96% Precision**, and **99.87% ROC-AUC** with XGBoost.

2. **Real-Time URL Anomaly Engine**
   - **Isolation Forest** detects structural anomalies in URL strings.
   - Computes Shannon character entropy, char continuation rate, obfuscation ratios, and subdomains.

3. **Composite Risk Index & Heuristics**
   - Calculates a **0–100 Composite Risk Index** (weighted ML probability + Anomaly score + Heuristics).
   - Classifies risk levels into `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
   - Generates human-readable detection reason breakdowns.

4. **FastAPI Cyber Backend**
   - `POST /analyze`: Real-time URL threat scanning endpoint.
   - `GET /health`: Backend operational & model loading state.
   - `GET /metrics`: Model comparison metrics and visual chart assets.
   - `POST /chat`: PhishGuard AI security assistant endpoint.

5. **Cyberpunk Dark UI Frontend**
   - Built with React, Vite, and custom CSS.
   - Animated radial radar scanner overlay during link analysis.
   - Circular risk score gauge & metric breakdown cards.
   - Model Intelligence dashboard with embedded high-resolution visual plots.
   - Context-aware PhishGuard AI chatbot widget.

6. **PhishGuard AI Chatbot**
   - Explains scan findings, anomaly metrics, and recommended action steps.
   - Integrates with Gemini API when key is configured, with seamless fallback to the local **Rule-Based Security Analyst Engine**.

---

## 📁 Project Structure

```
Phisihing Detection/
├── data/
│   └── phishing_dataset.csv         # PhiUSIIL Phishing URL Dataset (235k+ rows)
├── models/
│   ├── best_model.joblib            # Exported XGBoost Classifier
│   ├── rf_model.joblib              # Random Forest Model
│   ├── lr_model.joblib              # Logistic Regression Baseline
│   ├── xgb_model.joblib             # XGBoost Model
│   ├── iso_forest.joblib            # Isolation Forest Anomaly Detector
│   ├── scaler.joblib                # StandardScaler Artifact
│   └── metadata.json                # Benchmark metrics & feature schema
├── results/
│   ├── confusion_matrix.png         # High-res Confusion Matrix Plot
│   ├── roc_curve.png                # ROC Curve Comparison Plot
│   ├── feature_importance.png       # Top 12 XGBoost Feature Importances
│   ├── anomaly_visual.png           # Isolation Forest Score Density Plot
│   └── metrics.json                 # Exported metrics summary
├── backend/
│   ├── main.py                      # FastAPI App & Endpoints
│   ├── feature_extractor.py         # Deterministic URL Lexical Feature Engine
│   ├── risk_engine.py               # Risk Score Engine & Heuristic Processor
│   └── chatbot.py                   # PhishGuard AI Assistant Engine
├── frontend/
│   ├── src/
│   │   ├── App.jsx                  # Main Cyberpunk React Dashboard
│   │   ├── index.css                # Dark Cybersecurity CSS Styling System
│   │   └── main.jsx                 # Vite Entrypoint
│   ├── dist/                        # Production Web Build
│   ├── package.json                 # React Dependencies
│   └── vite.config.js               # Proxy & Server Configuration
├── extension/                       # Reserved for Chrome Extension (Phase 2)
├── docs/                            # Documentation Assets
├── train_pipeline.py                # Pipeline execution script
├── PROJECT_STATUS.md                # Project status & Phase 2 roadmap
├── README.md                        # Documentation
├── requirements.txt                 # Python dependencies
└── .gitignore                       # Git ignore configuration
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run ML Training Pipeline (Pre-trained Models Included)

To train models from scratch and export visualizations:

```bash
python train_pipeline.py
```

### 3. Launch Backend & Frontend Server

Start the FastAPI application (which serves both backend endpoints and built React frontend):

```bash
python -m uvicorn backend.main:app --port 8000 --host 127.0.0.1
```

Access the application in your browser:
👉 **http://127.0.0.1:8000**

---

## 📊 Empirical ML Benchmark Results

| Model Architecture | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost Classifier** *(Selected)* | **99.69%** | **99.96%** | **99.30%** | **99.63%** | **0.9984** | **ACTIVE MODEL** |
| **Random Forest** | 99.58% | 99.89% | 99.12% | 99.51% | 0.9984 | SAVED |
| **Logistic Regression** | 99.32% | 99.89% | 98.53% | 99.21% | 0.9964 | SAVED |

---

## 🔒 Security & Privacy

- Training is strictly local; user input URLs are parsed locally under 5ms without remote page scraping.
- Local fallback security engine guarantees zero data leakage when external LLM API is unconfigured.
