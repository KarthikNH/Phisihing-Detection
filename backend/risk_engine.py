import os
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from backend.feature_extractor import extract_url_features

# Trusted global domains whitelist for baseline sanity check
TOP_TRUSTED_DOMAINS = {
    'google.com', 'www.google.com', 'github.com', 'www.github.com',
    'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
    'amazon.com', 'www.amazon.com', 'wikipedia.org', 'www.wikipedia.org',
    'youtube.com', 'www.youtube.com', 'linkedin.com', 'www.linkedin.com',
    'python.org', 'www.python.org', 'stackoverflow.com', 'www.stackoverflow.com',
    'openai.com', 'www.openai.com', 'cloudflare.com', 'www.cloudflare.com',
    'x.com', 'www.x.com', 'twitter.com', 'www.twitter.com'
}

class PhishGuardRiskEngine:
    def __init__(self, models_dir='models'):
        self.models_dir = models_dir
        self.load_models()

    def load_models(self):
        meta_path = os.path.join(self.models_dir, 'metadata.json')
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model metadata not found at {meta_path}. Run train_pipeline.py first.")
            
        with open(meta_path, 'r') as f:
            self.metadata = json.load(f)
            
        self.feature_names = self.metadata['feature_names']
        self.best_model_name = self.metadata['best_model']
        
        self.scaler = joblib.load(os.path.join(self.models_dir, 'scaler.joblib'))
        self.best_model = joblib.load(os.path.join(self.models_dir, 'best_model.joblib'))
        self.iso_forest = joblib.load(os.path.join(self.models_dir, 'iso_forest.joblib'))

    def analyze_url(self, url: str) -> dict:
        url_clean = str(url).strip()
        parsed = urlparse(url_clean if '://' in url_clean else 'https://' + url_clean)
        domain_name = (parsed.netloc or parsed.path.split('/')[0]).lower().split(':')[0]
        
        # 1. Feature extraction
        features = extract_url_features(url_clean)
        
        # Format input vector matching trained feature order
        input_data = pd.DataFrame([features])[self.feature_names]
        input_vector = input_data.values
        input_scaled = self.scaler.transform(input_vector)
        
        # 2. Classifier Prediction
        if self.best_model_name == 'Logistic Regression':
            probs = self.best_model.predict_proba(input_scaled)[0]
        else:
            probs = self.best_model.predict_proba(input_vector)[0]
            
        phishing_probability = float(probs[1]) # 1 = Phishing
        
        # Sane trusted domain adjustment
        is_trusted = domain_name in TOP_TRUSTED_DOMAINS
        if is_trusted:
            phishing_probability = min(phishing_probability, 0.01)
            
        prediction = 1 if phishing_probability >= 0.5 else 0
        
        # 3. Anomaly Detection (Isolation Forest)
        raw_iso_score = float(self.iso_forest.decision_function(input_vector)[0])
        # Higher score = normal, negative score = anomaly. Map to 0.0 - 1.0 (1.0 = highly anomalous)
        anomaly_score = float(max(0.0, min(1.0, (0.15 - raw_iso_score) / 0.45)))
        if is_trusted:
            anomaly_score = min(anomaly_score, 0.05)
        
        # 4. Heuristic Rule Check & Reasons Generation
        reasons = []
        heuristic_penalty = 0
        
        if features['IsDomainIP'] == 1:
            reasons.append("URL uses an IP address instead of a domain name")
            heuristic_penalty += 25
            
        if features['HasAtSymbol'] == 1:
            reasons.append("URL contains an '@' symbol used to obscure real destination host")
            heuristic_penalty += 20
            
        if features['HasObfuscation'] == 1:
            reasons.append("Hexadecimal or percentage URL obfuscation detected")
            heuristic_penalty += 15
            
        if features['SuspiciousKeywordCount'] > 0 and not is_trusted:
            reasons.append(f"Contains {int(features['SuspiciousKeywordCount'])} suspicious credential/security keywords")
            heuristic_penalty += min(30, int(features['SuspiciousKeywordCount']) * 12)
            
        if features['NoOfSubDomain'] >= 3 and not is_trusted:
            reasons.append(f"Excessive subdomain depth detected ({int(features['NoOfSubDomain'])} subdomains)")
            heuristic_penalty += 15
            
        if features['IsHTTPS'] == 0:
            reasons.append("Insecure protocol: Connection does not use HTTPS encryption")
            heuristic_penalty += 10
            
        if features['URLLength'] > 75:
            reasons.append(f"Unusually long URL structure ({int(features['URLLength'])} characters)")
            heuristic_penalty += 10
            
        if features['Entropy'] > 4.5 and not is_trusted:
            reasons.append(f"High character entropy ({features['Entropy']:.2f}) indicating randomized/obfuscated tokens")
            heuristic_penalty += 10

        if features['HyphensInDomain'] > 1:
            reasons.append(f"Multiple hyphens in domain ({int(features['HyphensInDomain'])}) commonly used in typosquatting")
            heuristic_penalty += 10

        # Primary ML flag reasons
        if phishing_probability >= 0.85:
            reasons.insert(0, f"Critical ML Threat Flag: Classifier indicates {phishing_probability*100:.1f}% phishing probability")
        elif phishing_probability >= 0.50:
            reasons.insert(0, f"ML Threat Flag: Classifier indicates {phishing_probability*100:.1f}% phishing probability")
            
        if anomaly_score >= 0.65 and not is_trusted:
            reasons.append(f"Isolation Forest flagged structural anomaly (Anomaly Score: {anomaly_score:.2f})")

        if is_trusted:
            reasons.insert(0, f"Domain '{domain_name}' is recognized as a verified top-tier legitimate domain")

        if not reasons:
            reasons.append("URL exhibits normal domain structure and legitimate lexical characteristics")

        # 5. Composite Risk Score (0-100 scale, NOT a probability)
        normalized_heuristic = min(100.0, float(heuristic_penalty))
        composite_risk = (phishing_probability * 60.0) + (anomaly_score * 20.0) + (normalized_heuristic * 0.20)
        
        if is_trusted:
            composite_risk = min(composite_risk, 5.0)
            
        risk_score = round(float(max(0.0, min(100.0, composite_risk))), 1)
        
        # 6. Risk Level Categorization
        if risk_score >= 85.0:
            risk_level = "CRITICAL"
        elif risk_score >= 60.0:
            risk_level = "HIGH"
        elif risk_score >= 30.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            'url': url,
            'prediction': prediction,
            'prediction_label': 'Phishing' if prediction == 1 else 'Legitimate',
            'phishing_probability': round(phishing_probability, 4),
            'anomaly_score': round(anomaly_score, 4),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'reasons': reasons,
            'features': features,
            'model_used': self.best_model_name
        }

# Global singleton engine instance
_engine_instance = None

def get_risk_engine():
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PhishGuardRiskEngine()
    return _engine_instance

def analyze_url(url: str) -> dict:
    engine = get_risk_engine()
    return engine.analyze_url(url)
