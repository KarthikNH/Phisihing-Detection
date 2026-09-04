import os
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from backend.feature_extractor import extract_url_features

class PhishGuardRiskEngine:
    def __init__(self, models_dir='models'):
        self.models_dir = models_dir
        self.load_models()

    def load_models(self):
        # Load feature config or metadata fallback
        feature_config_path = os.path.join(self.models_dir, 'feature_config.joblib')
        meta_path = os.path.join(self.models_dir, 'metadata.json')
        
        if os.path.exists(feature_config_path):
            config = joblib.load(feature_config_path)
            self.feature_names = config['feature_names']
        elif os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                metadata = json.load(f)
            self.feature_names = metadata['feature_names']
        else:
            raise FileNotFoundError(f"Model configuration not found in {self.models_dir}. Run train_pipeline.py first.")
            
        # Load classifier (calibrated XGBoost primary, best_model fallback)
        classifier_path = os.path.join(self.models_dir, 'classifier.joblib')
        if not os.path.exists(classifier_path):
            classifier_path = os.path.join(self.models_dir, 'best_model.joblib')
            
        # Load anomaly detector (Isolation Forest primary, iso_forest fallback)
        anomaly_path = os.path.join(self.models_dir, 'anomaly_detector.joblib')
        if not os.path.exists(anomaly_path):
            anomaly_path = os.path.join(self.models_dir, 'iso_forest.joblib')
            
        self.scaler = joblib.load(os.path.join(self.models_dir, 'scaler.joblib'))
        self.classifier = joblib.load(classifier_path)
        self.anomaly_detector = joblib.load(anomaly_path)
        self.best_model_name = "Calibrated XGBoost"

    def analyze_url(self, url: str) -> dict:
        url_clean = str(url).strip()
        parsed = urlparse(url_clean if '://' in url_clean else 'https://' + url_clean)
        domain_name = (parsed.netloc or parsed.path.split('/')[0]).lower().split(':')[0]
        
        # 1. Canonical Feature Extraction
        features = extract_url_features(url_clean)
        
        # Format input vector matching trained feature order
        input_data = pd.DataFrame([features])[self.feature_names]
        input_vector = input_data.values
        
        # 2. Classifier Prediction & Calibrated Probability
        probs = self.classifier.predict_proba(input_vector)[0]
        phishing_probability = float(probs[1]) # 1 = Phishing
        prediction = 1 if phishing_probability >= 0.5 else 0
        
        # 3. Anomaly Detection (Isolation Forest)
        # Raw decision score: positive = normal, negative = anomalous.
        # Normalize to 0.0 - 1.0 scale (0.0 = completely normal, 1.0 = highly anomalous)
        raw_iso_score = float(self.anomaly_detector.decision_function(input_vector)[0])
        raw_anomaly = (0.15 - raw_iso_score) / 0.35
        anomaly_score = float(max(0.0, min(1.0, raw_anomaly)))
        
        # 4. Heuristic Penalty Calculation & Reasons Generation
        reasons = []
        heuristic_penalty = 0.0
        
        if features['IsDomainIP'] == 1:
            reasons.append("URL uses an IP address instead of a domain name")
            heuristic_penalty += 30
            
        if features['HasAtSymbol'] == 1:
            reasons.append("URL contains an '@' symbol used to obscure real destination host")
            heuristic_penalty += 25
            
        if features['HasObfuscation'] == 1:
            reasons.append("Hexadecimal or percentage URL obfuscation detected")
            heuristic_penalty += 20
            
        if features['SuspiciousKeywordCount'] > 0:
            reasons.append(f"Contains {int(features['SuspiciousKeywordCount'])} suspicious credential/security keywords")
            heuristic_penalty += min(35, int(features['SuspiciousKeywordCount']) * 12)
            
        if features['NoOfSubDomain'] >= 3:
            reasons.append(f"Excessive subdomain depth detected ({int(features['NoOfSubDomain'])} subdomains)")
            heuristic_penalty += 20
            
        if features['IsHTTPS'] == 0:
            reasons.append("Insecure protocol: Connection does not use HTTPS encryption")
            heuristic_penalty += 15
            
        if features['URLLength'] > 75:
            reasons.append(f"Unusually long URL structure ({int(features['URLLength'])} characters)")
            heuristic_penalty += 15
            
        if features['Entropy'] > 4.5:
            reasons.append(f"High character entropy ({features['Entropy']:.2f}) indicating randomized/obfuscated tokens")
            heuristic_penalty += 15

        if features['HyphensInDomain'] > 1:
            reasons.append(f"Multiple hyphens in domain ({int(features['HyphensInDomain'])}) commonly used in typosquatting")
            heuristic_penalty += 15

        # Primary ML Threat Reasons
        if phishing_probability >= 0.85:
            reasons.insert(0, f"Critical ML Threat Flag: Classifier indicates {phishing_probability*100:.1f}% phishing probability")
        elif phishing_probability >= 0.50:
            reasons.insert(0, f"ML Threat Flag: Classifier indicates {phishing_probability*100:.1f}% phishing probability")
            
        if anomaly_score >= 0.65:
            reasons.append(f"Isolation Forest flagged structural anomaly (Anomaly Score: {anomaly_score:.2f})")

        if not reasons:
            reasons.append("URL exhibits normal domain structure and legitimate lexical characteristics")

        # 5. Composite Risk Score (0-100 scale, harmonized logic)
        normalized_heuristic = min(100.0, heuristic_penalty)
        composite_risk = (phishing_probability * 70.0) + (anomaly_score * 15.0) + (normalized_heuristic * 0.15)
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
            
        prediction_label = 'Phishing' if prediction == 1 else 'Legitimate'
        return {
            'url': url,
            'prediction': prediction_label,
            'prediction_code': prediction,
            'prediction_label': prediction_label,
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

