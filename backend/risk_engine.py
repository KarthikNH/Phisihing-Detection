import os
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from backend.feature_extractor import extract_url_features

VERIFIED_DOMAINS = {
    'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de', 'google.fr', 'google.com.au',
    'youtube.com', 'youtu.be', 'gmail.com', 'gstatic.com', 'googleusercontent.com',
    'microsoft.com', 'live.com', 'office.com', 'bing.com', 'github.com', 'githubusercontent.com', 'linkedin.com',
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'aws.amazon.com',
    'apple.com', 'icloud.com',
    'wikipedia.org', 'wikimedia.org',
    'netflix.com', 'spotify.com', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'reddit.com', 'stackoverflow.com', 'stackexchange.com', 'nytimes.com', 'medium.com', 'walmart.com', 'zoom.us',
    'python.org', 'cloudflare.com', 'mozilla.org', 'w3.org'
}

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
        
        best_name = "Calibrated XGBoost"
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r') as f:
                    m = json.load(f)
                    best_name = m.get('best_model', best_name)
            except Exception:
                pass
        self.best_model_name = best_name

    def analyze_url(self, url: str) -> dict:
        url_clean = str(url).strip()
        parsed = urlparse(url_clean if '://' in url_clean else 'https://' + url_clean)
        domain_name = (parsed.netloc or parsed.path.split('/')[0]).lower().split(':')[0]
        domain_clean = domain_name.lstrip('www.')
        
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
        raw_iso_score = float(self.anomaly_detector.decision_function(input_vector)[0])
        raw_anomaly = (0.15 - raw_iso_score) / 0.35
        anomaly_score = float(max(0.0, min(1.0, raw_anomaly)))
        
        # 4. Verified Domain Integrity Check
        # Check if URL host is an authenticated high-reputation domain without host tampering
        has_host_tampering = (
            features.get('IsDomainIP', 0) == 1 or
            features.get('HasAtSymbol', 0) == 1 or
            features.get('HasDoubleSlashInPath', 0) == 1 or
            features.get('IsSuspiciousTLD', 0) == 1 or
            features.get('SuspiciousKeywordInDomain', 0) > 0
        )
        is_verified_domain = (
            not has_host_tampering and 
            any(domain_clean == vd or domain_clean.endswith('.' + vd) for vd in VERIFIED_DOMAINS)
        )
        
        if is_verified_domain:
            # Genuine verified domain: calibrate away false positive long-URL path/query inflation
            phishing_probability = min(phishing_probability, 0.08)
            prediction = 0
            anomaly_score = min(anomaly_score, 0.25)
            
        # 5. Heuristic Penalty Calculation & Reasons Generation
        reasons = []
        heuristic_penalty = 0.0
        
        # A. Critical host & obfuscation checks
        if features.get('IsDomainIP', 0) == 1:
            reasons.append("URL uses an IP address instead of a verified domain name")
            heuristic_penalty += 35
            
        if features.get('HasAtSymbol', 0) == 1:
            reasons.append("URL contains an '@' symbol used to obscure the destination host")
            heuristic_penalty += 30
            
        if features.get('HasObfuscation', 0) == 1:
            reasons.append("Hexadecimal or percentage URL encoding obfuscation detected")
            heuristic_penalty += 20
            
        if features.get('HasDoubleSlashInPath', 0) == 1:
            reasons.append("Contains consecutive slashes ('//') in path used in open redirects")
            heuristic_penalty += 15

        # B. Domain spoofing & structure checks
        if features.get('SuspiciousKeywordInDomain', 0) > 0:
            reasons.append(f"Contains security/credential keyword directly inside domain name ({int(features['SuspiciousKeywordInDomain'])})")
            heuristic_penalty += 35
        elif features.get('SuspiciousKeywordCount', 0) > 0 and not is_verified_domain:
            reasons.append(f"Contains {int(features['SuspiciousKeywordCount'])} credential/security keywords")
            heuristic_penalty += min(20, int(features['SuspiciousKeywordCount']) * 5)
            
        if features.get('IsSuspiciousTLD', 0) == 1:
            reasons.append("Domain uses a top-level domain (TLD) extension frequently abused in phishing campaigns")
            heuristic_penalty += 20
            
        if features.get('NoOfSubDomain', 1) >= 3:
            reasons.append(f"Excessive subdomain depth detected ({int(features['NoOfSubDomain'])} subdomains)")
            heuristic_penalty += 20
            
        if features.get('HyphensInDomain', 0) > 1:
            reasons.append(f"Multiple hyphens in domain ({int(features['HyphensInDomain'])}) commonly used in brand typosquatting")
            heuristic_penalty += 15

        if features.get('DigitsInDomain', 0) > 2:
            reasons.append(f"Excessive numeric digits ({int(features['DigitsInDomain'])}) in domain name")
            heuristic_penalty += 10

        # C. Protocol & entropy checks
        if features.get('IsHTTPS', 1) == 0:
            reasons.append("Insecure protocol: Connection does not use HTTPS encryption")
            heuristic_penalty += 15
            
        if features.get('DomainEntropy', 0) > 4.2:
            reasons.append(f"High domain entropy ({features['DomainEntropy']:.2f}) indicating randomized/algorithmically generated host")
            heuristic_penalty += 15

        # D. Primary ML Threat Reasons
        if phishing_probability >= 0.85:
            reasons.insert(0, f"Critical ML Threat Flag: Classifier indicates {phishing_probability*100:.1f}% phishing probability")
        elif phishing_probability >= 0.50:
            reasons.insert(0, f"ML Threat Flag: Classifier indicates {phishing_probability*100:.1f}% phishing probability")
            
        if anomaly_score >= 0.70:
            reasons.append(f"Isolation Forest flagged structural anomaly (Anomaly Score: {anomaly_score:.2f})")

        if not reasons:
            if is_verified_domain:
                reasons.append("Verified high-reputation domain; standard web path and parameter structure")
            else:
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
