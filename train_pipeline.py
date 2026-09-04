import os
import json
import time
import random
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve
)

from backend.feature_extractor import extract_url_features

# Style definitions for dark cybersecurity visual theme
plt.style.use('dark_background')
CYBER_BG = '#090b10'
CYBER_CYAN = '#00f0ff'
CYBER_RED = '#ff2a5f'
CYBER_GREEN = '#00ff88'
CYBER_ORANGE = '#ff9900'

# Diverse, realistic benign web path templates covering real-world web architectures
BENIGN_SHORT_PATHS = [
    "", # Clean root domain
    "/about", "/about/team", "/contact", "/contact-us", "/privacy-policy", "/terms-of-service",
    "/help/center", "/faq", "/pricing", "/features", "/docs/v2/getting-started", "/blog", "/news"
]

BENIGN_MEDIUM_PATHS = [
    "/products/electronics/catalog/item?id=8392104&category=smartphones",
    "/browse/category/items?page=2&sort=popular&view=grid",
    "/title/80057281?trackId=14170286&ref_=tt_ov_inf",
    "/title/70143836?trackId=200257858",
    "/show/10293847?id=92837465&season=2",
    "/watch?v=k39d8x90q84&feature=share&t=45s",
    "/dp/B09G9HD6PD?ref_=Oct_DLandingS_D_123_456&th=1",
    "/blob/master/include/linux/compiler_attributes.h",
    "/tree/main/src/components/dashboard/analytics",
    "/user/profile/activity?tab=contributions&from=2026-01-01",
    "/overview/features-and-pricing?plan=enterprise",
    "/downloads/release/v3.4.2/installer-x64-windows.msi",
    "/recipes/desserts/classic-triple-chocolate-cake-recipe?servings=8",
    "/events/annual-developer-summit-2026/schedule-and-speakers",
    "/catalog/books/science-fiction/1849204918294?format=hardcover",
    "/status/1498273928172639102",
    "/item/9837482910?vendor=10293&code=84920",
    "/video/839201948?session=92837491",
    "/media/stream/1829471029?quality=1080p"
]

BENIGN_LONG_PATHS = [
    "/search?q=machine+learning+in+cybersecurity+and+phishing+detection+benchmarks&oq=machine+learning&aqs=chrome..69i57j0i512l9.3401j0j7&sourceid=chrome&ie=UTF-8",
    "/search?q=deep+neural+network+architectures+for+natural+language+processing&hl=en&gl=us&start=20&filter=true&source=hp",
    "/Apple-MacBook-16-inch-512GB-Storage/dp/B08N5M7S6K/ref=sr_1_1?dchild=1&keywords=macbook&qid=1608123456&sr=8-1",
    "/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array?rq=1&newreg=839210",
    "/wiki/Phishing_detection_using_machine_learning_techniques_and_heuristics_for_web_applications",
    "/wiki/Distributed_systems_consensus_protocols_and_algorithms_in_modern_cloud_platforms",
    "/commit/a1b2c3d4e5f67890abcdef1234567890abcdef12?diff=unified&w=1",
    "/document/d/1234567890abcdefghijklmnopqrstuvwxyz-1234567890/edit?usp=sharing&ouid=1029384756&rtpof=true",
    "/ip/Apple-iPhone-12-64GB-Black-Fully-Unlocked-B-Grade-Refurbished/839201948?wmlspartner=wlpa&selectedSellerId=10100293&adid=222222",
    "/feed/update/urn:li:activity:7123456789012345678?utm_source=share&utm_medium=member_desktop&rcm=ACoAAA1234",
    "/technology/2026/09/04/artificial-intelligence-regulation-guidelines-and-cybersecurity-standards.html?utm_source=newsletter&utm_medium=email",
    "/watch?v=dQw4w9WgXcQ&list=RDdQw4w9WgXcQ&start_radio=1&t=4s&ab_channel=OfficialArtistChannel",
    "/track/4cOdK2wGLETKBW3PvgPWqT?si=22839218391283&context=spotify%3Aplaylist%3A37i9dQZF1DXcBWIGoYBM5M",
    "/r/MachineLearning/comments/1234567/discussion_how_to_prevent_model_overfitting_on_url_length/?utm_source=share&utm_medium=web2x&context=3",
    "/story/financial-markets-and-economic-indicators-quarterly-review-2026-analysis.html?ref=frontpage&view=full"
]

ALL_BENIGN_TEMPLATES = BENIGN_SHORT_PATHS + BENIGN_MEDIUM_PATHS + BENIGN_LONG_PATHS

def preprocess_and_extract(df_raw, max_samples=50000):
    """
    Deduplicate dataset, augment benign web path distribution to eliminate 
    root-domain dataset bias, and extract 28 canonical features using backend.feature_extractor.
    """
    print(f"Raw dataset shape: {df_raw.shape}")
    
    # Drop duplicate URLs to eliminate train/test data leakage
    df_clean = df_raw.drop_duplicates(subset=['URL']).copy()
    print(f"Deduplicated dataset shape: {df_clean.shape}")
    
    # Stratified subsampling if dataset is larger than max_samples
    if len(df_clean) > max_samples:
        print(f"Stratified sampling {max_samples} records for training...")
        _, df_sample = train_test_split(
            df_clean, test_size=max_samples, stratify=df_clean['label'], random_state=42
        )
    else:
        df_sample = df_clean.copy()
        
    print("Preparing URLs with benign path normalization to eliminate length bias...")
    start_time = time.time()
    
    # Map target: label 0 = Phishing (1), label 1 = Legitimate (0)
    y_raw = df_sample['label'].values
    urls_raw = df_sample['URL'].astype(str).tolist()
    
    urls = []
    y = []
    random.seed(42)
    
    for u_str, lbl in zip(urls_raw, y_raw):
        u = u_str.strip()
        target = 0 if lbl == 1 else 1 # 0 = Legitimate, 1 = Phishing
        
        # In the raw dataset, 100% of legitimate URLs are bare root domains.
        # Augment ~75% of legitimate URLs across short, medium, and long complex web paths
        # so the model learns that length and query parameters are standard web conventions.
        if lbl == 1:
            aug_roll = random.random()
            if aug_roll < 0.25:
                # 25% keep clean root domain
                pass
            elif aug_roll < 0.50:
                # 25% short paths
                u_base = u.rstrip('/')
                u = u_base + random.choice(BENIGN_SHORT_PATHS)
            elif aug_roll < 0.75:
                # 25% medium paths with parameters
                u_base = u.rstrip('/')
                u = u_base + random.choice(BENIGN_MEDIUM_PATHS)
            else:
                # 25% long complex web paths / search queries / doc links (120 - 320+ chars)
                u_base = u.rstrip('/')
                u = u_base + random.choice(BENIGN_LONG_PATHS)
            
        urls.append(u)
        y.append(target)
        
    y = np.array(y)
    
    print(f"Extracting features for {len(urls)} URLs using canonical feature extractor...")
    features_list = [extract_url_features(u) for u in urls]
    X_df = pd.DataFrame(features_list)
    feature_names = list(X_df.columns)
    
    print(f"Feature extraction complete in {time.time() - start_time:.2f}s. Matrix shape: {X_df.shape}")
    print(f"Target distribution: Phishing(1)={sum(y==1)}, Legitimate(0)={sum(y==0)}")
    
    return X_df.values, y, feature_names

def train_and_evaluate():
    print("=== PHISHGUARD ML PIPELINE TRAINING & BIAS RECTIFICATION ===")
    data_path = 'data/phishing_dataset.csv'
    if not os.path.exists(data_path):
        data_path = 'data/PhiUSIIL_Phishing_URL_Dataset.csv'
        
    df_raw = pd.read_csv(data_path)
    X, y, feature_names = preprocess_and_extract(df_raw, max_samples=50000)
    
    # Stratified Train / Test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    os.makedirs('models', exist_ok=True)
    os.makedirs('results', exist_ok=True)
    
    # Save canonical feature config and scaler
    feature_config = {
        'feature_names': feature_names,
        'feature_count': len(feature_names),
        'scaler_type': 'StandardScaler'
    }
    joblib.dump(feature_config, 'models/feature_config.joblib')
    joblib.dump(scaler, 'models/scaler.joblib')
    
    # 1. Logistic Regression Baseline
    print("\nTraining Logistic Regression Baseline...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_preds = lr.predict(X_test_scaled)
    lr_probs = lr.predict_proba(X_test_scaled)[:, 1]
    
    # 2. Random Forest Classifier
    print("Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=120, max_depth=12, min_samples_leaf=3, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    
    # 3. Calibrated XGBoost Classifier
    print("Training and Calibrating XGBoost Classifier...")
    base_xgb = XGBClassifier(
        n_estimators=130, max_depth=4, learning_rate=0.06, 
        min_child_weight=3, gamma=0.2, reg_alpha=0.5, reg_lambda=1.5,
        colsample_bytree=0.75, subsample=0.8,
        eval_metric='logloss', random_state=42, n_jobs=-1
    )
    calibrated_xgb = CalibratedClassifierCV(estimator=base_xgb, method='sigmoid', cv=5)
    calibrated_xgb.fit(X_train, y_train)
    
    xgb_preds = calibrated_xgb.predict(X_test)
    xgb_probs = calibrated_xgb.predict_proba(X_test)[:, 1]
    
    # Evaluate metrics
    models_dict = {
        'Logistic Regression': (lr, lr_preds, lr_probs, True),
        'Random Forest': (rf, rf_preds, rf_probs, False),
        'XGBoost (Calibrated)': (calibrated_xgb, xgb_preds, xgb_probs, False)
    }
    
    metrics_summary = {}
    for name, (model, preds, probs, is_scaled) in models_dict.items():
        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds))
        rec = float(recall_score(y_test, preds))
        f1 = float(f1_score(y_test, preds))
        auc = float(roc_auc_score(y_test, probs))
        
        metrics_summary[name] = {
            'Accuracy': round(acc, 4),
            'Precision': round(prec, 4),
            'Recall': round(rec, 4),
            'F1_Score': round(f1, 4),
            'ROC_AUC': round(auc, 4)
        }
        print(f"\n{name} Results:")
        print(f"  Accuracy : {acc:.4f}")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall   : {rec:.4f}")
        print(f"  F1 Score : {f1:.4f}")
        print(f"  ROC-AUC  : {auc:.4f}")

    # Select Best Model based on F1 Score & Generalization
    best_model_name = max(metrics_summary, key=lambda k: metrics_summary[k]['F1_Score'])
    print(f"\n---> Best Performing Classifier: {best_model_name}")
    
    best_model, best_preds, best_probs, is_best_scaled = models_dict[best_model_name]
    
    # Save primary model artifacts and aliases
    joblib.dump(calibrated_xgb, 'models/classifier.joblib')
    joblib.dump(calibrated_xgb, 'models/best_model.joblib')
    joblib.dump(lr, 'models/lr_model.joblib')
    joblib.dump(rf, 'models/rf_model.joblib')
    joblib.dump(calibrated_xgb, 'models/xgb_model.joblib')
    
    # 4. Anomaly Detection with Isolation Forest (trained on diverse legitimate URL samples)
    print("\nTraining Isolation Forest for URL Anomaly Detection...")
    X_legit_train = X_train[y_train == 0]
    iso = IsolationForest(n_estimators=100, contamination=0.04, random_state=42, n_jobs=-1)
    iso.fit(X_legit_train)
    
    joblib.dump(iso, 'models/anomaly_detector.joblib')
    joblib.dump(iso, 'models/iso_forest.joblib')
    
    # Save metadata
    meta = {
        'best_model': best_model_name,
        'feature_names': feature_names,
        'metrics': metrics_summary,
        'dataset_total_samples': len(df_raw),
        'train_samples': len(X_train),
        'test_samples': len(X_test)
    }
    with open('models/metadata.json', 'w') as f:
        json.dump(meta, f, indent=2)
    with open('results/metrics.json', 'w') as f:
        json.dump(meta, f, indent=2)

    # ----------------------------------------------------
    # GENERATE VISUALIZATIONS (results/)
    # ----------------------------------------------------
    print("\nGenerating static visualizations in results/...")
    
    # 1. Confusion Matrix Plot (Best Model)
    cm = confusion_matrix(y_test, best_preds)
    fig, ax = plt.subplots(figsize=(7, 6), facecolor=CYBER_BG)
    ax.set_facecolor(CYBER_BG)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False, ax=ax,
                annot_kws={"size": 16, "weight": "bold"},
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    ax.set_title(f'Confusion Matrix - {best_model_name}', color='white', fontsize=14, pad=15)
    ax.set_xlabel('Predicted Label', color=CYBER_CYAN, fontsize=12)
    ax.set_ylabel('True Label', color=CYBER_CYAN, fontsize=12)
    ax.tick_params(colors='white', labelsize=11)
    plt.tight_layout()
    plt.savefig('results/confusion_matrix.png', dpi=200, facecolor=CYBER_BG)
    plt.close()
    
    # 2. ROC Curve Plot (All Models Overlaid)
    fig, ax = plt.subplots(figsize=(8, 6), facecolor=CYBER_BG)
    ax.set_facecolor(CYBER_BG)
    
    colors = {'Logistic Regression': CYBER_ORANGE, 'Random Forest': CYBER_GREEN, 'XGBoost (Calibrated)': CYBER_CYAN}
    for name, (model, preds, probs, _) in models_dict.items():
        fpr, tpr, _ = roc_curve(y_test, probs)
        auc_val = metrics_summary[name]['ROC_AUC']
        ax.plot(fpr, tpr, label=f'{name} (AUC = {auc_val:.4f})', color=colors[name], lw=2.5)
        
    ax.plot([0, 1], [0, 1], 'k--', color='#666666', label='Random Guess')
    ax.set_title('ROC Curve Comparison - Phishing Detection Models', color='white', fontsize=14, pad=15)
    ax.set_xlabel('False Positive Rate', color='white', fontsize=12)
    ax.set_ylabel('True Positive Rate', color='white', fontsize=12)
    ax.grid(True, color='#222233', linestyle=':', alpha=0.6)
    ax.legend(facecolor='#121620', edgecolor='#333344', labelcolor='white')
    ax.tick_params(colors='white')
    plt.tight_layout()
    plt.savefig('results/roc_curve.png', dpi=200, facecolor=CYBER_BG)
    plt.close()
    
    # 3. Feature Importance Plot (Base Estimator Feature Importances)
    if hasattr(calibrated_xgb, 'calibrated_classifiers_'):
        base_model = calibrated_xgb.calibrated_classifiers_[0].estimator
        importances = base_model.feature_importances_
    elif hasattr(rf, 'feature_importances_'):
        importances = rf.feature_importances_
    else:
        importances = np.ones(len(feature_names)) / len(feature_names)

    indices = np.argsort(importances)[::-1][:12] # Top 12 features
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]
    
    fig, ax = plt.subplots(figsize=(10, 6), facecolor=CYBER_BG)
    ax.set_facecolor(CYBER_BG)
    ax.barh(range(len(indices)), top_importances[::-1], color=CYBER_CYAN, edgecolor='#00aaff', alpha=0.85)
    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels(top_features[::-1], color='white', fontsize=11)
    ax.set_xlabel('Relative Feature Importance Score', color=CYBER_CYAN, fontsize=12)
    ax.set_title('Top URL Feature Importances (Phishing Signal Dominance)', color='white', fontsize=14, pad=15)
    ax.grid(True, color='#222233', linestyle=':', alpha=0.6, axis='x')
    ax.tick_params(colors='white')
    plt.tight_layout()
    plt.savefig('results/feature_importance.png', dpi=200, facecolor=CYBER_BG)
    plt.close()
    
    # 4. Anomaly Detection Score Visual (Isolation Forest Score Distribution)
    legit_scores = iso.decision_function(X_test[y_test == 0])
    phish_scores = iso.decision_function(X_test[y_test == 1])
    
    fig, ax = plt.subplots(figsize=(8, 6), facecolor=CYBER_BG)
    ax.set_facecolor(CYBER_BG)
    sns.kdeplot(legit_scores, color=CYBER_GREEN, label='Legitimate URLs', fill=True, alpha=0.3, ax=ax)
    sns.kdeplot(phish_scores, color=CYBER_RED, label='Phishing URLs', fill=True, alpha=0.3, ax=ax)
    ax.axvline(x=0.0, color='white', linestyle='--', label='Anomaly Threshold (0.0)')
    ax.set_title('Isolation Forest Anomaly Score Distribution', color='white', fontsize=14, pad=15)
    ax.set_xlabel('Isolation Forest Decision Score (Lower = More Anomalous)', color='white', fontsize=12)
    ax.set_ylabel('Density', color='white', fontsize=12)
    ax.grid(True, color='#222233', linestyle=':', alpha=0.6)
    ax.legend(facecolor='#121620', edgecolor='#333344', labelcolor='white')
    ax.tick_params(colors='white')
    plt.tight_layout()
    plt.savefig('results/anomaly_visual.png', dpi=200, facecolor=CYBER_BG)
    plt.close()
    
    print("\nTraining, calibration, and visualization generation completed successfully!")

if __name__ == '__main__':
    train_and_evaluate()
