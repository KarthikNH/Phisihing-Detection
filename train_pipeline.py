import os
import json
import time
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
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve
)

from backend.feature_extractor import extract_url_features

# Set style for dark cybersecurity plots
plt.style.use('dark_background')
CYBER_BG = '#090b10'
CYBER_CYAN = '#00f0ff'
CYBER_RED = '#ff2a5f'
CYBER_GREEN = '#00ff88'
CYBER_ORANGE = '#ff9900'

def preprocess_and_extract(df_raw, max_samples=100000):
    """
    Extract features using backend.feature_extractor to guarantee 100% feature consistency
    between training and live inference.
    """
    print(f"Dataset shape: {df_raw.shape}")
    
    # Subsample if dataset is larger than max_samples for fast & accurate training
    if len(df_raw) > max_samples:
        print(f"Stratified sampling {max_samples} records for training...")
        _, df_sample = train_test_split(
            df_raw, test_size=max_samples, stratify=df_raw['label'], random_state=42
        )
    else:
        df_sample = df_raw.copy()
        
    print("Extracting URL features...")
    start_time = time.time()
    
    # Map target: label 0 = Phishing (1), label 1 = Legitimate (0)
    y = (df_sample['label'].values == 0).astype(int)
    
    # Extract features using our feature_extractor
    urls = df_sample['URL'].astype(str).tolist()
    features_list = [extract_url_features(u) for u in urls]
        
    X_df = pd.DataFrame(features_list)
    feature_names = list(X_df.columns)
    
    print(f"Feature extraction complete in {time.time() - start_time:.2f}s. Extract shape: {X_df.shape}")
    print(f"Target distribution: Phishing(1)={sum(y==1)}, Legitimate(0)={sum(y==0)}")
    
    return X_df.values, y, feature_names

def train_and_evaluate():
    print("=== PHISHGUARD ML PIPELINE TRAINING ===")
    data_path = 'data/phishing_dataset.csv'
    if not os.path.exists(data_path):
        data_path = 'data/PhiUSIIL_Phishing_URL_Dataset.csv'
        
    df_raw = pd.read_csv(data_path)
    X, y, feature_names = preprocess_and_extract(df_raw, max_samples=100000)
    
    # Train / Test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save feature names and scaler
    os.makedirs('models', exist_ok=True)
    os.makedirs('results', exist_ok=True)
    joblib.dump(scaler, 'models/scaler.joblib')
    
    # 1. Logistic Regression
    print("\nTraining Logistic Regression Baseline...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_preds = lr.predict(X_test_scaled)
    lr_probs = lr.predict_proba(X_test_scaled)[:, 1]
    
    # 2. Random Forest
    print("Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train) # Tree models work directly on unscaled
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    
    # 3. XGBoost Classifier
    print("Training XGBoost Classifier...")
    xgb = XGBClassifier(n_estimators=150, max_depth=8, learning_rate=0.1, eval_metric='logloss', random_state=42, n_jobs=-1)
    xgb.fit(X_train, y_train)
    xgb_preds = xgb.predict(X_test)
    xgb_probs = xgb.predict_proba(X_test)[:, 1]
    
    # Evaluate metrics
    models_dict = {
        'Logistic Regression': (lr, lr_preds, lr_probs, True),
        'Random Forest': (rf, rf_preds, rf_probs, False),
        'XGBoost': (xgb, xgb_preds, xgb_probs, False)
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

    # Select Best Model based on F1 Score
    best_model_name = max(metrics_summary, key=lambda k: metrics_summary[k]['F1_Score'])
    print(f"\n---> Best Performing Classifier: {best_model_name}")
    
    best_model, best_preds, best_probs, is_best_scaled = models_dict[best_model_name]
    
    # Save individual models and best model
    joblib.dump(lr, 'models/lr_model.joblib')
    joblib.dump(rf, 'models/rf_model.joblib')
    joblib.dump(xgb, 'models/xgb_model.joblib')
    joblib.dump(best_model, 'models/best_model.joblib')
    
    # 4. Anomaly Detection with Isolation Forest (trained on legitimate URL samples)
    print("\nTraining Isolation Forest for URL Anomaly Detection...")
    X_legit_train = X_train[y_train == 0]
    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X_legit_train)
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
    
    colors = {'Logistic Regression': CYBER_ORANGE, 'Random Forest': CYBER_GREEN, 'XGBoost': CYBER_CYAN}
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
    
    # 3. Feature Importance Plot (XGBoost / Random Forest)
    importances = xgb.feature_importances_
    indices = np.argsort(importances)[::-1][:12] # Top 12 features
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]
    
    fig, ax = plt.subplots(figsize=(10, 6), facecolor=CYBER_BG)
    ax.set_facecolor(CYBER_BG)
    ax.barh(range(len(indices)), top_importances[::-1], color=CYBER_CYAN, edgecolor='#00aaff', alpha=0.85)
    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels(top_features[::-1], color='white', fontsize=11)
    ax.set_xlabel('Relative Feature Importance Score', color=CYBER_CYAN, fontsize=12)
    ax.set_title('XGBoost Top URL Feature Importances', color='white', fontsize=14, pad=15)
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
    
    print("\nTraining and visualization generation completed successfully!")

if __name__ == '__main__':
    train_and_evaluate()
