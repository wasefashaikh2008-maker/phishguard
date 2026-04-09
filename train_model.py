import os, sys, joblib, pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    accuracy_score,
    precision_recall_curve,
    f1_score
)
from datetime import datetime
import numpy as np

# -------------------------
# PATH SETUP
# -------------------------
BASE = Path(__file__).resolve().parent
sys.path.append(str(BASE))


from detector.features import (
    SUSPICIOUS_TLDS,
    SUSPICIOUS_EXTENSIONS,
    URL_SHORTENERS,
    RED_FLAG_KEYWORDS,
    check_suspicious_tld,
    is_url_shortener
)

# -------------------------
# LOAD DATASET
# -------------------------
data_path = BASE / 'dataset' / 'urls_sample.csv'
df = pd.read_csv(data_path)

print("="*60)
print("📊 DATASET INFORMATION")
print("="*60)
print(f"CSV Columns: {df.columns.tolist()}")
print(f"Dataset shape: {df.shape}")

# -------------------------
# REQUIRED COLUMNS CHECK
# -------------------------
required_columns = [
    'url_length',
    'has_ip_address',
    'dot_count',
    'https_flag',
    'url_entropy',
    'token_count',
    'subdomain_count',
    'query_param_count',
    'tld_length',
    'path_length',
    'has_hyphen_in_domain',
    'number_of_digits',
    'tld_popularity',
    'suspicious_file_extension',
    'domain_name_length',
    'percentage_numeric_chars',
    'ClassLabel'
]

missing = set(required_columns) - set(df.columns)
if missing:
    print(f"\n❌ Missing columns in CSV: {missing}")
    print("Please ensure your dataset has all required columns.")
    sys.exit(1)
else:
    print("\n✅ All required columns found!")

# -------------------------
# CLEAN DATA
# -------------------------
df = df.dropna()
df['ClassLabel'] = df['ClassLabel'].astype(int)

print(f"\nDataset size after cleaning: {df.shape}")
print(f"\nClass distribution:")
print(df['ClassLabel'].value_counts())

# -------------------------
# FEATURE VALIDATION using features.py logic
# -------------------------
print("\n" + "="*60)
print("🔍 FEATURE VALIDATION")
print("="*60)

# Check TLD popularity against our suspicious TLDs list
suspicious_tld_count = df[df['tld_popularity'] == 0].shape[0]
print(f"📌 URLs with suspicious TLDs (tld_popularity=0): {suspicious_tld_count}")

# Check IP address usage
ip_address_count = df[df['has_ip_address'] == 1].shape[0]
print(f"📌 URLs using IP addresses: {ip_address_count}")

# Check hyphen in domain
hyphen_count = df[df['has_hyphen_in_domain'] == 1].shape[0]
print(f"📌 URLs with hyphen in domain: {hyphen_count}")

# Check suspicious file extensions
suspicious_ext_count = df[df['suspicious_file_extension'] == 1].shape[0]
print(f"📌 URLs with suspicious file extensions: {suspicious_ext_count}")

# Check HTTPS usage
https_count = df[df['https_flag'] == 1].shape[0]
print(f"📌 URLs using HTTPS: {https_count}")

# Check high entropy URLs
high_entropy_count = df[df['url_entropy'] > 4.5].shape[0]
print(f"📌 URLs with high entropy (>4.5): {high_entropy_count}")

# Check long URLs
long_url_count = df[df['url_length'] > 100].shape[0]
print(f"📌 URLs with length > 100: {long_url_count}")

# Check many subdomains
many_subdomains_count = df[df['subdomain_count'] > 2].shape[0]
print(f"📌 URLs with >2 subdomains: {many_subdomains_count}")

# Check high digit percentage
high_digit_count = df[df['percentage_numeric_chars'] > 30].shape[0]
print(f"📌 URLs with >30% digits: {high_digit_count}")

# -------------------------
# FEATURE / LABEL SPLIT
# -------------------------
X = df.drop(columns=['URL', 'ClassLabel'], errors='ignore')
y = df['ClassLabel']

print(f"\n📊 Feature matrix shape: {X.shape}")
print(f"📊 Target shape: {y.shape}")

# -------------------------
# TRAIN / TEST SPLIT
# -------------------------
Xtr, Xte, ytr, yte = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

print(f"\nTraining set: {Xtr.shape[0]} samples")
print(f"Test set: {Xte.shape[0]} samples")

# -------------------------
# MODEL + HYPERPARAMETER TUNING
# -------------------------
print("\n" + "="*60)
print("🚀 TRAINING MODEL")
print("="*60)

param_grid = {
    'n_estimators': [300, 400],
    'max_depth': [15, 20, None],
    'min_samples_leaf': [1, 2, 4]
}

base_model = RandomForestClassifier(
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

grid = GridSearchCV(
    base_model,
    param_grid,
    cv=3,
    scoring='f1',
    n_jobs=-1,
    verbose=1
)

print("Training with GridSearchCV...")
grid.fit(Xtr, ytr)

clf = grid.best_estimator_

print("\n✅ Best Parameters:", grid.best_params_)

# -------------------------
# PROBABILITIES
# -------------------------
proba = clf.predict_proba(Xte)[:, 1]

# -------------------------
# OPTIMAL THRESHOLD SELECTION
# -------------------------
precisions, recalls, thresholds = precision_recall_curve(yte, proba)

# Fix array length issue
precisions = precisions[:-1]
recalls = recalls[:-1]

f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
best_index = np.argmax(f1_scores)
best_threshold = thresholds[best_index]

print(f"\n🎯 Best Threshold (F1 optimized): {round(best_threshold, 4)}")

preds = (proba >= best_threshold).astype(int)

# -------------------------
# EVALUATION
# -------------------------
roc = roc_auc_score(yte, proba)
accuracy = accuracy_score(yte, preds)
f1 = f1_score(yte, preds)

print("\n" + "="*60)
print("📊 MODEL PERFORMANCE")
print("="*60)
print(f"📈 ROC-AUC: {round(roc, 4)}")
print(f"📊 Accuracy: {round(accuracy, 4)}")
print(f"🎯 F1 Score: {round(f1, 4)}")
print("\n📋 Classification Report:\n")
print(classification_report(yte, preds))

# -------------------------
# FEATURE IMPORTANCE
# -------------------------
importance = pd.Series(
    clf.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

print("\n" + "="*60)
print("🔝 TOP 10 MOST IMPORTANT FEATURES")
print("="*60)
for i, (feature, imp) in enumerate(importance.head(10).items(), 1):
    print(f"{i:2}. {feature:25} : {imp:.4f}")

# -------------------------
# FEATURE CORRELATION WITH PHISHING (Insights)
# -------------------------
print("\n" + "="*60)
print("💡 FEATURE INSIGHTS")
print("="*60)

# Calculate average values for phishing vs legitimate
phishing_data = df[df['ClassLabel'] == 1]
legit_data = df[df['ClassLabel'] == 0]

print("\n📊 Average values comparison (Phishing vs Legitimate):")

# URL Length
phishing_url_len = phishing_data['url_length'].mean()
legit_url_len = legit_data['url_length'].mean()
print(f"  URL Length:        Phishing: {phishing_url_len:.1f} | Legitimate: {legit_url_len:.1f} | Diff: +{phishing_url_len - legit_url_len:.1f}")

# Dot count
phishing_dots = phishing_data['dot_count'].mean()
legit_dots = legit_data['dot_count'].mean()
print(f"  Dot Count:         Phishing: {phishing_dots:.2f} | Legitimate: {legit_dots:.2f} | Diff: +{phishing_dots - legit_dots:.2f}")

# Entropy
phishing_entropy = phishing_data['url_entropy'].mean()
legit_entropy = legit_data['url_entropy'].mean()
print(f"  URL Entropy:       Phishing: {phishing_entropy:.2f} | Legitimate: {legit_entropy:.2f} | Diff: +{phishing_entropy - legit_entropy:.2f}")

# Subdomain count
phishing_sub = phishing_data['subdomain_count'].mean()
legit_sub = legit_data['subdomain_count'].mean()
print(f"  Subdomain Count:   Phishing: {phishing_sub:.2f} | Legitimate: {legit_sub:.2f} | Diff: +{phishing_sub - legit_sub:.2f}")

# Digits count
phishing_digits = phishing_data['number_of_digits'].mean()
legit_digits = legit_data['number_of_digits'].mean()
print(f"  Digit Count:       Phishing: {phishing_digits:.1f} | Legitimate: {legit_digits:.1f} | Diff: +{phishing_digits - legit_digits:.1f}")

# Percentage numeric
phishing_percent = phishing_data['percentage_numeric_chars'].mean()
legit_percent = legit_data['percentage_numeric_chars'].mean()
print(f"  % Numeric:         Phishing: {phishing_percent:.1f}% | Legitimate: {legit_percent:.1f}% | Diff: +{phishing_percent - legit_percent:.1f}%")

# Hyphen in domain
phishing_hyphen = phishing_data['has_hyphen_in_domain'].mean() * 100
legit_hyphen = legit_data['has_hyphen_in_domain'].mean() * 100
print(f"  % with Hyphen:     Phishing: {phishing_hyphen:.1f}% | Legitimate: {legit_hyphen:.1f}% | Diff: +{phishing_hyphen - legit_hyphen:.1f}%")

# IP address
phishing_ip = phishing_data['has_ip_address'].mean() * 100
legit_ip = legit_data['has_ip_address'].mean() * 100
print(f"  % using IP:        Phishing: {phishing_ip:.1f}% | Legitimate: {legit_ip:.1f}% | Diff: +{phishing_ip - legit_ip:.1f}%")

# Suspicious TLD
phishing_tld = phishing_data['tld_popularity'].apply(lambda x: 1 if x == 0 else 0).mean() * 100
legit_tld = legit_data['tld_popularity'].apply(lambda x: 1 if x == 0 else 0).mean() * 100
print(f"  % Suspicious TLD:  Phishing: {phishing_tld:.1f}% | Legitimate: {legit_tld:.1f}% | Diff: +{phishing_tld - legit_tld:.1f}%")

# Suspicious file extension
phishing_ext = phishing_data['suspicious_file_extension'].mean() * 100
legit_ext = legit_data['suspicious_file_extension'].mean() * 100
print(f"  % Suspicious Ext:  Phishing: {phishing_ext:.1f}% | Legitimate: {legit_ext:.1f}% | Diff: +{phishing_ext - legit_ext:.1f}%")

# -------------------------
# MODEL INFO
# -------------------------
model_info = {
    "model_name": "Random Forest",
    "accuracy": round(accuracy, 4),
    "roc_auc": round(roc, 4),
    "f1_score": round(f1, 4),
    "threshold": float(best_threshold),
    "trained_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "num_features": X.shape[1],
    "feature_names": X.columns.tolist(),
    "best_params": grid.best_params_,
    "dataset_size": len(df),
    "phishing_samples": int(y.sum()),
    "legitimate_samples": int(len(y) - y.sum())
}

# -------------------------
# SAVE MODEL
# -------------------------
bundle = {
    'model': clf,
    'columns': X.columns.tolist(),
    'threshold': float(best_threshold),
    'model_info': model_info,
    'feature_importance': importance.to_dict()
}

out = BASE / 'detector' / 'ml_model.joblib'
joblib.dump(bundle, out)

print("\n" + "="*60)
print(f"✅ Model saved to: {out}")
print("="*60)

# Optional: Save feature names for reference
feature_names_path = BASE / 'detector' / 'feature_names.txt'
with open(feature_names_path, 'w') as f:
    for col in X.columns:
        f.write(f"{col}\n")
print(f"📄 Feature names saved to: {feature_names_path}")

# Quick validation
print("\n" + "="*60)
print("🔍 QUICK VALIDATION")
print("="*60)

# Test with a few samples from test set
sample_preds = clf.predict(Xte.head())
sample_proba = clf.predict_proba(Xte.head())
print("Sample predictions (first 5 test samples):")
for i, (true, pred, prob) in enumerate(zip(yte.head(), sample_preds, sample_proba[:, 1])):
    result = "✅ CORRECT" if true == pred else "❌ WRONG"
    print(f"  Sample {i+1}: True={true}, Pred={pred}, Prob={prob:.3f} - {result}")

print("\n" + "="*60)
print("✨ TRAINING COMPLETE!")
print("="*60)