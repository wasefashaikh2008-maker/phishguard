# PhishGuard — Website Phishing Detection (Django + ML)

A minimal, working starter for detecting phishing URLs using URL lexical features and a scikit-learn model, wrapped in a Django app.

## 1) Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2) Create DB + Admin
```bash
python manage.py migrate
python manage.py createsuperuser
```

## 3) Train the ML Model
```bash
python train_model.py
```
This creates `detector/ml_model.joblib`.

## 4) Run the Server
```bash
python manage.py runserver
```

Open http://127.0.0.1:8000/ to test.

## 5) How it works
- Features are computed in `detector/features.py` (URL length, dots, hyphens, digits, punycode, IP host, params, brand similarity, etc.)
- Model: `RandomForestClassifier`
- API endpoint: `/api/check/?url=...` returns JSON `{phish_score, label}`
- History is saved to `URLCheck` for authenticated users (visible in **/history** and in **/admin**).

## 6) Improve It
- Replace `dataset/urls_sample.csv` with a bigger dataset.
- Try LightGBM/XGBoost for better AUC.
- Add content-based features (HTML analysis) in a separate pipeline.
- Threshold-tune for your desired recall/FPR.
- Cache results with Redis; add rate limiting.

---
Educational starter; not production-hardened.
