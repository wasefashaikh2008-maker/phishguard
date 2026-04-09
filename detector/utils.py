import re
from urllib.parse import urlparse


# ===============================
# FEATURE EXTRACTION
# ===============================
def extract_features(url):
    parsed = urlparse(url)

    features = {
        "url_length": len(url),
        "has_ip_address": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "https_flag": 1 if parsed.scheme == "https" else 0,
        "subdomain_count": len(parsed.netloc.split(".")) - 2,
        "suspicious_file_extension": 1 if any(ext in url for ext in [".exe", ".zip", ".rar"]) else 0,
        "percentage_numeric_chars": sum(c.isdigit() for c in url) / len(url),
    }

    return features


# ===============================
# FAKE MODEL (Replace later with ML)
# ===============================
def check_url_with_model(url):
    features = extract_features(url)

    risk_score = 0

    if features["has_ip_address"]:
        risk_score += 0.3

    if features["url_length"] > 75:
        risk_score += 0.2

    if features["https_flag"] == 0:
        risk_score += 0.2

    if features["subdomain_count"] > 3:
        risk_score += 0.2

    if features["suspicious_file_extension"]:
        risk_score += 0.3

    risk_score = min(risk_score, 1.0)

    if risk_score > 0.5:
        return "Phishing", risk_score
    else:
        return "Legitimate", risk_score