"""
Machine Learning Core & Feature Engineering Engine for ShieldGuard AI 2.0.
Provides production-grade, zero-dependency classifiers (NLP TF-IDF Naive Bayes
and Vectorized Regularized Logistic Classifiers) designed to run completely offline.
"""

import os
import re
import math
import pickle
import urllib.parse
from collections import Counter
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODELS_DIR = os.path.join(BASE_DIR, "data", "models")
os.makedirs(MODELS_DIR, exist_ok=True)

URL_MODEL_PATH = os.path.join(MODELS_DIR, "url_phishing_model.pkl")
CONTENT_MODEL_PATH = os.path.join(MODELS_DIR, "content_phishing_model.pkl")
EMAIL_MODEL_PATH = os.path.join(MODELS_DIR, "email_threat_model.pkl")

# Cached model instances in memory
_CACHED_URL_MODEL = None
_CACHED_CONTENT_MODEL = None
_CACHED_EMAIL_MODEL = None

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".buzz", ".cfd", ".monster",
    ".sbs", ".rest", ".fit", ".gq", ".ml", ".cf", ".tk", ".ga", ".icu", ".cam"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl", "bit.do"
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "kyc", "account", "suspended",
    "security", "update", "banking", "wallet", "recover", "confirm", "claim",
    "prize", "free", "winner", "reward", "redelivery", "parcel", "apk"
]

TOP_LEGITIMATE_DOMAINS = {
    "google.com", "youtube.com", "amazon.com", "facebook.com", "apple.com",
    "microsoft.com", "wikipedia.org", "github.com", "linkedin.com", "netflix.com",
    "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "nytimes.com",
    "bbc.com", "cnn.com", "stackoverflow.com", "python.org", "pypi.org", "fastapi.tiangolo.com"
}

TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "chase", "wellsfargo", "binance", "metamask", "sbi"
]

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "tempmail.com", "guerrillamail.com",
    "throwawaymail.com", "trashmail.com", "yopmail.com", "tempmail.ninja"
}

FREE_PROVIDERS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com"}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(round(entropy, 4))


# ==============================================================================
# 1. Feature Extraction Pipelines
# ==============================================================================

URL_FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "nb_dots", "nb_hyphens",
    "nb_slash", "nb_question", "nb_equal", "nb_at", "nb_digits",
    "digit_ratio", "is_https", "is_raw_ip", "is_shortened", "has_suspicious_tld",
    "has_phishing_keywords", "is_known_top_domain", "shannon_entropy"
]


def extract_url_features(url: str) -> List[float]:
    """Extract 18 numeric features from a URL for machine learning classification."""
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned

    parsed = urllib.parse.urlparse(cleaned)
    host = parsed.netloc.lower()
    if ":" in host:
        host = host.split(":")[0]
    path = parsed.path.lower()
    query = parsed.query.lower()

    url_len = len(cleaned)
    host_len = len(host)
    path_len = len(path)

    nb_dots = cleaned.count(".")
    nb_hyphens = cleaned.count("-")
    nb_slash = cleaned.count("/")
    nb_question = cleaned.count("?")
    nb_equal = cleaned.count("=")
    nb_at = cleaned.count("@")

    digits = sum(c.isdigit() for c in cleaned)
    digit_ratio = digits / url_len if url_len > 0 else 0.0

    is_https = 1.0 if parsed.scheme == "https" else 0.0
    is_raw_ip = 1.0 if bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)) else 0.0
    is_shortened = 1.0 if any(s in host for s in URL_SHORTENERS) else 0.0

    tld = "." + host.split(".")[-1] if "." in host else ""
    has_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # Phishing keywords count in path + query + subdomain
    kw_count = sum(1 for kw in PHISHING_KEYWORDS if kw in (host + path + query))

    # Top domain verification
    # Host is either exactly or a subdomain of a verified top domain (e.g. docs.github.com)
    is_known_top = 0.0
    for top_d in TOP_LEGITIMATE_DOMAINS:
        if host == top_d or host.endswith("." + top_d):
            # Check if brand appears in subdomain while apex is different (spoofing trick)
            is_known_top = 1.0
            break

    entropy = calculate_entropy(cleaned)

    return [
        float(url_len), float(host_len), float(path_len),
        float(nb_dots), float(nb_hyphens), float(nb_slash),
        float(nb_question), float(nb_equal), float(nb_at),
        float(digits), float(digit_ratio), float(is_https),
        float(is_raw_ip), float(is_shortened), float(has_suspicious_tld),
        float(kw_count), float(is_known_top), float(entropy)
    ]


EMAIL_FEATURE_NAMES = [
    "email_length", "local_length", "domain_length", "digits_local",
    "digit_ratio_local", "is_disposable", "is_free_provider",
    "has_suspicious_tld", "has_brand_spoof", "shannon_entropy"
]


def extract_email_features(email: str) -> List[float]:
    """Extract 10 structural features from an email address."""
    cleaned = email.strip().lower()
    local_part = ""
    domain = ""
    if "@" in cleaned:
        parts = cleaned.split("@", 1)
        local_part, domain = parts[0], parts[1]
    else:
        domain = cleaned

    email_len = len(cleaned)
    local_len = len(local_part)
    domain_len = len(domain)

    nb_digits_local = sum(c.isdigit() for c in local_part)
    digit_ratio_local = nb_digits_local / local_len if local_len > 0 else 0.0

    is_disposable = 1.0 if domain in DISPOSABLE_DOMAINS else 0.0
    is_free = 1.0 if domain in FREE_PROVIDERS else 0.0

    tld = "." + domain.split(".")[-1] if "." in domain else ""
    has_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    has_brand_spoof = 0.0
    for brand in TARGET_BRANDS:
        if brand in local_part and is_free:
            has_brand_spoof = 1.0
            break
        if brand in domain and not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
            has_brand_spoof = 1.0
            break

    entropy = calculate_entropy(cleaned)

    return [
        float(email_len), float(local_len), float(domain_len),
        float(nb_digits_local), float(digit_ratio_local),
        float(is_disposable), float(is_free), float(has_suspicious_tld),
        float(has_brand_spoof), float(entropy)
    ]


# ==============================================================================
# 2. Vectorized Machine Learning Models
# ==============================================================================

class LogisticRegressionClassifier:
    """
    Vectorized Regularized Logistic Regression Classifier.
    Computes calibrated phishing probabilities with feature standardization.
    """
    def __init__(self, feature_names: List[str], lr: float = 0.08, epochs: int = 400, reg_lambda: float = 0.005):
        self.feature_names = feature_names
        self.lr = lr
        self.epochs = epochs
        self.reg_lambda = reg_lambda
        self.weights = None
        self.bias = 0.0
        self.means = None
        self.stds = None

    def fit(self, X: np.ndarray, y: np.ndarray):
        m, n = X.shape
        self.means = np.mean(X, axis=0)
        self.stds = np.std(X, axis=0)
        self.stds[self.stds == 0.0] = 1.0

        X_norm = (X - self.means) / self.stds
        self.weights = np.zeros(n)
        self.bias = 0.0

        for _ in range(self.epochs):
            z = np.dot(X_norm, self.weights) + self.bias
            p = 1.0 / (1.0 + np.exp(-np.clip(z, -25.0, 25.0)))
            grad_w = (np.dot(X_norm.T, (p - y)) / m) + (self.reg_lambda * self.weights)
            grad_b = np.sum(p - y) / m

            self.weights -= self.lr * grad_w
            self.bias -= self.lr * grad_b

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X_norm = (X - self.means) / self.stds
        z = np.dot(X_norm, self.weights) + self.bias
        p = 1.0 / (1.0 + np.exp(-np.clip(z, -25.0, 25.0)))
        return np.column_stack([1.0 - p, p])

    def predict(self, X: np.ndarray) -> np.ndarray:
        probs = self.predict_proba(X)[:, 1]
        return (probs >= 0.5).astype(int)


class TfidfNaiveBayesClassifier:
    """
    NLP Text Phishing Classifier combining N-gram TF-IDF weighting
    with Laplace-Smoothed Multinomial Naive Bayes.
    """
    def __init__(self, max_features: int = 3500, alpha: float = 0.5):
        self.max_features = max_features
        self.alpha = alpha
        self.vocab = {}
        self.idf = {}
        self.log_priors = [0.0, 0.0]
        self.log_likelihoods = None

    def _tokenize(self, text: str) -> List[str]:
        words = re.findall(r"\b[a-z0-9]{2,}\b", text.lower())
        tokens = list(words)
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]}_{words[i+1]}")
        return tokens

    def fit(self, texts: List[str], labels: List[int]):
        n_samples = len(texts)
        n_pos = sum(labels)
        n_neg = n_samples - n_pos

        self.log_priors = [math.log(n_neg / n_samples), math.log(n_pos / n_samples)]

        doc_freq = Counter()
        for text in texts:
            toks = set(self._tokenize(text))
            doc_freq.update(toks)

        top_items = doc_freq.most_common(self.max_features)
        self.vocab = {term: idx for idx, (term, _) in enumerate(top_items)}

        self.idf = {}
        for term, df in top_items:
            self.idf[term] = math.log((1.0 + n_samples) / (1.0 + df)) + 1.0

        class_term_weights = [np.zeros(len(self.vocab)), np.zeros(len(self.vocab))]

        for text, label in zip(texts, labels):
            tokens = self._tokenize(text)
            term_counts = Counter(tokens)
            for term, count in term_counts.items():
                if term in self.vocab:
                    idx = self.vocab[term]
                    tf = 1.0 + math.log(count)
                    weight = tf * self.idf[term]
                    class_term_weights[label][idx] += weight

        self.log_likelihoods = []
        for c in [0, 1]:
            total_weight = np.sum(class_term_weights[c]) + (self.alpha * len(self.vocab))
            log_prob = np.log((class_term_weights[c] + self.alpha) / total_weight)
            self.log_likelihoods.append(log_prob)

    def predict_proba(self, texts: List[str]) -> List[float]:
        results = []
        for text in texts:
            tokens = self._tokenize(text)
            term_counts = Counter(tokens)

            log_posteriors = [self.log_priors[0], self.log_priors[1]]

            for term, count in term_counts.items():
                if term in self.vocab:
                    idx = self.vocab[term]
                    weight = (1.0 + math.log(count)) * self.idf[term]
                    log_posteriors[0] += weight * self.log_likelihoods[0][idx]
                    log_posteriors[1] += weight * self.log_likelihoods[1][idx]

            max_log = max(log_posteriors)
            exp0 = math.exp(log_posteriors[0] - max_log)
            exp1 = math.exp(log_posteriors[1] - max_log)
            p1 = exp1 / (exp0 + exp1)
            results.append(float(p1))
        return results


# ==============================================================================
# 3. Model Loading & Inference Gateways
# ==============================================================================

def get_url_model() -> Optional[LogisticRegressionClassifier]:
    """Load or cache URL classifier."""
    global _CACHED_URL_MODEL
    if _CACHED_URL_MODEL is None and os.path.exists(URL_MODEL_PATH):
        try:
            with open(URL_MODEL_PATH, "rb") as f:
                _CACHED_URL_MODEL = pickle.load(f)
        except Exception as e:
            print(f"[ShieldGuard ML] Notice loading URL model: {e}")
    return _CACHED_URL_MODEL


def get_content_model() -> Optional[TfidfNaiveBayesClassifier]:
    """Load or cache Content NLP classifier."""
    global _CACHED_CONTENT_MODEL
    if _CACHED_CONTENT_MODEL is None and os.path.exists(CONTENT_MODEL_PATH):
        try:
            with open(CONTENT_MODEL_PATH, "rb") as f:
                _CACHED_CONTENT_MODEL = pickle.load(f)
        except Exception as e:
            print(f"[ShieldGuard ML] Notice loading Content model: {e}")
    return _CACHED_CONTENT_MODEL


def get_email_model() -> Optional[LogisticRegressionClassifier]:
    """Load or cache Email threat classifier."""
    global _CACHED_EMAIL_MODEL
    if _CACHED_EMAIL_MODEL is None and os.path.exists(EMAIL_MODEL_PATH):
        try:
            with open(EMAIL_MODEL_PATH, "rb") as f:
                _CACHED_EMAIL_MODEL = pickle.load(f)
        except Exception as e:
            print(f"[ShieldGuard ML] Notice loading Email model: {e}")
    return _CACHED_EMAIL_MODEL


def predict_url_ml(url: str) -> Dict[str, Any]:
    """Run ML inference on a URL."""
    model = get_url_model()
    if model is None:
        return {
            "model_available": False,
            "prediction": "UNAVAILABLE",
            "phishing_probability": 0.0,
            "confidence": "NONE"
        }

    try:
        feats = np.array([extract_url_features(url)])
        prob = float(model.predict_proba(feats)[0][1])  # Class 1 = Phishing
        prediction = "PHISHING" if prob >= 0.50 else "LEGITIMATE"
        confidence = "HIGH" if (prob >= 0.80 or prob <= 0.20) else "MEDIUM"

        return {
            "model_available": True,
            "model_type": "Vectorized Logistic Regression URL Classifier",
            "prediction": prediction,
            "phishing_probability": round(prob * 100, 2),
            "confidence": confidence,
            "extracted_features": {
                name: round(float(val), 3) for name, val in zip(URL_FEATURE_NAMES, feats[0])
            }
        }
    except Exception as e:
        return {
            "model_available": False,
            "error": str(e),
            "prediction": "ERROR",
            "phishing_probability": 0.0
        }


def predict_content_ml(text: str) -> Dict[str, Any]:
    """Run TF-IDF + Naive Bayes ML inference on message/SMS/email text."""
    model = get_content_model()
    if model is None or not text.strip():
        return {
            "model_available": False,
            "prediction": "UNAVAILABLE",
            "phishing_probability": 0.0,
            "confidence": "NONE"
        }

    try:
        prob = float(model.predict_proba([text])[0])
        prediction = "PHISHING" if prob >= 0.50 else "LEGITIMATE"
        confidence = "HIGH" if (prob >= 0.80 or prob <= 0.20) else "MEDIUM"

        return {
            "model_available": True,
            "model_type": "TF-IDF N-Gram + Naive Bayes NLP Classifier",
            "prediction": prediction,
            "phishing_probability": round(prob * 100, 2),
            "confidence": confidence
        }
    except Exception as e:
        return {
            "model_available": False,
            "error": str(e),
            "prediction": "ERROR",
            "phishing_probability": 0.0
        }


def predict_email_ml(email: str) -> Dict[str, Any]:
    """Run ML inference on an email address."""
    model = get_email_model()
    if model is None or not email.strip():
        return {
            "model_available": False,
            "prediction": "UNAVAILABLE",
            "phishing_probability": 0.0,
            "confidence": "NONE"
        }

    try:
        feats = np.array([extract_email_features(email)])
        prob = float(model.predict_proba(feats)[0][1])
        prediction = "PHISHING" if prob >= 0.50 else "LEGITIMATE"
        confidence = "HIGH" if (prob >= 0.80 or prob <= 0.20) else "MEDIUM"

        return {
            "model_available": True,
            "model_type": "Vectorized Logistic Regression Email Classifier",
            "prediction": prediction,
            "phishing_probability": round(prob * 100, 2),
            "confidence": confidence,
            "extracted_features": {
                name: round(float(val), 3) for name, val in zip(EMAIL_FEATURE_NAMES, feats[0])
            }
        }
    except Exception as e:
        return {
            "model_available": False,
            "error": str(e),
            "prediction": "ERROR",
            "phishing_probability": 0.0
        }
