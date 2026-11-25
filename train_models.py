"""
ShieldGuard AI 2.0 - Machine Learning Model Training Pipeline
Trains high-performance, zero-dependency classifiers on offline datasets:
1. URL Phishing Classifier (Vectorized Logistic Regression on 16 Lexical/Structural Features)
2. Content NLP Classifier (TF-IDF N-Grams + Laplace Naive Bayes)
3. Email Threat Classifier (Vectorized Logistic Regression on Domain/Homoglyph Features)
"""

import os
import sys
import csv
import pickle
import math
from typing import List, Tuple
import numpy as np

# Ensure root import paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from app.engines.ml_engine import (
    extract_url_features, extract_email_features,
    LogisticRegressionClassifier, TfidfNaiveBayesClassifier,
    URL_FEATURE_NAMES, EMAIL_FEATURE_NAMES,
    URL_MODEL_PATH, CONTENT_MODEL_PATH, EMAIL_MODEL_PATH,
    MODELS_DIR
)

DATASETS_DIR = os.path.join(CURRENT_DIR, "data", "datasets")
os.makedirs(MODELS_DIR, exist_ok=True)


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[float, float, float, float]:
    """Calculate accuracy, precision, recall, and f1 score."""
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    tp = np.sum((y_true == 1) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))

    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return float(accuracy), float(precision), float(recall), float(f1)


def train_url_model():
    """Train Vectorized Logistic URL Phishing Classifier."""
    dataset_file = os.path.join(DATASETS_DIR, "url_phishing_dataset.csv")
    if not os.path.exists(dataset_file):
        print(f"[!] URL dataset missing at {dataset_file}. Please run download_datasets.py first.")
        return None

    print("\n" + "=" * 65)
    print(" [1/3] Training URL Phishing Classifier (Vectorized ML)")
    print("=" * 65)

    urls = []
    labels = []

    with open(dataset_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            u = row.get("url", "").strip()
            l_str = row.get("label", "").strip()
            if u and l_str in ["0", "1"]:
                urls.append(u)
                labels.append(int(l_str))

    print(f"[-] Loaded {len(urls)} URLs (Phishing: {labels.count(1)}, Legitimate: {labels.count(0)})")
    print("[-] Extracting 16 lexical, structural, and entropy features...")

    X = np.array([extract_url_features(u) for u in urls])
    y = np.array(labels)

    # Train/Test Split (80/20)
    indices = np.arange(len(y))
    np.random.seed(42)
    np.random.shuffle(indices)
    split_idx = int(0.8 * len(y))

    train_idx, test_idx = indices[:split_idx], indices[split_idx:]
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    clf = LogisticRegressionClassifier(URL_FEATURE_NAMES, lr=0.1, epochs=400, reg_lambda=0.005)
    print("[-] Optimizing regularized logistic loss via gradient descent...")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc, prec, rec, f1 = calculate_metrics(y_test, y_pred)

    print(f"[+] Evaluation on Test Split ({len(y_test)} URLs):")
    print(f"    * Accuracy:  {acc * 100:.2f}%")
    print(f"    * Precision: {prec * 100:.2f}%")
    print(f"    * Recall:    {rec * 100:.2f}%")
    print(f"    * F1-Score:  {f1 * 100:.2f}%")

    with open(URL_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved to: {URL_MODEL_PATH}")
    return clf


def train_content_model():
    """Train TF-IDF + Naive Bayes Content / Message Phishing Classifier."""
    dataset_file = os.path.join(DATASETS_DIR, "sms_spam_dataset.csv")
    if not os.path.exists(dataset_file):
        print(f"[!] Content dataset missing at {dataset_file}. Please run download_datasets.py first.")
        return None

    print("\n" + "=" * 65)
    print(" [2/3] Training Content NLP Classifier (TF-IDF + Naive Bayes)")
    print("=" * 65)

    texts = []
    labels = []

    with open(dataset_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = row.get("text", "").strip()
            l_str = row.get("label", "").strip()
            if t and l_str in ["0", "1"]:
                texts.append(t)
                labels.append(int(l_str))

    print(f"[-] Loaded {len(texts)} messages (Spam/Phishing: {labels.count(1)}, Legitimate: {labels.count(0)})")

    # Train/Test Split (80/20)
    indices = np.arange(len(labels))
    np.random.seed(42)
    np.random.shuffle(indices)
    split_idx = int(0.8 * len(labels))

    train_idx, test_idx = indices[:split_idx], indices[split_idx:]
    X_train = [texts[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    X_test = [texts[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]

    clf = TfidfNaiveBayesClassifier(max_features=3500, alpha=0.5)
    print("[-] Building vocabulary, computing N-Gram TF-IDF weights and log-likelihoods...")
    clf.fit(X_train, y_train)

    probs = clf.predict_proba(X_test)
    y_pred = np.array([1 if p >= 0.5 else 0 for p in probs])
    acc, prec, rec, f1 = calculate_metrics(np.array(y_test), y_pred)

    print(f"[+] Evaluation on Test Split ({len(y_test)} messages):")
    print(f"    * Accuracy:  {acc * 100:.2f}%")
    print(f"    * Precision: {prec * 100:.2f}%")
    print(f"    * Recall:    {rec * 100:.2f}%")
    print(f"    * F1-Score:  {f1 * 100:.2f}%")

    with open(CONTENT_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved to: {CONTENT_MODEL_PATH}")
    return clf


def train_email_model():
    """Train Vectorized Logistic Email Threat Classifier."""
    dataset_file = os.path.join(DATASETS_DIR, "email_threats_dataset.csv")
    if not os.path.exists(dataset_file):
        print(f"[!] Email dataset missing at {dataset_file}. Please run download_datasets.py first.")
        return None

    print("\n" + "=" * 65)
    print(" [3/3] Training Email Threat Classifier (Vectorized ML)")
    print("=" * 65)

    emails = []
    labels = []

    with open(dataset_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            e = row.get("email", "").strip()
            l_str = row.get("label", "").strip()
            if e and l_str in ["0", "1"]:
                emails.append(e)
                labels.append(int(l_str))

    print(f"[-] Loaded {len(emails)} email records (Phishing/Spoofed: {labels.count(1)}, Legitimate: {labels.count(0)})")

    X = np.array([extract_email_features(e) for e in emails])
    y = np.array(labels)

    clf = LogisticRegressionClassifier(EMAIL_FEATURE_NAMES, lr=0.15, epochs=350, reg_lambda=0.01)
    clf.fit(X, y)

    y_pred = clf.predict(X)
    acc, prec, rec, f1 = calculate_metrics(y, y_pred)

    print(f"[+] Training Performance ({len(y)} samples):")
    print(f"    * Accuracy:  {acc * 100:.2f}%")
    print(f"    * Precision: {prec * 100:.2f}%")
    print(f"    * Recall:    {rec * 100:.2f}%")
    print(f"    * F1-Score:  {f1 * 100:.2f}%")

    with open(EMAIL_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved to: {EMAIL_MODEL_PATH}")
    return clf


def main():
    print("=" * 70)
    print(" ShieldGuard AI 2.0 - Machine Learning Model Training Pipeline")
    print("=" * 70)

    train_url_model()
    train_content_model()
    train_email_model()

    print("\n" + "=" * 70)
    print("[SUCCESS] All Machine Learning Models Successfully Trained and Saved!")
    for fname in os.listdir(MODELS_DIR):
        fpath = os.path.join(MODELS_DIR, fname)
        size_kb = os.path.getsize(fpath) / 1024
        print(f"  * {fname:32} ({size_kb:.1f} KB)")
    print("=" * 70)


if __name__ == "__main__":
    main()
