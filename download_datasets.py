"""
Automated Offline Dataset Downloader & Curated Threat Corpus Generator
Downloads public benchmark datasets for ShieldGuard AI:
1. UCI SMS Spam & Smishing Dataset
2. OpenPhish & PhishTank URL Datasets
3. Typosquatting & Disposable Email Datasets
4. Telecom & Phone Scam Intelligence Dataset
5. Comprehensive Test Inputs Dataset (for easy tracking and verification)
"""

import os
import sys
import csv
import json
import urllib.request
import math

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "data", "datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)


def download_sms_dataset() -> str:
    """Download the UCI SMS Spam & Phishing Collection dataset."""
    dest_path = os.path.join(DATASETS_DIR, "sms_spam_dataset.csv")
    url = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"
    
    print("[-] Fetching UCI SMS Spam & Phishing dataset...")
    records = []
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                if "\t" in line:
                    label_str, text = line.split("\t", 1)
                    label = 1 if label_str.strip().lower() == "spam" else 0
                    records.append({"label": label, "category": "spam" if label == 1 else "ham", "text": text.strip()})
        print(f"[+] Successfully downloaded {len(records)} UCI SMS records!")
    except Exception as e:
        print(f"[!] Warning: Could not download live UCI SMS dataset ({e}). Generating curated offline corpus...")

    # Enrich with specialized cyber-attack and banking KYC/OTP phishing templates
    cyber_phishing_samples = [
        {"label": 1, "category": "bank_kyc", "text": "Dear customer, your SBI account has been locked. Click http://sbi-kyc-update.xyz/verify to update PAN and unblock within 24 hours."},
        {"label": 1, "category": "bank_kyc", "text": "HDFC Bank Alert: Your netbanking is suspended due to pending KYC. Submit your Aadhaar at http://hdfc-netbanking-verify.top now."},
        {"label": 1, "category": "otp_theft", "text": "Dear customer, your OTP for transaction of Rs 48,990 is 849201. If not done by you, visit http://192.168.1.105/dispute to cancel."},
        {"label": 1, "category": "lottery_fraud", "text": "CONGRATULATIONS! You won $2,500,000 in Mega Millions lottery draw. Call +18765550199 or email claim@megawin-prize.click to claim."},
        {"label": 1, "category": "tech_support", "text": "CRITICAL ALERT: Microsoft Defender detected Trojan virus in your computer. Call toll-free +1-800-555-0143 immediately to avoid data loss."},
        {"label": 1, "category": "fake_job", "text": "Earn $200-$500 daily by liking YouTube videos and completing simple remote tasks. Contact WhatsApp +447012345678 to start today."},
        {"label": 1, "category": "courier_trap", "text": "USPS: Your package could not be delivered due to incomplete address. Pay $1.99 redelivery fee at http://usps-redelivery-tracking.buzz/parcel."},
        {"label": 1, "category": "crypto_doubler", "text": "Double your Bitcoin! Send 0.1 BTC to official Elon Musk promo wallet and receive 0.2 BTC back instantly at http://musk-crypto-promo.work"},
        {"label": 1, "category": "utility_fraud", "text": "Electricity Alert: Your power supply will be disconnected tonight at 9:30 PM due to unpaid bill. Call our officer at 9876543210 immediately."},
        {"label": 0, "category": "legitimate", "text": "Hi Mom, I will be home for dinner around 7 PM today. See you soon!"},
        {"label": 0, "category": "legitimate", "text": "Your Amazon package with order #402-8921892 has been dispatched and will arrive tomorrow by 8 PM."},
        {"label": 0, "category": "legitimate", "text": "Meeting reminder: Q3 project review is scheduled for tomorrow at 10:00 AM on Google Meet."},
        {"label": 0, "category": "legitimate", "text": "Hey, could you please review the attached draft when you have a free moment? Thanks!"},
        {"label": 0, "category": "legitimate", "text": "Your GitHub verification code is 492018. It expires in 10 minutes."}
    ]
    records.extend(cyber_phishing_samples)

    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["label", "category", "text"])
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Saved SMS dataset to {dest_path} (Total: {len(records)} records)")
    return dest_path


def download_url_dataset() -> str:
    """Download and curate Phishing and Legitimate URLs dataset."""
    dest_path = os.path.join(DATASETS_DIR, "url_phishing_dataset.csv")
    print("[-] Compiling URL Phishing & Legitimate benchmark dataset...")
    
    urls_data = []
    seen = set()

    # 1. Fetch live OpenPhish URLs
    try:
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                u = line.strip()
                if u and u not in seen:
                    seen.add(u)
                    urls_data.append({"url": u, "label": 1, "source": "openphish_live"})
        print(f"[+] Fetched {len(urls_data)} live phishing URLs from OpenPhish!")
    except Exception as e:
        print(f"[!] OpenPhish live feed notice: {e}")

    # 2. Fetch curated legitimate and phishing dataset from academic repo
    academic_sources = [
        ("https://raw.githubusercontent.com/jishnusaurav/Phishing-attack-PCAP-analysis-using-scapy/master/Phishing-Website-Detection/datasets/phishing-urls.csv", 1, "academic_phish"),
        ("https://raw.githubusercontent.com/jishnusaurav/Phishing-attack-PCAP-analysis-using-scapy/master/Phishing-Website-Detection/datasets/legitimate-urls.csv", 0, "academic_legit")
    ]

    for source_url, label, src_name in academic_sources:
        try:
            req = urllib.request.Request(source_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                reader = csv.DictReader(resp.read().decode("utf-8", errors="ignore").splitlines())
                for row in reader:
                    domain = row.get("Domain", "").strip()
                    path = row.get("Path", "").strip()
                    proto = row.get("Protocol", "http").strip()
                    if domain:
                        full_u = f"{proto}://{domain}{path}"
                        if full_u not in seen:
                            seen.add(full_u)
                            urls_data.append({"url": full_u, "label": label, "source": src_name})
        except Exception as e:
            print(f"[!] Warning reading academic source {src_name}: {e}")

    # 3. Supplemental High-Risk Phishing Patterns & Top Benign Sites
    high_value_phishing = [
        "http://paypal.com.account-verification-service.xyz/login.php",
        "https://micros0ft-online-security.net/auth/session-renew",
        "http://192.168.1.105:8080/bank-kyc/update-pan.html",
        "http://apple-support.id-verification.top/confirm",
        "https://chase-bank-verify.click/signin/restore",
        "http://amazon-account-reverification.buzz/security",
        "https://binance-wallet-recovery.cfd/connect",
        "http://netflix-billing-update.work/update-card",
        "http://google-drive-shared-doc.top/document-view",
        "http://paypa1-update.com/signin?cmd=_login-run",
        "http://wellsfargo-account-locked.xyz/auth",
        "http://fedx-parcel-clearance.buzz/pay-fee",
        "https://secure-metamask-io-wallet.click/phrase",
        "http://sbi-online-kyc-portal.click/debitcard-pin",
        "http://bit.ly/3x89Akyc-update-blocked",
        "http://tinyurl.com/bank-urgent-unfreeze"
    ]
    for u in high_value_phishing:
        if u not in seen:
            seen.add(u)
            urls_data.append({"url": u, "label": 1, "source": "threat_intel_seed"})

    top_legitimate = [
        "https://www.google.com/search?q=machine+learning",
        "https://github.com/fastapi/fastapi",
        "https://www.wikipedia.org/wiki/Phishing",
        "https://www.amazon.com/gp/bestsellers",
        "https://www.microsoft.com/en-us/security",
        "https://www.paypal.com/signin",
        "https://apple.com/iphone",
        "https://netflix.com/browse",
        "https://stackoverflow.com/questions",
        "https://developer.mozilla.org/en-US/docs/Web",
        "https://www.nytimes.com/section/technology",
        "https://www.bbc.com/news",
        "https://www.linkedin.com/feed",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://drive.google.com/drive/my-drive",
        "https://pypi.org/project/scikit-learn/",
        "https://scikit-learn.org/stable/modules/classes.html",
        "https://www.mit.edu/research",
        "https://stanford.edu/academics",
        "https://hub.docker.com/_/python"
    ]
    for u in top_legitimate:
        if u not in seen:
            seen.add(u)
            urls_data.append({"url": u, "label": 0, "source": "tranco_top_seed"})

    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "source"])
        writer.writeheader()
        writer.writerows(urls_data)

    print(f"[+] Saved URL dataset to {dest_path} (Total: {len(urls_data)} URLs)")
    return dest_path


def create_email_threat_dataset() -> str:
    """Create curated dataset of legitimate vs spoofed, disposable, and typosquatting emails."""
    dest_path = os.path.join(DATASETS_DIR, "email_threats_dataset.csv")
    print("[-] Generating Email Threat & Typosquatting dataset...")

    records = [
        # Phishing / Malicious Emails (label=1)
        {"email": "security@paypa1-update.com", "label": 1, "category": "homoglyph_typosquatting"},
        {"email": "account-alert@micros0ft-security.net", "label": 1, "category": "homoglyph_typosquatting"},
        {"email": "support@binance-helpdesk-auth.top", "label": 1, "category": "suspicious_tld_brand"},
        {"email": "kyc-update@sbi-online-portal.click", "label": 1, "category": "banking_kyc_phish"},
        {"email": "tracking@fedx-delivery-parcel.xyz", "label": 1, "category": "courier_fraud"},
        {"email": "billing@netflix-subscription-renew.work", "label": 1, "category": "subscription_phish"},
        {"email": "claim@winner-lottery-mega.buzz", "label": 1, "category": "lottery_fraud"},
        {"email": "officer@chase-secure-banking.cfd", "label": 1, "category": "banking_spoof"},
        {"email": "urgent-notice@irs-tax-refund.top", "label": 1, "category": "government_impersonation"},
        {"email": "user98421@mailinator.com", "label": 1, "category": "disposable_burner"},
        {"email": "temp4891@10minutemail.com", "label": 1, "category": "disposable_burner"},
        {"email": "scam99@guerrillamail.com", "label": 1, "category": "disposable_burner"},
        {"email": "burner84@tempmail.ninja", "label": 1, "category": "disposable_burner"},
        {"email": "fakebox@throwawaymail.com", "label": 1, "category": "disposable_burner"},
        {"email": "paypal-support-team@gmail.com", "label": 1, "category": "free_webmail_corporate_spoof"},
        {"email": "microsoft-helpdesk@yahoo.com", "label": 1, "category": "free_webmail_corporate_spoof"},
        {"email": "apple-id-recovery@outlook.com", "label": 1, "category": "free_webmail_corporate_spoof"},
        {"email": "amazon-fraud-prevention@hotmail.com", "label": 1, "category": "free_webmail_corporate_spoof"},
        {"email": "support@arnazon.com", "label": 1, "category": "edit_distance_typo"},
        {"email": "verify@netflx.com", "label": 1, "category": "edit_distance_typo"},
        {"email": "service@g00gle.com", "label": 1, "category": "homoglyph_typo"},
        {"email": "alert@chasee.com", "label": 1, "category": "edit_distance_typo"},

        # Legitimate / Clean Emails (label=0)
        {"email": "service@paypal.com", "label": 0, "category": "official_corporate"},
        {"email": "no-reply@microsoft.com", "label": 0, "category": "official_corporate"},
        {"email": "support@github.com", "label": 0, "category": "official_corporate"},
        {"email": "notifications@google.com", "label": 0, "category": "official_corporate"},
        {"email": "order-update@amazon.com", "label": 0, "category": "official_corporate"},
        {"email": "info@netflix.com", "label": 0, "category": "official_corporate"},
        {"email": "contact@apple.com", "label": 0, "category": "official_corporate"},
        {"email": "customer.service@chase.com", "label": 0, "category": "official_corporate"},
        {"email": "alerts@wellsfargo.com", "label": 0, "category": "official_corporate"},
        {"email": "john.doe@gmail.com", "label": 0, "category": "clean_personal"},
        {"email": "sarah.miller@yahoo.com", "label": 0, "category": "clean_personal"},
        {"email": "alex_student@stanford.edu", "label": 0, "category": "academic_edu"},
        {"email": "research@mit.edu", "label": 0, "category": "academic_edu"},
        {"email": "help@fastapi.tiangolo.com", "label": 0, "category": "clean_domain"},
        {"email": "contact@python.org", "label": 0, "category": "non_profit_org"}
    ]

    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["email", "label", "category"])
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Saved Email Threat dataset to {dest_path} (Total: {len(records)} records)")
    return dest_path


def create_phone_threat_dataset() -> str:
    """Create curated dataset of phone numbers with risk levels and fraud classifications."""
    dest_path = os.path.join(DATASETS_DIR, "phone_threats_dataset.csv")
    print("[-] Generating Phone Scam & Telecom Threat dataset...")

    records = [
        # Scam / High Risk Numbers (label=1)
        {"phone_number": "+18765550199", "label": 1, "fraud_type": "lottery_scam_jamaica", "country": "Jamaica", "risk_level": "CRITICAL"},
        {"phone_number": "+18005550143", "label": 1, "fraud_type": "tech_support_toll_free", "country": "US", "risk_level": "CRITICAL"},
        {"phone_number": "+919876543210", "label": 1, "fraud_type": "bank_kyc_electricity_fraud", "country": "India", "risk_level": "HIGH"},
        {"phone_number": "+12845550188", "label": 1, "fraud_type": "wangiri_bvi_toll_trap", "country": "British Virgin Islands", "risk_level": "CRITICAL"},
        {"phone_number": "+447012345678", "label": 1, "fraud_type": "fake_task_whatsapp_scam", "country": "UK", "risk_level": "HIGH"},
        {"phone_number": "+23299887766", "label": 1, "fraud_type": "wangiri_sierra_leone", "country": "Sierra Leone", "risk_level": "CRITICAL"},
        {"phone_number": "+22466554433", "label": 1, "fraud_type": "wangiri_guinea", "country": "Guinea", "risk_level": "CRITICAL"},
        {"phone_number": "+18095550122", "label": 1, "fraud_type": "caribbean_toll_trap_dominican", "country": "Dominican Republic", "risk_level": "HIGH"},
        {"phone_number": "+19005550199", "label": 1, "fraud_type": "premium_rate_billing_trap", "country": "US", "risk_level": "CRITICAL"},
        {"phone_number": "+15550000000", "label": 1, "fraud_type": "synthetic_spoofed_caller_id", "country": "US", "risk_level": "HIGH"},
        {"phone_number": "+12345678901", "label": 1, "fraud_type": "sequential_spoof_pattern", "country": "US", "risk_level": "HIGH"},

        # Legitimate / Clean Numbers (label=0)
        {"phone_number": "+16502530000", "label": 0, "fraud_type": "clean_google_headquarters", "country": "US", "risk_level": "SAFE"},
        {"phone_number": "+14258828080", "label": 0, "fraud_type": "clean_microsoft_headquarters", "country": "US", "risk_level": "SAFE"},
        {"phone_number": "+18002752273", "label": 0, "fraud_type": "official_apple_support", "country": "US", "risk_level": "SAFE"},
        {"phone_number": "+18009359935", "label": 0, "fraud_type": "official_chase_customer_service", "country": "US", "risk_level": "SAFE"},
        {"phone_number": "+918022221111", "label": 0, "fraud_type": "clean_bangalore_landline", "country": "India", "risk_level": "SAFE"},
        {"phone_number": "+442079460912", "label": 0, "fraud_type": "clean_london_business", "country": "UK", "risk_level": "SAFE"},
        {"phone_number": "+14155552671", "label": 0, "fraud_type": "clean_california_mobile", "country": "US", "risk_level": "SAFE"}
    ]

    with open(dest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["phone_number", "label", "fraud_type", "country", "risk_level"])
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Saved Phone Threat dataset to {dest_path} (Total: {len(records)} records)")
    return dest_path


def create_sample_test_inputs() -> str:
    """
    Generate sample test inputs file so users can easily copy, enter, 
    and track scans across all vector scanners.
    """
    dest_json = os.path.join(DATASETS_DIR, "sample_test_inputs.json")
    dest_csv = os.path.join(DATASETS_DIR, "sample_test_inputs.csv")

    test_data = {
        "url_scanner_samples": [
            {
                "id": "url-01",
                "label": "PHISHING",
                "target": "http://paypal.com.account-verification-service.xyz/login.php",
                "description": "Deceptive subdomain spoofing PayPal with suspicious .xyz TLD and login lure",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "url-02",
                "label": "PHISHING",
                "target": "http://192.168.1.55/sbi-kyc-download.apk",
                "description": "Raw IP address link hosting Android banking malware dropper",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "url-03",
                "label": "PHISHING",
                "target": "https://micros0ft-online-security.net/auth/login",
                "description": "Homoglyph character substitution (0 for o) targeting Microsoft",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "url-04",
                "label": "LEGITIMATE",
                "target": "https://www.google.com/search?q=cybersecurity+defense",
                "description": "Clean authoritative Google search URL",
                "expected_verdict": "SAFE"
            },
            {
                "id": "url-05",
                "label": "LEGITIMATE",
                "target": "https://github.com/fastapi/fastapi",
                "description": "Official GitHub open source repository link",
                "expected_verdict": "SAFE"
            }
        ],
        "content_scanner_samples": [
            {
                "id": "content-01",
                "label": "PHISHING / SCAM",
                "target": "Dear customer, your SBI account has been locked. Click http://sbi-kyc-update.xyz/verify to update PAN within 24 hours.",
                "description": "Urgency manipulation with fake bank KYC suspension threat",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "content-02",
                "label": "PHISHING / SCAM",
                "target": "Congratulations! You have won $2,500,000 in Mega Millions lottery draw. Call +18765550199 or email claim@megawin-prize.click to claim.",
                "description": "Fake prize lottery scam with advance fee request",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "content-03",
                "label": "PHISHING / SCAM",
                "target": "USPS: Your package could not be delivered due to incomplete address. Pay $1.99 redelivery fee at http://usps-redelivery.buzz/parcel immediately.",
                "description": "Courier delivery clearance fee phishing trap",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "content-04",
                "label": "LEGITIMATE",
                "target": "Hi Sarah, our team meeting is scheduled for tomorrow at 10 AM in Conference Room B. Please find the agenda attached.",
                "description": "Standard business workplace meeting message",
                "expected_verdict": "SAFE"
            },
            {
                "id": "content-05",
                "label": "LEGITIMATE",
                "target": "Your Amazon order #402-9817291 has shipped and will arrive Thursday. Track your package in the official app.",
                "description": "Legitimate automated shipment notification",
                "expected_verdict": "SAFE"
            }
        ],
        "email_scanner_samples": [
            {
                "id": "email-01",
                "label": "PHISHING / SPOOFED",
                "target": "security@paypa1-update.com",
                "description": "Homoglyph brand spoofing substituting 1 for l targeting PayPal",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "email-02",
                "label": "DISPOSABLE / SUSPICIOUS",
                "target": "user98421@mailinator.com",
                "description": "Disposable burner inbox domain frequently abused by spammers",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "email-03",
                "label": "FREE WEBMAIL SPOOF",
                "target": "microsoft-support-team@gmail.com",
                "description": "Free webmail address pretending to be official corporate IT department",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "email-04",
                "label": "LEGITIMATE",
                "target": "service@paypal.com",
                "description": "Official authentic PayPal corporate email",
                "expected_verdict": "SAFE"
            },
            {
                "id": "email-05",
                "label": "LEGITIMATE",
                "target": "alex_student@stanford.edu",
                "description": "Verified academic institution email address",
                "expected_verdict": "SAFE"
            }
        ],
        "phone_scanner_samples": [
            {
                "id": "phone-01",
                "label": "SCAM / TOLL TRAP",
                "target": "+18765550199",
                "description": "High-risk Jamaica area code (+1-876) known for Mega Millions lottery traps",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "phone-02",
                "label": "TECH SUPPORT SCAM",
                "target": "+18005550143",
                "description": "Toll-free 1-800 number reported for AnyDesk fake Windows Defender alerts",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "phone-03",
                "label": "WANGIRI FRAUD",
                "target": "+12845550188",
                "description": "British Virgin Islands (+1-284) one-ring callback billing trap",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "phone-04",
                "label": "LEGITIMATE",
                "target": "+18002752273",
                "description": "Official Apple Support toll-free contact number",
                "expected_verdict": "SAFE"
            },
            {
                "id": "phone-05",
                "label": "LEGITIMATE",
                "target": "+16502530000",
                "description": "Official Google Headquarters landline in Mountain View, CA",
                "expected_verdict": "SAFE"
            }
        ],
        "qr_scanner_samples": [
            {
                "id": "qr-01",
                "label": "QUISHING LINK",
                "target": "http://paypa1-verification-portal.xyz/login",
                "description": "QR code embedding malicious homoglyph credential harvesting URL",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "qr-02",
                "label": "QUISHING CALL TRAP",
                "target": "tel:+18765550199",
                "description": "QR code initiating international toll fraud callback",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "qr-03",
                "label": "LEGITIMATE QR LINK",
                "target": "https://www.google.com",
                "description": "QR code encoding safe standard URL",
                "expected_verdict": "SAFE"
            }
        ],
        "combined_multi_vector_samples": [
            {
                "id": "multi-01",
                "label": "MULTI-VECTOR ATTACK",
                "sender_phone": "+18765550199",
                "sender_email": "security@paypa1-update.com",
                "message_text": "URGENT: Your account has been suspended due to suspicious activity. Verify KYC immediately at http://paypa1-verification-portal.xyz/login to avoid permanent block.",
                "description": "Coordinated campaign: Jamaican toll trap + homoglyph email + phishing URL",
                "expected_verdict": "DANGEROUS"
            },
            {
                "id": "multi-02",
                "label": "CLEAN WORKPLACE NOTICE",
                "sender_phone": "+16502530000",
                "sender_email": "notifications@google.com",
                "message_text": "Your weekly security summary is ready to review. Log in to your Google Admin console for details.",
                "description": "Legitimate enterprise security summary from official channels",
                "expected_verdict": "SAFE"
            }
        ]
    }

    with open(dest_json, "w", encoding="utf-8") as f:
        json.dump(test_data, f, indent=2)

    # Also write a flattened CSV for easy spreadsheet viewing
    csv_rows = []
    for vector, items in test_data.items():
        for it in items:
            csv_rows.append({
                "vector": vector.replace("_samples", ""),
                "id": it.get("id"),
                "label": it.get("label"),
                "target": it.get("target") or it.get("message_text"),
                "expected_verdict": it.get("expected_verdict"),
                "description": it.get("description")
            })

    with open(dest_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["vector", "id", "label", "target", "expected_verdict", "description"])
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"[+] Saved sample test inputs to {dest_json} and {dest_csv}")
    return dest_json


def main():
    print("=" * 70)
    print(" ShieldGuard AI 2.0 - Offline Dataset Acquisition & Curation")
    print("=" * 70)
    
    download_sms_dataset()
    download_url_dataset()
    create_email_threat_dataset()
    create_phone_threat_dataset()
    create_sample_test_inputs()

    print("\n[SUCCESS] All datasets have been downloaded and saved offline:")
    for fname in os.listdir(DATASETS_DIR):
        fpath = os.path.join(DATASETS_DIR, fname)
        size_kb = os.path.getsize(fpath) / 1024
        print(f"  * {fname:32} ({size_kb:.1f} KB)")
    print("=" * 70)


if __name__ == "__main__":
    main()
