"""
Message, SMS, and Email Body Content Phishing & Scam Scanner.
Analyzes message text for social engineering, urgency triggers, financial fraud patterns, and malicious links.
"""

import re
from typing import Dict, Any, List, Set
from app.data.brand_patterns import TARGET_BRANDS
from app.data.disposable_domains import SUSPICIOUS_TLDS
from app.database import log_scan

# Scam pattern categories and associated regular expression triggers
SCAM_CATEGORIES = {
    "Bank KYC & Account Suspension": [
        r"\b(account|card|debit card|credit card)\s+(is|has been|will be)\s+(blocked|suspended|disabled|frozen|locked|terminated)\b",
        r"\b(update|complete|verify|submit)\s+(your\s+)?(kyc|pan|aadhaar|ssn|identity)\b",
        r"\b(unauthorized|suspicious|fraudulent)\s+(transaction|login|activity|charge)\b",
        r"\b(click|visit|tap)\s+here\s+to\s+(unblock|reactivate|verify|restore)\b",
        r"\b(electricity|power|gas)\s+supply\s+will\s+be\s+(disconnected|cut off)\b"
    ],
    "Credential & OTP Harvesting": [
        r"\b(share|send|provide|enter|submit)\s+(your\s+)?(otp|pin|password|passcode|cvv|security code)\b",
        r"\b(do not share|never share)\s+this\s+otp\s+with\s+anyone\b",
        r"\b(seed phrase|recovery phrase|private key|12 words|secret key)\b",
        r"\bverify\s+your\s+identity\s+by\s+entering\s+password\b"
    ],
    "Lottery & Fake Prize Fraud": [
        r"\b(congratulations|winner|won)\b.*\b(\$|usd|inr|£|€|\bmillion|\blakh|\bcrore)\b",
        r"\b(claim|collect)\s+(your\s+)?(prize|reward|lottery|jackpot|inheritance|funds)\b",
        r"\bselected\s+as\s+(the\s+)?lucky\s+winner\b",
        r"\bprocessing\s+fee\s+required\s+to\s+release\b"
    ],
    "Tech Support & Virus Alert": [
        r"\b(microsoft|apple|windows|google)\s+(security|defender|support|helpline)\b",
        r"\b(virus|trojan|malware|spyware|ransomware)\s+(detected|found|infected)\b",
        r"\bcall\s+(immediately|helpline|support|toll-free|\+?1-?8\d{2})\b",
        r"\bdownload\s+(anydesk|teamviewer|quicksupport|rustdesk|supremo)\b"
    ],
    "Fake Job & Task Fraud": [
        r"\b(part-time|work from home|remote job|online task)\b.*\b(earn|salary|daily|hourly)\b",
        r"\bearn\s+(\$|₹|£|€)?\s?\d{2,5}\s*(per day|daily|every day|per hour)\b",
        r"\blike\s+(youtube|tiktok|instagram)\s+videos\s+to\s+earn\b",
        r"\b(prepaid task|deposit usdt|vip commission)\b"
    ],
    "Courier & Customs Delivery Trap": [
        r"\b(package|parcel|shipment|delivery|order)\s+(is on hold|could not be delivered|failed|pending)\b",
        r"\b(pay|outstanding|clearance)\s+(customs fee|shipping fee|delivery charge|redelivery fee|\$\d+\.\d{2}|₹\d+)\b",
        r"\bupdate\s+(your\s+)?delivery\s+address\s+within\b",
        r"\b(fedex|dhl|usps|ups|royal mail|india post)\s+(tracking|notice|alert)\b"
    ],
    "Crypto Doubler & Investment Ponzi": [
        r"\b(double|triple)\s+your\s+(crypto|bitcoin|btc|eth|usdt|investment)\b",
        r"\bguaranteed\s+(returns|profit|roi|yield)\s+of\s+\d+%\b",
        r"\bsend\s+(\d+\s+)?(btc|eth|sol)\s+and\s+receive\s+(\d+\s+)?back\b"
    ]
}

# Urgency / Psychological manipulation triggers
URGENCY_PATTERNS = [
    r"\b(within\s+\d+\s+(hours|mins|minutes|days))\b",
    r"\b(immediate(ly)?|urgent(ly)?|action required|act now|hurry|final notice|last chance)\b",
    r"\b(law enforcement|police|court|legal action|arrest warrant|jail|penalty)\b",
    r"\b(before\s+it\s+is\s+too\s+late|without\s+delay|strictly\s+confidential)\b"
]

# URL Shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl", "bit.do"
}


def extract_urls(text: str) -> List[str]:
    """Extract URLs and domain links from text."""
    url_pattern = r"(https?://[^\s<>\"'()]+|(?:www\.)[^\s<>\"'()]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|xyz|top|click|buzz|io|online|site|app|co|in|tech|info)[/\w\-.~!$&'()*+,;=:#?%]*)"
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    return list(dict.fromkeys(matches))  # deduplicate preserving order


def analyze_message_content(text: str) -> Dict[str, Any]:
    """
    Perform deep textual and phishing scan on message text / SMS / email body.
    """
    cleaned = text.strip()
    threat_factors = []
    base_risk = 0
    detected_categories = []
    flagged_keywords = []
    recommendations = []

    if not cleaned:
        return {
            "risk_score": 0,
            "risk_level": "SAFE",
            "verdict": "EMPTY CONTENT",
            "detected_categories": [],
            "flagged_keywords": [],
            "extracted_urls": [],
            "threat_factors": [],
            "recommendations": ["No text provided for analysis."]
        }

    # 1. Scan for specific Scam Categories
    for category_name, patterns in SCAM_CATEGORIES.items():
        cat_matches = []
        for pattern in patterns:
            found = re.findall(pattern, cleaned, re.IGNORECASE)
            if found:
                for match in found:
                    if isinstance(match, tuple):
                        match_str = " ".join([m for m in match if m])
                    else:
                        match_str = str(match)
                    if match_str:
                        cat_matches.append(match_str)

        if cat_matches:
            detected_categories.append(category_name)
            flagged_keywords.extend(cat_matches[:3])
            
            impact = 35 if "KYC" in category_name or "Credential" in category_name else 30
            base_risk += impact
            
            threat_factors.append({
                "name": f"Scam Pattern: {category_name}",
                "severity": "CRITICAL" if impact >= 35 else "HIGH",
                "description": f"Text exhibits hallmark patterns of {category_name.lower()} operations.",
                "impact_score": impact
            })

    # 2. Check Urgency / Coercion Triggers
    urgency_matches = []
    for u_pattern in URGENCY_PATTERNS:
        u_found = re.findall(u_pattern, cleaned, re.IGNORECASE)
        if u_found:
            for item in u_found:
                if isinstance(item, tuple):
                    urgency_matches.append(" ".join(filter(None, item)))
                else:
                    urgency_matches.append(str(item))

    if urgency_matches:
        flagged_keywords.extend(urgency_matches[:2])
        base_risk += 20
        threat_factors.append({
            "name": "Artificial Urgency & Coercive Language",
            "severity": "HIGH",
            "description": "Message creates artificial panic or emergency deadlines (e.g. account lockout, legal threats) to force impulsive action without verification.",
            "impact_score": 20
        })

    # 3. Analyze Extracted URLs and Links
    urls = extract_urls(cleaned)
    for url in urls:
        url_lower = url.lower()

        # Check for URL Shorteners
        for shortener in URL_SHORTENERS:
            if shortener in url_lower:
                base_risk += 20
                threat_factors.append({
                    "name": f"Obfuscated Short URL ({shortener})",
                    "severity": "MEDIUM",
                    "description": f"URL shortener '{shortener}' conceals the true landing domain and destination payload.",
                    "impact_score": 20
                })
                break

        # Check for Raw IP Address in URL
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
            base_risk += 35
            threat_factors.append({
                "name": "Direct IP-Based Link Detected",
                "severity": "CRITICAL",
                "description": f"Link '{url}' uses a raw IP address instead of a legitimate domain name. This is standard in malware and credential harvesting.",
                "impact_score": 35
            })

        # Check for Suspicious TLD in Link
        for tld in SUSPICIOUS_TLDS:
            if tld in url_lower:
                base_risk += 15
                threat_factors.append({
                    "name": f"Suspicious Link TLD ({tld})",
                    "severity": "MEDIUM",
                    "description": f"Link domain utilizes high-abuse top level domain '{tld}'.",
                    "impact_score": 15
                })
                break

    # Calculate Final Risk Score (capped 0-100)
    risk_score = min(100, max(0, base_risk))

    # Determine Verdict & Risk Level
    if risk_score >= 70:
        risk_level = "DANGEROUS"
        verdict = "MALICIOUS SCAM / PHISHING CONTENT DETECTED"
    elif risk_score >= 40:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS SOCIAL ENGINEERING ATTEMPT"
    elif risk_score >= 15:
        risk_level = "LOW_RISK"
        verdict = "LOW RISK / MINOR SPAM INDICATORS"
    else:
        risk_level = "SAFE"
        verdict = "CLEAN / NO PHISHING PATTERNS DETECTED"

    # Actionable Recommendations
    if "Bank KYC & Account Suspension" in detected_categories or "Credential & OTP Harvesting" in detected_categories:
        recommendations.append("NEVER share passwords, OTP codes, or click links claiming your account will be suspended.")
        recommendations.append("Log in only by typing your bank's official URL directly into your browser.")
    if "Tech Support & Virus Alert" in detected_categories:
        recommendations.append("NEVER call numbers shown in pop-up virus warnings and never install remote software (AnyDesk).")
    if "Lottery & Fake Prize Fraud" in detected_categories:
        recommendations.append("Legitimate lotteries NEVER require an upfront fee or tax payment to claim winnings.")
    if "Fake Job & Task Fraud" in detected_categories:
        recommendations.append("Any job that asks you to pay money/deposit crypto upfront to earn commission is a task scam.")
    if "Courier & Customs Delivery Trap" in detected_categories:
        recommendations.append("Check package status directly on the official courier website using your original tracking code.")

    if not recommendations:
        if risk_level == "SAFE":
            recommendations.append("Text does not match any known phishing templates or coercion patterns.")
        else:
            recommendations.append("Exercise caution and independently verify the sender's identity.")

    # Deduplicate flagged keywords
    unique_flagged = list(dict.fromkeys([kw.strip() for kw in flagged_keywords if kw.strip()]))

    # Log analytics
    log_scan("content", cleaned[:50], risk_score, risk_level)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "detected_categories": detected_categories,
        "flagged_keywords": unique_flagged,
        "extracted_urls": urls,
        "threat_factors": threat_factors,
        "recommendations": recommendations
    }
