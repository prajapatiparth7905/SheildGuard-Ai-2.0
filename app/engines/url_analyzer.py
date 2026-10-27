"""
URL & Domain Phishing Threat Intelligence Engine.
Analyzes full URLs for homoglyphs, brand impersonation in subdomains/paths,
high-risk TLDs, raw IP hosts, port anomalies, obfuscated shorteners, and deceptive keywords.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from app.data.brand_patterns import TARGET_BRANDS, PHISHING_DOMAIN_KEYWORDS, HOMOGLYPHS
from app.data.disposable_domains import SUSPICIOUS_TLDS
from app.engines.email_analyzer import normalize_homoglyphs, levenshtein_distance
from app.database import log_scan

# Common URL Shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl", "bit.do", "rb.gy", "s.id", "soo.gd"
}

# High-risk path & query keyword triggers
HIGH_RISK_URL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "kyc-update",
    "account-suspended", "security-alert", "recover-account", "wallet-connect",
    "banking", "update-payment", "confirm-identity", "secure-auth", "webscr",
    "cmd=_login-run", "restore-access", "claim-reward", "lottery-winner", "parcel-redelivery"
]


def extract_url_components(url: str) -> Dict[str, Any]:
    """Parse and dissect a URL into standard and structural security components."""
    # Ensure scheme for urllib parsing
    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://", "ftp://")):
        parsed_url_str = "http://" + raw_url
    else:
        parsed_url_str = raw_url

    parsed = urllib.parse.urlparse(parsed_url_str)
    netloc = parsed.netloc or ""
    
    # Handle port if present
    host = netloc
    port = None
    if ":" in netloc:
        parts = netloc.split(":")
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    # Extract domain, subdomain, and TLD
    host_lower = host.lower()
    host_parts = [p for p in host_lower.split(".") if p]
    
    tld = ""
    registered_domain = ""
    subdomain = ""

    if len(host_parts) >= 2:
        # Check for multi-part TLDs (e.g. .co.uk, .com.au, .gov.in)
        if len(host_parts) >= 3 and host_parts[-2] in ["co", "com", "gov", "ac", "net", "org", "edu"]:
            tld = f"{host_parts[-2]}.{host_parts[-1]}"
            registered_domain = f"{host_parts[-3]}.{tld}"
            subdomain = ".".join(host_parts[:-3])
        else:
            tld = host_parts[-1]
            registered_domain = f"{host_parts[-2]}.{tld}"
            subdomain = ".".join(host_parts[:-2])
    elif len(host_parts) == 1:
        registered_domain = host_parts[0]
        tld = ""

    return {
        "raw_url": raw_url,
        "scheme": parsed.scheme or "http",
        "host": host_lower,
        "port": port,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "tld": tld,
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "subdomain_count": len(subdomain.split(".")) if subdomain else 0
    }


def analyze_url_threat(url: str) -> Dict[str, Any]:
    """
    Perform multi-layered cyber security analysis on a destination URL.
    Returns detailed risk score, risk level, threat factors, and breakdown.
    """
    threat_factors = []
    base_risk = 0
    recommendations = []
    detected_indicators = []

    cleaned_url = url.strip()
    if not cleaned_url:
        return {
            "url": "",
            "is_valid": False,
            "risk_score": 0,
            "risk_level": "SAFE",
            "verdict": "EMPTY URL",
            "components": {},
            "threat_factors": [],
            "recommendations": ["No URL provided for analysis."]
        }

    components = extract_url_components(cleaned_url)
    host = components["host"]
    registered_domain = components["registered_domain"]
    subdomain = components["subdomain"]
    path = components["path"]
    query = components["query"]
    tld = components["tld"]
    port = components["port"]

    full_lower = cleaned_url.lower()

    # 1. Check for Raw IP Address in Host
    is_raw_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
    if is_raw_ip:
        base_risk += 45
        detected_indicators.append("Raw IPv4 Host Address")
        threat_factors.append({
            "name": "Direct IP-Based Host Link",
            "severity": "CRITICAL",
            "description": f"URL uses raw IP address '{host}' instead of a verified domain name. Legitimate services virtually always use branded domain names.",
            "impact_score": 45
        })

    # 2. Check for URL Shorteners
    for shortener in URL_SHORTENERS:
        if shortener in host:
            base_risk += 25
            detected_indicators.append(f"URL Shortener ({shortener})")
            threat_factors.append({
                "name": f"Obfuscated Short URL Service ({shortener})",
                "severity": "MEDIUM",
                "description": f"URL shortener conceals final redirect destination, payload, and true domain reputation.",
                "impact_score": 25
            })
            recommendations.append(f"Use a URL expander to preview the final landing destination before opening '{shortener}' links.")
            break

    # 3. Check for High-Abuse / Suspicious TLD
    formatted_tld = f".{tld}" if not tld.startswith(".") else tld
    if formatted_tld in SUSPICIOUS_TLDS or tld in SUSPICIOUS_TLDS:
        base_risk += 25
        detected_indicators.append(f"Suspicious TLD ({formatted_tld})")
        threat_factors.append({
            "name": f"High-Abuse Phishing TLD (.{tld})",
            "severity": "HIGH",
            "description": f"Top Level Domain '.{tld}' is recognized by global cyber threat feeds as having high malware/phishing registration abuse rates.",
            "impact_score": 25
        })

    # 4. Check for Brand Impersonation & Typosquatting in Domain or Subdomain
    # Case A: Brand name inside subdomain to deceive users (e.g., paypal.com.attacker-domain.xyz)
    target_impersonated_brand = None
    for brand in TARGET_BRANDS:
        # Check if brand appears in subdomain while registered domain is different
        if brand in subdomain:
            if brand not in registered_domain:
                base_risk += 45
                target_impersonated_brand = brand
                detected_indicators.append(f"Subdomain Brand Spoofing ({brand})")
                threat_factors.append({
                    "name": f"Subdomain Brand Spoofing ('{brand}')",
                    "severity": "CRITICAL",
                    "description": f"URL places legitimate brand '{brand}' in subdomain, while the actual authoritative domain is '{registered_domain}'. This is a deceptive social-engineering technique.",
                    "impact_score": 45
                })
                break

        # Case B: Homoglyph or Typosquatting in Registered Domain (e.g. micros0ft.com, paypa1-auth.net)
        domain_no_tld = registered_domain.rsplit(".", 1)[0] if "." in registered_domain else registered_domain
        normalized_dom = normalize_homoglyphs(domain_no_tld)

        if brand in normalized_dom and brand not in domain_no_tld:
            base_risk += 45
            target_impersonated_brand = brand
            detected_indicators.append(f"Homoglyph Brand Impersonation ({brand})")
            threat_factors.append({
                "name": f"Homoglyph Character Substitution ('{brand}')",
                "severity": "CRITICAL",
                "description": f"Domain '{registered_domain}' substitutes characters (e.g., '0' for 'o', '1' for 'l') to impersonate '{brand}'.",
                "impact_score": 45
            })
            break

        # Case C: Edit distance 1 typosquatting
        if len(domain_no_tld) >= 4 and len(brand) >= 4:
            dist = levenshtein_distance(domain_no_tld, brand)
            if dist == 1:
                base_risk += 40
                target_impersonated_brand = brand
                detected_indicators.append(f"Typosquatting Lookalike Domain ({brand})")
                threat_factors.append({
                    "name": f"Typosquatting Lookalike Domain ('{brand}')",
                    "severity": "HIGH",
                    "description": f"Domain '{registered_domain}' is 1 character variant off from legitimate brand '{brand}'.",
                    "impact_score": 40
                })
                break

        # Case D: Compound brand + phishing keyword (e.g. paypal-verify-login.com)
        if brand in domain_no_tld and ("-" in domain_no_tld or any(kw in domain_no_tld for kw in PHISHING_DOMAIN_KEYWORDS)):
            base_risk += 35
            target_impersonated_brand = brand
            detected_indicators.append(f"Compound Phishing Keyword Domain ({brand})")
            threat_factors.append({
                "name": f"Compound Brand-Phishing Keyword Domain ({brand})",
                "severity": "HIGH",
                "description": f"Domain combines brand '{brand}' with security/login lures to trick victims into entering credentials.",
                "impact_score": 35
            })
            break

    # 5. Check for Excessive Subdomain Depth
    if components["subdomain_count"] >= 3:
        base_risk += 15
        detected_indicators.append(f"Excessive Subdomain Depth ({components['subdomain_count']} levels)")
        threat_factors.append({
            "name": "Excessive Subdomain Nesting Depth",
            "severity": "MEDIUM",
            "description": f"URL contains {components['subdomain_count']} subdomain levels. Phishers use deep subdomains to camouflage the true apex domain on mobile screens.",
            "impact_score": 15
        })

    # 6. Check for Non-standard / High-risk Web Ports
    if port and port not in [80, 443, 8000, 8080, 3000]:
        base_risk += 20
        detected_indicators.append(f"Non-Standard Port (:{port})")
        threat_factors.append({
            "name": f"Non-Standard Port Connection (:{port})",
            "severity": "MEDIUM",
            "description": f"URL directs connection to unusual network port {port}, bypassing standard web proxies and security filters.",
            "impact_score": 20
        })

    # 7. Check for High-Risk Phishing Keywords in Path or Query
    matched_keywords = []
    full_path_query = f"{path}?{query}".lower()
    for kw in HIGH_RISK_URL_KEYWORDS:
        if kw in full_path_query:
            matched_keywords.append(kw)

    if matched_keywords:
        kw_impact = min(30, len(matched_keywords) * 10)
        base_risk += kw_impact
        detected_indicators.append(f"Lure Keywords ({', '.join(matched_keywords[:3])})")
        threat_factors.append({
            "name": "Deceptive Phishing Path / Parameter Keywords",
            "severity": "HIGH" if kw_impact >= 20 else "MEDIUM",
            "description": f"URL path/parameters contain credential harvesting triggers: {', '.join(matched_keywords)}.",
            "impact_score": kw_impact
        })

    # 8. Check for '@' symbol in URL (HTTP Basic Auth spoofing trick)
    if "@" in cleaned_url:
        base_risk += 40
        detected_indicators.append("HTTP Basic Auth Spoofing ('@' in URL)")
        threat_factors.append({
            "name": "Deceptive '@' Character in URL",
            "severity": "CRITICAL",
            "description": "The '@' character in URLs instructs browsers to ignore everything preceding it as authentication metadata, deceiving users about the true destination host.",
            "impact_score": 40
        })

    # 9. Check for Unencrypted HTTP on Sensitive Actions
    if components["scheme"] == "http" and (matched_keywords or target_impersonated_brand):
        base_risk += 20
        threat_factors.append({
            "name": "Unencrypted HTTP on Authentication / Phishing Endpoint",
            "severity": "HIGH",
            "description": "Sensitive login/verification pages require encrypted HTTPS. Unencrypted HTTP indicates a fraudulent or poorly configured attack page.",
            "impact_score": 20
        })

    # Calculate final risk score
    risk_score = min(100, max(0, base_risk))

    if risk_score >= 70:
        risk_level = "DANGEROUS"
        verdict = "HIGH-RISK MALICIOUS / PHISHING LINK"
    elif risk_score >= 40:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS URL WITH DECEPTIVE INDICATORS"
    elif risk_score >= 15:
        risk_level = "LOW_RISK"
        verdict = "LOW RISK / MINOR IRREGULARITIES"
    else:
        risk_level = "SAFE"
        verdict = "CLEAN / NO PHISHING PATTERNS DETECTED"

    # Actionable safety recommendations
    if target_impersonated_brand:
        recommendations.append(f"Do NOT enter passwords or financial information. Navigate to official '{target_impersonated_brand}' directly via search or bookmark.")
    if is_raw_ip:
        recommendations.append("Do NOT submit any credentials on raw IP links.")
    if matched_keywords:
        recommendations.append("Check the browser address bar carefully to verify domain spelling before typing account credentials.")
    if not recommendations:
        if risk_level == "SAFE":
            recommendations.append("URL does not contain known malicious structural patterns, homoglyphs, or spoofing tactics.")
        else:
            recommendations.append("Exercise standard cyber caution before clicking unknown web links.")

    # Log analytics
    log_scan("url", cleaned_url[:50], risk_score, risk_level)

    return {
        "url": cleaned_url,
        "is_valid": True,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "impersonated_brand": target_impersonated_brand,
        "detected_indicators": detected_indicators,
        "components": components,
        "threat_factors": threat_factors,
        "recommendations": recommendations
    }
