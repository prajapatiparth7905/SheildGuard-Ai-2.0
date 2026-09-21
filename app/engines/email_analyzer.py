"""
Email Spam, Scam, Phishing, and Typosquatting Intelligence Engine.
Analyzes email addresses for disposable domains, brand impersonation, MX/DNS validity, and scam records.
"""

import re
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from typing import Dict, Any, List, Optional, Tuple
from app.data.disposable_domains import DISPOSABLE_DOMAINS, FREE_EMAIL_PROVIDERS, SUSPICIOUS_TLDS
from app.data.brand_patterns import TARGET_BRANDS, PHISHING_DOMAIN_KEYWORDS, HOMOGLYPHS
from app.database import check_scam_database, log_scan


def normalize_homoglyphs(text: str) -> str:
    """Normalize common character substitutions used in lookalike domains."""
    normalized = text.lower()
    for char, replacement in HOMOGLYPHS.items():
        normalized = normalized.replace(char, replacement)
    return normalized


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_brand_impersonation(domain: str) -> Tuple[bool, Optional[str], str]:
    """
    Check if a domain is impersonating a well-known brand using typosquatting, 
    homoglyphs, or brand-keyword combinations (e.g. paypal-security.com).
    """
    domain_lower = domain.lower()
    domain_no_tld = domain_lower.rsplit(".", 1)[0]
    normalized_domain = normalize_homoglyphs(domain_no_tld)

    for brand in TARGET_BRANDS:
        # Legitimate brand exact match (e.g. paypal.com, google.com, apple.com)
        if domain_lower == f"{brand}.com" or domain_lower == f"{brand}.org" or domain_lower == f"{brand}.net" or domain_lower == f"{brand}.in" or domain_lower == f"{brand}.co.uk":
            continue

        # Case 1: Brand name contains phishing keyword combos (e.g. paypal-login-verify.com, chase-online-auth.net)
        if brand in domain_no_tld:
            # Check if domain is a compound with security/login keywords
            has_keyword = any(kw in domain_no_tld for kw in PHISHING_DOMAIN_KEYWORDS)
            if has_keyword or "-" in domain_no_tld or "." in domain_no_tld:
                return True, brand, f"Domain contains brand '{brand}' alongside suspicious keywords/subdomains ({domain})"

        # Case 2: Homoglyph spoofing (e.g. paypa1.com -> paypal, micros0ft.com -> microsoft)
        if brand in normalized_domain and brand not in domain_no_tld:
            return True, brand, f"Homoglyph character substitution targeting '{brand}' (e.g. 0->o, 1->l/i)"

        # Case 3: Typosquatting edit distance (e.g. arnazon.com, go0gle.com, netflx.com)
        main_part = domain_no_tld.split(".")[-1]
        if len(main_part) >= 4 and len(brand) >= 4:
            dist = levenshtein_distance(main_part, brand)
            if dist == 1:
                return True, brand, f"Typosquatting variation with 1-character difference from '{brand}'"

    return False, None, ""


def check_dns_mx_records(domain: str, timeout: float = 3.0) -> Tuple[bool, List[str], bool]:
    """
    Query DNS for MX (Mail Exchange) and A records to confirm domain validity and mail readiness.
    """
    mx_hosts = []
    has_mx = False
    is_resolvable = False

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    # 1. Try MX record query
    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            mx_hosts.append(str(rdata.exchange).rstrip("."))
        if mx_hosts:
            has_mx = True
            is_resolvable = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        has_mx = False

    # 2. If no MX, check if A record exists (fallback mail server)
    if not has_mx:
        try:
            a_answers = resolver.resolve(domain, "A")
            if a_answers:
                is_resolvable = True
        except Exception:
            is_resolvable = False

    return has_mx, mx_hosts, is_resolvable


def analyze_email_address(raw_email: str, perform_dns_check: bool = True) -> Dict[str, Any]:
    """
    Deep intelligence scan on an email address.
    Checks syntax, disposable domains, brand typosquatting, MX records, and scam databases.
    """
    cleaned = raw_email.strip()
    threat_factors = []
    base_risk = 0
    recommendations = []

    # 1. Syntax Validation
    is_valid_syntax = False
    local_part = ""
    domain = ""
    tld = ""

    try:
        valid_info = validate_email(cleaned, check_deliverability=False)
        cleaned = valid_info.normalized
        local_part = valid_info.local_part
        domain = valid_info.domain.lower()
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        is_valid_syntax = True
    except EmailNotValidError as e:
        is_valid_syntax = False
        if "@" in cleaned:
            parts = cleaned.split("@", 1)
            local_part = parts[0]
            domain = parts[1].lower()
            tld = "." + domain.split(".")[-1] if "." in domain else ""

        threat_factors.append({
            "name": "Invalid Email Syntax",
            "severity": "HIGH",
            "description": f"The email format violates standard RFC specifications: {str(e)}",
            "impact_score": 35
        })
        base_risk += 35

    # 2. Check Disposable / Burner Email Service
    is_disposable = domain in DISPOSABLE_DOMAINS
    if is_disposable:
        base_risk += 50
        threat_factors.append({
            "name": "Disposable / Temporary Email Domain",
            "severity": "CRITICAL",
            "description": f"Domain '{domain}' is a known throwaway burner email service (e.g. Mailinator, TempMail). Scammers frequently use disposable inboxes for fraud and spam.",
            "impact_score": 50
        })
        recommendations.append("Do NOT accept registrations or trust communications from this disposable/burner email address.")

    # 3. Check Free Consumer Email Provider
    is_free_provider = domain in FREE_EMAIL_PROVIDERS
    if is_free_provider:
        # If local-part mimics a corporate or support team e.g. "microsoft-support@gmail.com"
        for brand in TARGET_BRANDS:
            if brand in local_part.lower() and ("support" in local_part or "security" in local_part or "service" in local_part or "billing" in local_part or "help" in local_part):
                base_risk += 45
                threat_factors.append({
                    "name": f"Free Email Impersonating Enterprise Brand ({brand.capitalize()})",
                    "severity": "CRITICAL",
                    "description": f"The email uses a free webmail service ({domain}) while pretending to be official '{brand.capitalize()}' department in the username ('{local_part}').",
                    "impact_score": 45
                })
                recommendations.append(f"Official {brand.capitalize()} support never sends security or billing alerts from free @{domain} accounts.")

    # 4. Check Brand Typosquatting / Lookalike Phishing Domain
    is_typosquatting, impersonated_brand, typo_reason = detect_brand_impersonation(domain)
    if is_typosquatting:
        base_risk += 55
        threat_factors.append({
            "name": f"Brand Typosquatting / Impersonation ({impersonated_brand.capitalize()})",
            "severity": "CRITICAL",
            "description": typo_reason,
            "impact_score": 55
        })
        recommendations.append(f"This domain is a fraudulent spoof targeting {impersonated_brand.capitalize()}. Do not click any links or provide credentials.")

    # 5. Check High-Risk / Suspicious TLD
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    if is_suspicious_tld:
        base_risk += 25
        threat_factors.append({
            "name": f"High-Risk / Frequently Abused TLD ({tld})",
            "severity": "MEDIUM",
            "description": f"The top-level domain '{tld}' has a statistically high correlation with phishing campaigns and bulk spam distribution.",
            "impact_score": 25
        })

    # 6. Live DNS & MX Record Check
    has_mx = False
    mx_hosts = []
    is_resolvable = False
    if perform_dns_check and domain and is_valid_syntax:
        has_mx, mx_hosts, is_resolvable = check_dns_mx_records(domain)
        if not is_resolvable:
            base_risk += 40
            threat_factors.append({
                "name": "Unresolvable Domain (Dead / Spoofed DNS)",
                "severity": "CRITICAL",
                "description": f"Domain '{domain}' does not exist or has no active DNS records. It cannot send or receive legitimate email.",
                "impact_score": 40
            })
            recommendations.append("The sender domain is non-existent. The sender address is likely forged/spoofed.")
        elif not has_mx:
            base_risk += 25
            threat_factors.append({
                "name": "No MX (Mail Server) Records Found",
                "severity": "HIGH",
                "description": f"Domain '{domain}' has no configured Mail Exchange (MX) records to handle incoming replies.",
                "impact_score": 25
            })

    # 7. Check Community Scam Database
    community_reports = check_scam_database(cleaned, target_type="email")
    if not community_reports and domain:
        # Also check if the domain itself is reported
        domain_reports = check_scam_database(domain, target_type="email")
        community_reports.extend(domain_reports)

    if community_reports:
        num_reports = len(community_reports)
        total_upvotes = sum(r.get("upvotes", 1) for r in community_reports)
        top_report = community_reports[0]

        added_risk = min(75, 45 + (num_reports * 10) + min(20, total_upvotes // 5))
        base_risk += added_risk

        threat_factors.append({
            "name": f"Confirmed Community Scam Reports ({num_reports} report{'s' if num_reports > 1 else ''})",
            "severity": "CRITICAL" if total_upvotes > 20 else "HIGH",
            "description": f"This email/domain is flagged in the scam registry for: {top_report.get('scam_category', 'Fraud')}. {top_report.get('description', '')}",
            "impact_score": added_risk
        })
        recommendations.append(f"Email reported for '{top_report.get('scam_category')}'. Block sender and report as phishing.")

    # Calculate Final Risk Score (capped 0-100)
    risk_score = min(100, max(0, base_risk))

    # Determine Verdict & Risk Level
    if risk_score >= 75:
        risk_level = "DANGEROUS"
        verdict = "MALICIOUS PHISHING / SCAM EMAIL"
    elif risk_score >= 50:
        risk_level = "SUSPICIOUS"
        verdict = "HIGH SUSPICION / SPAM RISK"
    elif risk_score >= 20:
        risk_level = "LOW_RISK"
        verdict = "LOW RISK / MINOR CONCERNS"
    else:
        risk_level = "SAFE"
        verdict = "CLEAN / LEGITIMATE EMAIL FORMAT"

    # Default general recommendations
    if not recommendations:
        if risk_level == "SAFE":
            recommendations.append("Valid domain and mail exchange records verified with no scam blacklist matches.")
            recommendations.append("Standard security: never enter passwords on unverified external links.")
        else:
            recommendations.append("Do not download attachments or click links from this sender.")

    # Log analytics
    log_scan("email", cleaned, risk_score, risk_level)

    return {
        "email": cleaned,
        "is_valid": is_valid_syntax,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "email_details": {
            "raw_email": cleaned,
            "local_part": local_part,
            "domain": domain,
            "is_valid_syntax": is_valid_syntax,
            "is_disposable": is_disposable,
            "is_free_provider": is_free_provider,
            "is_suspicious_tld": is_suspicious_tld,
            "tld": tld,
            "mx_records_found": has_mx,
            "mx_hosts": mx_hosts,
            "dns_resolvable": is_resolvable if perform_dns_check else True,
            "impersonated_brand": impersonated_brand,
            "typosquatting_detected": is_typosquatting
        },
        "threat_factors": threat_factors,
        "community_reports": community_reports,
        "recommendations": recommendations
    }
