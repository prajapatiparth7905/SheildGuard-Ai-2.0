"""
Phone Scam & Spam Detection Intelligence Engine.
Analyzes phone numbers for spam risk, scam history, carrier line type, Wangiri traps, and spoofing heuristics.
"""

import re
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
from typing import Dict, Any, List, Optional
from app.data.scam_prefixes import WANGIRI_COUNTRY_CODES, CARIBBEAN_SCAM_AREA_CODES, PREMIUM_RATE_PREFIXES
from app.database import check_scam_database, log_scan


def get_line_type_str(p_type: PhoneNumberType) -> str:
    """Map PhoneNumberType enum to readable string."""
    mapping = {
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line / Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.SHARED_COST: "Shared Cost",
        PhoneNumberType.VOIP: "VoIP (Virtual / Internet Phone)",
        PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "Universal Access Number (UAN)",
        PhoneNumberType.VOICEMAIL: "Voicemail",
        PhoneNumberType.UNKNOWN: "Unknown / Unassigned"
    }
    return mapping.get(p_type, "Unknown")


def check_synthetic_or_repeated_pattern(national_str: str) -> bool:
    """Check if number consists of suspicious repeated or sequential patterns."""
    digits = re.sub(r"\D", "", national_str)
    if not digits or len(digits) < 6:
        return False
    
    # Check all same digits (e.g. 9999999999, 0000000000)
    if len(set(digits)) == 1:
        return True
        
    # Check 6+ repeating trailing digits (e.g. 555000000)
    if re.search(r"(\d)\1{5,}$", digits):
        return True

    # Check simple sequences like 123456789 or 987654321
    if "0123456789" in digits or "9876543210" in digits or "12345678" in digits:
        return True

    return False


def analyze_phone_number(raw_phone: str, default_country: str = "US") -> Dict[str, Any]:
    """
    Perform deep intelligence scan on a phone number.
    Returns composite risk score, danger flags, line details, and safety advice.
    """
    cleaned_input = raw_phone.strip()
    threat_factors = []
    base_risk = 0
    recommendations = []

    # 1. Parse number with phonenumbers library
    parsed = None
    is_valid = False
    is_possible = False
    e164_val = None
    national_val = None
    international_val = None
    country_code_int = None
    country_iso = None
    location_name = "Unknown Location"
    carrier_name = "Unknown Carrier"
    line_type_str = "Unknown"

    try:
        # Pre-fix leading plus if missing but starts with common international indicator
        if not cleaned_input.startswith("+") and default_country:
            parsed = phonenumbers.parse(cleaned_input, default_country.upper())
        else:
            parsed = phonenumbers.parse(cleaned_input, None)

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)
        e164_val = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        national_val = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        international_val = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        country_code_int = parsed.country_code
        country_iso = phonenumbers.region_code_for_number(parsed)

        # Geocode location and Carrier
        loc = geocoder.description_for_number(parsed, "en")
        if loc:
            location_name = loc
        elif country_iso:
            location_name = country_iso

        c_name = carrier.name_for_number(parsed, "en")
        if c_name:
            carrier_name = c_name

        p_type = number_type(parsed)
        line_type_str = get_line_type_str(p_type)

    except phonenumbers.NumberParseException as e:
        is_valid = False
        is_possible = False
        threat_factors.append({
            "name": "Invalid Phone Format",
            "severity": "MEDIUM",
            "description": f"The number could not be parsed according to standard telecom ITU-T recommendations: {str(e)}",
            "impact_score": 30
        })
        base_risk += 30

    # 2. Check Line Type Risks
    if parsed and is_valid:
        p_type = number_type(parsed)
        
        # VoIP numbers (often used for anonymous robocalls and fake call centers)
        if p_type == PhoneNumberType.VOIP:
            base_risk += 25
            threat_factors.append({
                "name": "VoIP / Virtual Number Detected",
                "severity": "MEDIUM",
                "description": "This is an internet-based virtual VoIP number. VoIP services are frequently used by anonymous scam operations and spammers to hide physical identity.",
                "impact_score": 25
            })
            recommendations.append("Exercise caution if receiving financial or account security requests from a VoIP line.")

        # Premium Rate Numbers (Charges caller high rates)
        elif p_type == PhoneNumberType.PREMIUM_RATE:
            base_risk += 50
            threat_factors.append({
                "name": "Premium Rate Number",
                "severity": "CRITICAL",
                "description": "This is a premium-rate number that bills the caller high per-minute charges. Calling this number back may incur heavy telephone charges.",
                "impact_score": 50
            })
            recommendations.append("DO NOT call back this number. It is configured to bill high charges directly to your phone bill.")

        # Toll-Free Numbers (Used often in tech support / fake Amazon refund popups)
        elif p_type == PhoneNumberType.TOLL_FREE:
            base_risk += 15
            threat_factors.append({
                "name": "Toll-Free Line (High Impersonation Risk)",
                "severity": "LOW",
                "description": "Toll-free 1-800 numbers are frequently registered by fake tech support and banking refund impersonators.",
                "impact_score": 15
            })

    # 3. Check Known Scam International Country Prefixes (Wangiri Trap Detection)
    if country_code_int and str(country_code_int) in WANGIRI_COUNTRY_CODES:
        w_info = WANGIRI_COUNTRY_CODES[str(country_code_int)]
        base_risk += w_info["risk"]
        threat_factors.append({
            "name": "High-Risk Wangiri Fraud Destination",
            "severity": "CRITICAL",
            "description": f"Country code +{country_code_int} ({w_info['country']}) is flagged: {w_info['reason']}",
            "impact_score": w_info["risk"]
        })
        recommendations.append("Do NOT return missed calls from this international country code. It is an international toll trap.")

    # 4. Check Caribbean Area Codes masked as Domestic US (+1-876, +1-809, +1-284, etc.)
    if country_code_int == 1 and e164_val:
        # Extract area code (first 3 digits after +1)
        area_code = e164_val[2:5] if len(e164_val) >= 5 else ""
        if area_code in CARIBBEAN_SCAM_AREA_CODES:
            c_info = CARIBBEAN_SCAM_AREA_CODES[area_code]
            base_risk += c_info["risk"]
            threat_factors.append({
                "name": f"High-Risk Caribbean Area Code (+1-{area_code})",
                "severity": "CRITICAL",
                "description": f"Area code {area_code} ({c_info['location']}) resembles a regular US domestic number but incurs steep international toll rates: {c_info['reason']}",
                "impact_score": c_info["risk"]
            })
            recommendations.append(f"Area code {area_code} is located in {c_info['location']}. Do not return unsolicited calls.")

    # 5. Check Synthetic or Sequential Repetitive Numbers
    raw_digits = re.sub(r"\D", "", cleaned_input)
    if check_synthetic_or_repeated_pattern(raw_digits):
        base_risk += 35
        threat_factors.append({
            "name": "Suspicious Synthetic / Spoofed Number Pattern",
            "severity": "HIGH",
            "description": "The number consists of repeated, sequential, or fake placeholder digits commonly associated with Caller ID spoofing software.",
            "impact_score": 35
        })
        recommendations.append("This number exhibits spoofed Caller ID characteristics. Treat caller identity with extreme skepticism.")

    # 6. Query Community Crowd-Sourced Scam Database
    lookup_id = e164_val if e164_val else cleaned_input
    community_reports = check_scam_database(lookup_id, target_type="phone")
    
    if community_reports:
        num_reports = len(community_reports)
        total_upvotes = sum(r.get("upvotes", 1) for r in community_reports)
        top_report = community_reports[0]
        
        # Heavy risk addition for confirmed community scam records
        added_risk = min(75, 40 + (num_reports * 10) + min(25, total_upvotes // 5))
        base_risk += added_risk
        
        threat_factors.append({
            "name": f"Confirmed Community Scam Reports ({num_reports} report{'s' if num_reports > 1 else ''})",
            "severity": "CRITICAL" if total_upvotes > 20 else "HIGH",
            "description": f"This number has been actively reported for: {top_report.get('scam_category', 'Fraud')}. {top_report.get('description', '')}",
            "impact_score": added_risk
        })
        recommendations.append(f"Number reported by community for '{top_report.get('scam_category')}'. Block this number immediately.")

    # Calculate Final Risk Score (capped 0-100)
    risk_score = min(100, max(0, base_risk))

    # Determine Verdict & Risk Level
    if risk_score >= 75:
        risk_level = "DANGEROUS"
        verdict = "HIGH RISK SCAM / FRAUD DETECTED"
    elif risk_score >= 50:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS ACTIVITY DETECTED"
    elif risk_score >= 20:
        risk_level = "LOW_RISK"
        verdict = "LOW RISK / MINOR CONCERNS"
    else:
        risk_level = "SAFE"
        verdict = "CLEAN / NO KNOWN THREATS DETECTED"

    # Default general recommendations
    if not recommendations:
        if risk_level == "SAFE":
            recommendations.append("No active scam reports or suspicious routing patterns detected for this number.")
            recommendations.append("Always exercise standard safety precautions before sharing personal data or PINs.")
        else:
            recommendations.append("Never share one-time passwords (OTPs), bank credentials, or install remote access apps.")

    # Log analytics
    log_scan("phone", lookup_id, risk_score, risk_level)

    return {
        "phone_number": cleaned_input,
        "is_valid": is_valid,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "phone_details": {
            "raw_input": cleaned_input,
            "e164_format": e164_val,
            "national_format": national_val,
            "international_format": international_val,
            "country_code": country_code_int,
            "country_iso": country_iso,
            "location_name": location_name,
            "carrier_name": carrier_name,
            "line_type": line_type_str,
            "is_valid_format": is_valid,
            "is_possible": is_possible
        },
        "threat_factors": threat_factors,
        "community_reports": community_reports,
        "recommendations": recommendations
    }
