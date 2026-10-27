"""
External Security APIs & AI Intelligence Connectors for ShieldGuard AI.
Handles optional integrations with free security feeds (Google Safe Browsing, VirusTotal, Gemini AI)
with seamless, 100% offline fallback to local heuristic engines when keys are not configured.
"""

import os
import httpx
from typing import Dict, Any, List, Optional

# In-memory storage for runtime API keys (can also be set via Environment variables)
CONFIGURED_KEYS: Dict[str, str] = {
    "GOOGLE_SAFE_BROWSING_KEY": os.getenv("GOOGLE_SAFE_BROWSING_KEY", ""),
    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", ""),
    "IPQS_API_KEY": os.getenv("IPQS_API_KEY", "")
}

# Directory of supported APIs with Free Tier specifications, pricing, and setup guides
SUPPORTED_APIS_DIRECTORY = [
    {
        "id": "builtin_heuristics",
        "name": "ShieldGuard Built-in Multi-Vector Heuristic Engine",
        "provider": "ShieldGuard AI Core (Local)",
        "pricing_tier": "100% FREE / Open Source",
        "cost": "$0.00 / forever",
        "free_limit": "Unlimited (Zero latency, runs locally on server)",
        "requires_key": False,
        "is_active": True,
        "category": "Core Threat Intelligence",
        "description": "Multi-layered algorithmic engine analyzing Levenshtein typosquatting, homoglyphs, E.164 line types, Wangiri fraud prefixes, burner email domains, and NLP urgency cues.",
        "setup_guide": "Pre-installed and fully functional out of the box. No external account or key required."
    },
    {
        "id": "google_safe_browsing",
        "name": "Google Safe Browsing API v4",
        "provider": "Google Cloud Platform",
        "pricing_tier": "Free Tier Available",
        "cost": "$0.00 (Free for academic & non-commercial use)",
        "free_limit": "10,000 lookup queries / day",
        "requires_key": True,
        "is_active": bool(CONFIGURED_KEYS.get("GOOGLE_SAFE_BROWSING_KEY")),
        "category": "URL & Malware Reputation",
        "description": "Google's real-time global database of billions of unsafe URLs categorized by Social Engineering (Phishing), Malware, and Unwanted Software.",
        "setup_guide": "1. Go to Google Cloud Console (console.cloud.google.com)\n2. Enable 'Safe Browsing API'\n3. Create an API Key in Credentials\n4. Paste API key into ShieldGuard Settings modal."
    },
    {
        "id": "virustotal",
        "name": "VirusTotal API v3",
        "provider": "Google Chronicle / VirusTotal",
        "pricing_tier": "Free Community Tier",
        "cost": "$0.00 (Public API Free Tier)",
        "free_limit": "500 requests / day (4 requests / minute)",
        "requires_key": True,
        "is_active": bool(CONFIGURED_KEYS.get("VIRUSTOTAL_API_KEY")),
        "category": "Multi-Antivirus Threat Aggregation",
        "description": "Cross-examines URLs, domains, and IP addresses across 70+ top antivirus and security vendors (Kaspersky, Bitdefender, Sophos, ESET, etc.).",
        "setup_guide": "1. Sign up for a free account at virustotal.com\n2. Open your Profile -> API Key\n3. Copy your 64-character free Public API Key and paste into ShieldGuard."
    },
    {
        "id": "gemini_ai",
        "name": "Google Gemini 1.5 Flash AI Threat Briefing",
        "provider": "Google AI Studio",
        "pricing_tier": "Free Tier Available",
        "cost": "$0.00 (Free Tier with 15 RPM)",
        "free_limit": "15 requests / minute, 1,500 requests / day (Free Tier)",
        "requires_key": True,
        "is_active": bool(CONFIGURED_KEYS.get("GEMINI_API_KEY")),
        "category": "Generative AI Incident Analysis",
        "description": "Generates natural-language cybersecurity incident debriefs, psychological manipulation breakdowns, and custom mitigation protocols for academic presentations.",
        "setup_guide": "1. Visit aistudio.google.com\n2. Click 'Get API key' -> 'Create API key in new project'\n3. Paste the key into ShieldGuard to enable GenAI threat narratives."
    },
    {
        "id": "ipqs",
        "name": "IPQualityScore (IPQS) Fraud Intelligence",
        "provider": "IPQualityScore",
        "pricing_tier": "Free Developer Plan",
        "cost": "$0.00 (5,000 lookups/mo free)",
        "free_limit": "5,000 free API queries / month",
        "requires_key": True,
        "is_active": bool(CONFIGURED_KEYS.get("IPQS_API_KEY")),
        "category": "Phone Carrier & Disposable Email Validation",
        "description": "Enterprise-grade IP, phone number reputation, and email deliverability intelligence.",
        "setup_guide": "1. Register at ipqualityscore.com/create-account\n2. Access API key from account dashboard."
    }
]


def get_api_directory() -> List[Dict[str, Any]]:
    """Return the active state and metadata of all supported built-in and external APIs."""
    for api in SUPPORTED_APIS_DIRECTORY:
        if api["id"] == "google_safe_browsing":
            api["is_active"] = bool(CONFIGURED_KEYS.get("GOOGLE_SAFE_BROWSING_KEY"))
        elif api["id"] == "virustotal":
            api["is_active"] = bool(CONFIGURED_KEYS.get("VIRUSTOTAL_API_KEY"))
        elif api["id"] == "gemini_ai":
            api["is_active"] = bool(CONFIGURED_KEYS.get("GEMINI_API_KEY"))
        elif api["id"] == "ipqs":
            api["is_active"] = bool(CONFIGURED_KEYS.get("IPQS_API_KEY"))
    return SUPPORTED_APIS_DIRECTORY


def update_api_key(api_id: str, key_value: str) -> bool:
    """Update runtime API key for a specified external provider."""
    key_map = {
        "google_safe_browsing": "GOOGLE_SAFE_BROWSING_KEY",
        "virustotal": "VIRUSTOTAL_API_KEY",
        "gemini_ai": "GEMINI_API_KEY",
        "ipqs": "IPQS_API_KEY"
    }
    env_var = key_map.get(api_id)
    if env_var:
        CONFIGURED_KEYS[env_var] = key_value.strip()
        return True
    return False


async def check_google_safe_browsing(url: str) -> Optional[Dict[str, Any]]:
    """
    Query Google Safe Browsing Lookup API v4 if API key is provided.
    Returns threat details or None if no match / key not configured.
    """
    api_key = CONFIGURED_KEYS.get("GOOGLE_SAFE_BROWSING_KEY")
    if not api_key:
        return None

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "shieldguard-ai",
            "clientVersion": "2.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "UNKNOWN_THREAT")
                    return {
                        "source": "Google Safe Browsing v4",
                        "is_threat": True,
                        "threat_type": threat_type,
                        "description": f"Flagged by Google Safe Browsing as '{threat_type}'."
                    }
                return {
                    "source": "Google Safe Browsing v4",
                    "is_threat": False,
                    "threat_type": "CLEAN",
                    "description": "Verified clean by Google Safe Browsing."
                }
    except Exception as e:
        print(f"[ShieldGuard Warning] Google Safe Browsing check error: {e}")

    return None


async def generate_ai_threat_briefing(scan_type: str, target: str, risk_score: int, risk_level: str, threat_factors: List[Dict[str, Any]]) -> str:
    """
    Generate an AI-powered Threat Analysis Briefing.
    Uses Google Gemini Flash API if key is present, otherwise utilizes local template synthesis.
    """
    gemini_key = CONFIGURED_KEYS.get("GEMINI_API_KEY")

    if gemini_key:
        try:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            threat_names = [t.get("name", "") for t in threat_factors]
            prompt = (
                f"You are ShieldGuard AI, a cyber threat intelligence system. "
                f"Provide a concise 2-3 sentence executive threat briefing for a security audit report. "
                f"Target Type: {scan_type}. Target Value: {target}. "
                f"Calculated Risk Score: {risk_score}/100 ({risk_level}). "
                f"Identified Threat Indicators: {', '.join(threat_names) if threat_names else 'None (Clean)'}. "
                f"State the primary psychological/technical mechanism used and the immediate defensive action."
            )
            
            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }]
            }

            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text:
                            return text.strip()
        except Exception as e:
            print(f"[ShieldGuard Warning] Gemini AI query failed: {e}")

    # Fallback: High-grade heuristic synthesis
    if risk_score >= 70:
        return f"🚨 CRITICAL ALERT: Target '{target}' demonstrates severe indicators of malicious cyber deception, including {len(threat_factors)} high-severity threat signatures. Immediate blocking and incident logging recommended."
    elif risk_score >= 40:
        return f"⚠️ SUSPICIOUS ACTIVITY: Target '{target}' exhibits deceptive patterns common in credential-harvesting and social-engineering campaigns. Exercise strict verification before interacting."
    elif risk_score >= 15:
        return f"ℹ️ LOW RISK: Minor non-standard structural attributes detected for '{target}'. No critical malware or scam blacklists triggered."
    else:
        return f"✅ VERIFIED CLEAN: No known malicious signatures, homoglyphs, or blacklisted indicators identified for '{target}'."
