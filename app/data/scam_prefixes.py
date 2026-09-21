"""
Known Scam Phone Prefixes, Wangiri Trap Area Codes, and High-Risk Robocall Patterns.
"""

# International country codes notorious for "Wangiri" (one-ring callback traps)
# Scammers call and hang up immediately, prompting victims to call back at exorbitant international toll rates ($20-$50/min).
WANGIRI_COUNTRY_CODES = {
    "232": {"country": "Sierra Leone", "risk": 85, "reason": "Frequent source of Wangiri one-ring toll callback fraud"},
    "224": {"country": "Guinea", "risk": 85, "reason": "High frequency of international one-ring callback scams"},
    "247": {"country": "Ascension Island", "risk": 90, "reason": "Notorious high-cost satellite destination used for toll fraud"},
    "269": {"country": "Comoros", "risk": 85, "reason": "Common origin for international toll-charge callback scams"},
    "678": {"country": "Vanuatu", "risk": 85, "reason": "Pacific island premium toll callback fraud source"},
    "685": {"country": "Samoa", "risk": 80, "reason": "Frequent Wangiri callback fraud reports"},
    "252": {"country": "Somalia", "risk": 80, "reason": "High volume of international premium-rate robocall fraud"},
    "231": {"country": "Liberia", "risk": 80, "reason": "Frequent one-ring international callback scams"},
    "216": {"country": "Tunisia", "risk": 75, "reason": "Known origin of lottery and callback robocall spam"},
    "387": {"country": "Bosnia and Herzegovina", "risk": 75, "reason": "Reported source of unauthorized premium toll routing"},
    "960": {"country": "Maldives", "risk": 80, "reason": "Common premium toll callback fraud target"},
    "236": {"country": "Central African Republic", "risk": 80, "reason": "Wangiri toll fraud source"}
}

# Caribbean area codes that look like regular US/Canada 10-digit numbers (+1-XXX)
# but actually bill expensive international rates without user realization.
CARIBBEAN_SCAM_AREA_CODES = {
    "876": {"location": "Jamaica", "risk": 90, "reason": "Jamaican lottery scam hub & high-cost international calling area"},
    "284": {"location": "British Virgin Islands", "risk": 85, "reason": "High-rate offshore area code masked as domestic US number"},
    "809": {"location": "Dominican Republic", "risk": 85, "reason": "Classic '809 scam' area code billing international toll rates"},
    "829": {"location": "Dominican Republic", "risk": 85, "reason": "Dominican Republic toll callback scam area"},
    "849": {"location": "Dominican Republic", "risk": 85, "reason": "Dominican Republic toll callback scam area"},
    "473": {"location": "Grenada", "risk": 85, "reason": "Caribbean toll trap masking as standard domestic number"},
    "268": {"location": "Antigua and Barbuda", "risk": 80, "reason": "High-cost international prefix spoof"},
    "649": {"location": "Turks and Caicos", "risk": 80, "reason": "International toll trap area code"},
    "767": {"location": "Dominica", "risk": 80, "reason": "Caribbean high-cost billing area code"},
    "869": {"location": "Saint Kitts and Nevis", "risk": 80, "reason": "Offshore high-cost number prefix"}
}

# US & International premium-rate prefixes that charge caller per minute
PREMIUM_RATE_PREFIXES = {
    "900": "US/Canada Premium Rate Information Service (Charges $5-$50+ per call)",
    "976": "US Premium Rate Service (Often adult or fee-based scams)",
    "090": "UK Premium Rate Service",
    "09": "European Premium Rate Band"
}

# Common Toll-free prefixes often spoofed or abused by tech support scammers ("Call Microsoft Support")
TECH_SUPPORT_TOLL_FREE_PREFIXES = {"800", "888", "877", "866", "855", "844", "833"}
