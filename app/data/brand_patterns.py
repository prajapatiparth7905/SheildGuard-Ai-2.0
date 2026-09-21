"""
High-Profile Brands and Phishing Keywords for Typosquatting & Impersonation Detection.
"""

TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "telegram", "twitter", "x",
    "linkedin", "tiktok", "snapchat", "discord",
    # Financial & Banking
    "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "barclays", "hsbc", "santander", "revolut", "wise", "venmo", "zelle", "cashapp",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe", "gpay",
    # Crypto Exchanges & Wallets
    "binance", "coinbase", "kraken", "metamask", "trustwallet", "kucoin", "bybit",
    # Shipping & Courier
    "fedex", "dhl", "ups", "usps", "royalmail", "indiapost", "dpd", "hermes",
    # Tech & Software
    "adobe", "dropbox", "github", "gitlab", "salesforce", "steam", "epicgames", "spotify"
]

# Suspicious keywords commonly attached to brand names by phishers
# e.g., paypal-security.com, verify-chase-login.net, apple-support-id.org
PHISHING_DOMAIN_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "update",
    "account", "auth", "authenticate", "portal", "support", "helpdesk",
    "billing", "invoice", "confirm", "recovery", "alert", "notice", "unlock",
    "service", "customer-care", "kyc", "wallet", "restore", "protect", "suspend"
]

# Common character substitution / homoglyph mapping used in lookalike domains
HOMOGLYPHS = {
    '0': 'o',
    '1': 'l',  # or 'i'
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '@': 'a',
    'vv': 'w',
    'rn': 'm',
    'cl': 'd'
}
