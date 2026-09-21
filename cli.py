"""
ShieldGuard AI - Command Line Interface (CLI)
Usage:
    python cli.py --phone "+18765550199"
    python cli.py --email "security@paypa1-update.com"
    python cli.py --text "Dear customer your bank account is blocked. Update KYC immediately."
    python cli.py --interactive
"""

import sys
import os
import argparse
import json

# Ensure UTF-8 output encoding on Windows consoles
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from app.database import init_db
from app.engines.phone_analyzer import analyze_phone_number
from app.engines.email_analyzer import analyze_email_address
from app.engines.content_analyzer import analyze_message_content


def color_text(text: str, color_code: str) -> str:
    return f"\033[{color_code}m{text}\033[0m"


def print_header():
    print(color_text("\n=======================================================", "1;34"))
    print(color_text("   [#] ShieldGuard AI - Spam & Scam Detection System", "1;36"))
    print(color_text("=======================================================\n", "1;34"))


def print_phone_report(res: dict):
    print(color_text(f"[*] Phone Number Analysis: {res['phone_number']}", "1;37"))
    
    score = res["risk_score"]
    level = res["risk_level"]
    verdict = res["verdict"]

    if level == "DANGEROUS":
        level_colored = color_text(f"CRITICAL DANGER ({score}%)", "1;31")
    elif level == "SUSPICIOUS":
        level_colored = color_text(f"SUSPICIOUS ({score}%)", "1;33")
    elif level == "LOW_RISK":
        level_colored = color_text(f"LOW RISK ({score}%)", "1;33")
    else:
        level_colored = color_text(f"CLEAN / SAFE ({score}%)", "1;32")

    print(f"  * Risk Assessment : {level_colored}")
    print(f"  * Verdict         : {verdict}")
    
    details = res["phone_details"]
    print(f"  * Line Type       : {details.get('line_type')}")
    print(f"  * Country/Region  : {details.get('location_name')} ({details.get('country_iso')})")
    print(f"  * Carrier         : {details.get('carrier_name')}")
    print(f"  * Format Valid    : {'Yes' if details.get('is_valid_format') else 'No'}")

    if res["threat_factors"]:
        print(color_text("\n  [!] Detected Threat Indicators:", "1;31"))
        for tf in res["threat_factors"]:
            print(f"    - [{tf['severity']}] {tf['name']}: {tf['description']}")

    if res["community_reports"]:
        print(color_text(f"\n  [!] Community Scam Database Matches ({len(res['community_reports'])}):", "1;31"))
        for cr in res["community_reports"][:3]:
            print(f"    - [{cr.get('scam_category')}] {cr.get('description')} (Upvotes: {cr.get('upvotes')})")

    if res["recommendations"]:
        print(color_text("\n  [*] Recommendations:", "1;36"))
        for r in res["recommendations"]:
            print(f"    + {r}")
    print()


def print_email_report(res: dict):
    print(color_text(f"[*] Email Address Analysis: {res['email']}", "1;37"))
    
    score = res["risk_score"]
    level = res["risk_level"]
    verdict = res["verdict"]

    if level == "DANGEROUS":
        level_colored = color_text(f"CRITICAL DANGER ({score}%)", "1;31")
    elif level == "SUSPICIOUS":
        level_colored = color_text(f"SUSPICIOUS ({score}%)", "1;33")
    elif level == "LOW_RISK":
        level_colored = color_text(f"LOW RISK ({score}%)", "1;33")
    else:
        level_colored = color_text(f"CLEAN / SAFE ({score}%)", "1;32")

    print(f"  * Risk Assessment : {level_colored}")
    print(f"  * Verdict         : {verdict}")

    details = res["email_details"]
    print(f"  * Domain          : {details.get('domain')}")
    print(f"  * Disposable Mail : {'YES (Burner Service)' if details.get('is_disposable') else 'No'}")
    print(f"  * Typosquatting   : {'YES - Spoofing ' + str(details.get('impersonated_brand')) if details.get('typosquatting_detected') else 'None Detected'}")
    print(f"  * MX Records      : {'Found' if details.get('mx_records_found') else 'No MX Server'}")
    print(f"  * DNS Resolvable  : {'Yes' if details.get('dns_resolvable') else 'No (Dead Domain)'}")

    if res["threat_factors"]:
        print(color_text("\n  [!] Detected Threat Indicators:", "1;31"))
        for tf in res["threat_factors"]:
            print(f"    - [{tf['severity']}] {tf['name']}: {tf['description']}")

    if res["recommendations"]:
        print(color_text("\n  [*] Recommendations:", "1;36"))
        for r in res["recommendations"]:
            print(f"    + {r}")
    print()


def print_content_report(res: dict):
    print(color_text("[*] Message & Content Scan Results:", "1;37"))
    
    score = res["risk_score"]
    level = res["risk_level"]
    verdict = res["verdict"]

    if level == "DANGEROUS":
        level_colored = color_text(f"CRITICAL DANGER ({score}%)", "1;31")
    elif level == "SUSPICIOUS":
        level_colored = color_text(f"SUSPICIOUS ({score}%)", "1;33")
    else:
        level_colored = color_text(f"CLEAN ({score}%)", "1;32")

    print(f"  * Risk Assessment : {level_colored}")
    print(f"  * Verdict         : {verdict}")
    print(f"  * Categories      : {', '.join(res['detected_categories']) if res['detected_categories'] else 'None'}")
    print(f"  * Flagged Words   : {', '.join(res['flagged_keywords']) if res['flagged_keywords'] else 'None'}")
    print(f"  * Extracted URLs  : {', '.join(res['extracted_urls']) if res['extracted_urls'] else 'None'}")

    if res["threat_factors"]:
        print(color_text("\n  [!] Threat Indicators:", "1;31"))
        for tf in res["threat_factors"]:
            print(f"    - [{tf['severity']}] {tf['name']}: {tf['description']}")

    if res["recommendations"]:
        print(color_text("\n  [*] Recommendations:", "1;36"))
        for r in res["recommendations"]:
            print(f"    + {r}")
    print()


def interactive_mode():
    print_header()
    while True:
        print("Choose an option:")
        print("  [1] Scan a Phone / Mobile Number")
        print("  [2] Scan an Email Address")
        print("  [3] Scan Message / SMS / Email Text")
        print("  [4] Exit")
        choice = input("\nEnter choice (1-4): ").strip()

        if choice == "1":
            phone = input("Enter phone number (e.g. +18765550199 or 9876543210): ").strip()
            if phone:
                res = analyze_phone_number(phone)
                print_phone_report(res)
        elif choice == "2":
            email = input("Enter email address: ").strip()
            if email:
                res = analyze_email_address(email)
                print_email_report(res)
        elif choice == "3":
            print("Enter message text:")
            text = input("> ").strip()
            if text:
                res = analyze_message_content(text)
                print_content_report(res)
        elif choice == "4" or choice.lower() in ("q", "exit"):
            print("Goodbye!")
            break
        else:
            print("Invalid selection.")


def main():
    init_db()
    parser = argparse.ArgumentParser(description="ShieldGuard AI - Spam & Scam Detection CLI")
    parser.add_argument("--phone", type=str, help="Phone number to check")
    parser.add_argument("--country", type=str, default="US", help="Default country code if not in +E.164 format")
    parser.add_argument("--email", type=str, help="Email address to check")
    parser.add_argument("--text", type=str, help="Message text to analyze for phishing")
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run interactive terminal mode")

    args = parser.parse_args()

    if len(sys.argv) == 1 or args.interactive:
        interactive_mode()
        return

    if args.phone:
        res = analyze_phone_number(args.phone, default_country=args.country)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_header()
            print_phone_report(res)

    if args.email:
        res = analyze_email_address(args.email)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_header()
            print_email_report(res)

    if args.text:
        res = analyze_message_content(args.text)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print_header()
            print_content_report(res)


if __name__ == "__main__":
    main()
