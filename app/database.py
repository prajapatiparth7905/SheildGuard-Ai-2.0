"""
Database module for Scam Reports, Search, and Scan Analytics using SQLite.
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "shieldguard.db")

# Ensure the data directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_db_connection():
    """Create and return a SQLite database connection with row factory."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables and pre-seed with realistic scam intelligence data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table for Scam Reports (Phone Numbers, Emails, Domains)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,         -- 'phone', 'email', 'domain', 'message'
            identifier TEXT NOT NULL,          -- Normalized phone number or email
            scam_category TEXT NOT NULL,       -- 'Bank KYC', 'Tech Support', 'Lottery', 'Job Offer', 'Courier Delivery', etc.
            risk_level TEXT NOT NULL,          -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
            description TEXT NOT NULL,
            reported_by TEXT DEFAULT 'Anonymous',
            upvotes INTEGER DEFAULT 1,
            downvotes INTEGER DEFAULT 0,
            evidence_url TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Index for fast lookup on identifier
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scam_identifier ON scam_reports (identifier);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_type ON scam_reports (target_type);")

    # Table for Scan History / Analytics
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,           -- 'phone', 'email', 'content', 'combined'
            target_value TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,             -- 'SAFE', 'LOW_RISK', 'SUSPICIOUS', 'DANGEROUS'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

    # Check if database is empty, then seed initial intelligence
    cursor.execute("SELECT COUNT(*) as count FROM scam_reports")
    count = cursor.fetchone()["count"]
    if count == 0:
        seed_initial_data(cursor, conn)

    conn.close()


def seed_initial_data(cursor, conn):
    """Seed initial realistic scam records for immediate demonstration and testing."""
    seed_records = [
        # Phone Numbers
        {
            "target_type": "phone",
            "identifier": "+18765550199",
            "scam_category": "Lottery / Prize Fraud",
            "risk_level": "CRITICAL",
            "description": "Caller claims victim has won $2,500,000 in Mega Millions and demands $500 processing fee via Western Union or Apple gift card.",
            "reported_by": "CyberWatch Admin",
            "upvotes": 42
        },
        {
            "target_type": "phone",
            "identifier": "+18005550143",
            "scam_category": "Tech Support Impersonation",
            "risk_level": "CRITICAL",
            "description": "Fake Windows Defender pop-up warning directing users to call this number to remove non-existent virus, asking for AnyDesk remote access.",
            "reported_by": "Community Sentinel",
            "upvotes": 89
        },
        {
            "target_type": "phone",
            "identifier": "+919876543210",
            "scam_category": "Bank KYC / Electricity Disconnection",
            "risk_level": "HIGH",
            "description": "SMS stating: 'Dear customer your SBI bank account/Electricity will be blocked tonight. Call this number or download APK to update KYC.'",
            "reported_by": "FraudAlert IN",
            "upvotes": 124
        },
        {
            "target_type": "phone",
            "identifier": "+12845550188",
            "scam_category": "Wangiri / One-Ring Scam",
            "risk_level": "HIGH",
            "description": "Rings once and hangs up to lure callback. Charges victim $30/minute international toll fee.",
            "reported_by": "Telecom Shield",
            "upvotes": 67
        },
        {
            "target_type": "phone",
            "identifier": "+447012345678",
            "scam_category": "Job / Work From Home Scam",
            "risk_level": "HIGH",
            "description": "WhatsApp job offer offering $200-$500/day for liking YouTube videos, then asks for crypto deposit for VIP tasks.",
            "reported_by": "ScamHunter UK",
            "upvotes": 53
        },
        # Email Addresses
        {
            "target_type": "email",
            "identifier": "security@paypa1-update.com",
            "scam_category": "PayPal Phishing / Credential Theft",
            "risk_level": "CRITICAL",
            "description": "Phishing email warning about unauthorized $849 purchase on PayPal with fake login button linking to credential harvester.",
            "reported_by": "AntiPhish Global",
            "upvotes": 215
        },
        {
            "target_type": "email",
            "identifier": "account-alert@micros0ft-security.net",
            "scam_category": "Microsoft 365 Account Takeover",
            "risk_level": "CRITICAL",
            "description": "Posing as Microsoft Security Team asking user to reset password to avoid permanent account termination.",
            "reported_by": "IT Sec Operations",
            "upvotes": 178
        },
        {
            "target_type": "email",
            "identifier": "tracking@fedx-delivery-parcel.xyz",
            "scam_category": "Fake Courier Delivery Fee",
            "risk_level": "HIGH",
            "description": "Fake FedEx delivery notice claiming package is held at customs pending a $2.99 clearance payment.",
            "reported_by": "Consumer Defense",
            "upvotes": 95
        },
        {
            "target_type": "email",
            "identifier": "kyc-update@sbi-online-portal.click",
            "scam_category": "Banking KYC Phishing",
            "risk_level": "CRITICAL",
            "description": "Sends fake netbanking login page to harvest debit card PIN, CVV, and OTP.",
            "reported_by": "BankSec Team",
            "upvotes": 142
        },
        {
            "target_type": "email",
            "identifier": "support@binance-helpdesk-auth.top",
            "scam_category": "Crypto Wallet Drainer",
            "risk_level": "CRITICAL",
            "description": "Phishing email requesting users to connect MetaMask / Binance wallet or enter seed phrase to prevent account freeze.",
            "reported_by": "CryptoSecurity Watch",
            "upvotes": 110
        }
    ]

    for record in seed_records:
        cursor.execute("""
            INSERT INTO scam_reports (target_type, identifier, scam_category, risk_level, description, reported_by, upvotes)
            VALUES (:target_type, :identifier, :scam_category, :risk_level, :description, :reported_by, :upvotes)
        """, record)
    conn.commit()


def check_scam_database(identifier: str, target_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Look up an identifier in the local community scam database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Normalize identifier for matching
    cleaned = identifier.strip().lower()
    phone_cleaned = cleaned.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")

    if target_type:
        cursor.execute("""
            SELECT * FROM scam_reports 
            WHERE (LOWER(identifier) = ? OR LOWER(REPLACE(REPLACE(REPLACE(identifier, ' ', ''), '-', ''), '+', '')) = ?)
            AND target_type = ?
            ORDER BY upvotes DESC
        """, (cleaned, phone_cleaned.replace("+", ""), target_type))
    else:
        cursor.execute("""
            SELECT * FROM scam_reports 
            WHERE (LOWER(identifier) = ? OR LOWER(REPLACE(REPLACE(REPLACE(identifier, ' ', ''), '-', ''), '+', '')) = ?)
            ORDER BY upvotes DESC
        """, (cleaned, phone_cleaned.replace("+", "")))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_scam_report(target_type: str, identifier: str, scam_category: str, 
                    risk_level: str, description: str, reported_by: str = "Anonymous",
                    evidence_url: str = "") -> int:
    """Add a new community scam report."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cleaned = identifier.strip()
    cursor.execute("""
        INSERT INTO scam_reports (target_type, identifier, scam_category, risk_level, description, reported_by, evidence_url, upvotes)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    """, (target_type.lower(), cleaned, scam_category, risk_level.upper(), description, reported_by or "Anonymous", evidence_url))
    
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id


def vote_scam_report(report_id: int, is_upvote: bool = True) -> Optional[Dict[str, Any]]:
    """Upvote or downvote a scam report."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if is_upvote:
        cursor.execute("UPDATE scam_reports SET upvotes = upvotes + 1 WHERE id = ?", (report_id,))
    else:
        cursor.execute("UPDATE scam_reports SET downvotes = downvotes + 1 WHERE id = ?", (report_id,))
    
    conn.commit()
    cursor.execute("SELECT * FROM scam_reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_scam_reports(limit: int = 50, offset: int = 0, category: Optional[str] = None, 
                         search: Optional[str] = None, target_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve list of scam reports with filtering and search."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM scam_reports WHERE 1=1"
    params = []
    
    if target_type:
        query += " AND target_type = ?"
        params.append(target_type.lower())
    if category:
        query += " AND scam_category LIKE ?"
        params.append(f"%{category}%")
    if search:
        query += " AND (identifier LIKE ? OR description LIKE ? OR scam_category LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        
    query += " ORDER BY upvotes DESC, created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def log_scan(scan_type: str, target_value: str, risk_score: int, verdict: str):
    """Log a scan result for analytics."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_logs (scan_type, target_value, risk_score, verdict)
            VALUES (?, ?, ?, ?)
        """, (scan_type, target_value, risk_score, verdict))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_system_stats() -> Dict[str, Any]:
    """Calculate dashboard statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total_reports FROM scam_reports")
    total_reports = cursor.fetchone()["total_reports"]

    cursor.execute("SELECT COUNT(*) as total_scans FROM scan_logs")
    total_scans = cursor.fetchone()["total_scans"]

    cursor.execute("SELECT COUNT(*) as threats_detected FROM scan_logs WHERE verdict IN ('SUSPICIOUS', 'DANGEROUS')")
    threats_detected = cursor.fetchone()["threats_detected"]

    cursor.execute("""
        SELECT scam_category, COUNT(*) as count 
        FROM scam_reports 
        GROUP BY scam_category 
        ORDER BY count DESC LIMIT 5
    """)
    top_categories = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "total_scam_reports": total_reports,
        "total_scans_performed": total_scans,
        "threats_detected": threats_detected,
        "top_scam_categories": top_categories
    }
