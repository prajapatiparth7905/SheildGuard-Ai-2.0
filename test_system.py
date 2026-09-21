"""
Automated Test Suite for ShieldGuard AI Spam & Scam Detection System.
Tests phone intelligence, email phishing detection, text analysis, and API endpoints.
"""

import sys
import os
import unittest
from fastapi.testclient import TestClient

from app.database import init_db, check_scam_database, add_scam_report, vote_scam_report, get_system_stats
from app.engines.phone_analyzer import analyze_phone_number
from app.engines.email_analyzer import analyze_email_address
from app.engines.content_analyzer import analyze_message_content
from app.main import app


class TestShieldGuardSystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def test_phone_scam_jamaica_area_code(self):
        """Test Jamaican +1-876 lottery scam detection."""
        result = analyze_phone_number("+18765550199")
        self.assertTrue(result["is_valid"])
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "DANGEROUS")
        threat_names = [t["name"] for t in result["threat_factors"]]
        self.assertTrue(any("Caribbean" in name or "Lottery" in name or "Community" in name for name in threat_names))

    def test_phone_legitimate_number(self):
        """Test legitimate business phone number."""
        result = analyze_phone_number("+16502530000") # Google Mountain View
        self.assertTrue(result["is_valid"])
        self.assertLess(result["risk_score"], 40)
        self.assertIn(result["risk_level"], ["SAFE", "LOW_RISK"])

    def test_phone_synthetic_pattern(self):
        """Test detection of sequential/synthetic spoofed numbers."""
        result = analyze_phone_number("+18000000000")
        self.assertGreaterEqual(result["risk_score"], 35)

    def test_email_typosquatting_paypal(self):
        """Test detection of lookalike homoglyph domain (paypa1)."""
        result = analyze_email_address("security@paypa1-update.com")
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "DANGEROUS")
        self.assertTrue(result["email_details"]["typosquatting_detected"])
        self.assertEqual(result["email_details"]["impersonated_brand"], "paypal")

    def test_email_disposable_domain(self):
        """Test detection of burner/disposable email address."""
        result = analyze_email_address("user12345@10minutemail.com")
        self.assertTrue(result["email_details"]["is_disposable"])
        self.assertGreaterEqual(result["risk_score"], 50)

    def test_email_legitimate_google(self):
        """Test legitimate Google email address."""
        result = analyze_email_address("support@google.com")
        self.assertTrue(result["is_valid"])
        self.assertFalse(result["email_details"]["is_disposable"])
        self.assertFalse(result["email_details"]["typosquatting_detected"])
        self.assertLess(result["risk_score"], 30)

    def test_content_kyc_phishing(self):
        """Test phishing message text containing KYC suspension triggers."""
        text = "URGENT: Your Bank account has been blocked due to KYC non-compliance. Click here to verify: http://sbi-kyc.xyz/auth"
        result = analyze_message_content(text)
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertIn("Bank KYC & Account Suspension", result["detected_categories"])
        self.assertEqual(len(result["extracted_urls"]), 1)

    def test_content_legitimate_message(self):
        """Test clean everyday conversation text."""
        text = "Hi Alex, please send the project report when you are free. Thanks!"
        result = analyze_message_content(text)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "SAFE")
        self.assertEqual(len(result["detected_categories"]), 0)

    def test_database_reporting_and_voting(self):
        """Test creating a scam report, querying it, and voting on it."""
        test_id = f"test-scammer-{os.urandom(4).hex()}@fakephish.com"
        report_id = add_scam_report(
            target_type="email",
            identifier=test_id,
            scam_category="Test Scam Category",
            risk_level="HIGH",
            description="Testing report submission and retrieval",
            reported_by="Tester"
        )
        self.assertIsInstance(report_id, int)

        # Check that it is retrievable
        records = check_scam_database(test_id, target_type="email")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["identifier"], test_id)

        # Vote
        updated = vote_scam_report(report_id, is_upvote=True)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["upvotes"], 2)

    def test_api_check_phone_endpoint(self):
        """Test POST /api/check/phone API endpoint."""
        response = self.client.post("/api/check/phone", json={"phone_number": "+18765550199"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("risk_score", data)
        self.assertIn("verdict", data)
        self.assertIn("phone_details", data)

    def test_api_check_email_endpoint(self):
        """Test POST /api/check/email API endpoint."""
        response = self.client.post("/api/check/email", json={"email": "security@paypa1-update.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("risk_score", data)
        self.assertIn("email_details", data)

    def test_api_bulk_endpoint(self):
        """Test POST /api/check/bulk API endpoint."""
        items = ["+18765550199", "security@paypa1-update.com", "support@google.com"]
        response = self.client.post("/api/check/bulk", json={"items": items})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_processed"], 3)
        self.assertGreaterEqual(data["dangerous_count"], 1)


if __name__ == "__main__":
    unittest.main()


