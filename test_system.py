"""
Automated Test Suite for ShieldGuard AI Cyber Threat Intelligence Platform.
Tests phone intelligence, email phishing detection, text analysis, URL inspection, QR payloads, and API endpoints.
"""

import os
import unittest
from fastapi.testclient import TestClient

from app.database import init_db, check_scam_database, add_scam_report, vote_scam_report, get_system_stats
from app.engines.phone_analyzer import analyze_phone_number
from app.engines.email_analyzer import analyze_email_address
from app.engines.content_analyzer import analyze_message_content
from app.engines.url_analyzer import analyze_url_threat
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

    def test_content_kyc_phishing(self):
        """Test phishing message text containing KYC suspension triggers."""
        text = "URGENT: Your Bank account has been blocked due to KYC non-compliance. Click here to verify: http://sbi-kyc.xyz/auth"
        result = analyze_message_content(text)
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertIn("Bank KYC & Account Suspension", result["detected_categories"])
        self.assertEqual(len(result["extracted_urls"]), 1)

    def test_url_homoglyph_and_subdomain_spoof(self):
        """Test deep URL inspection on brand impersonation & subdomain tricks."""
        res1 = analyze_url_threat("http://paypal.com.account-verification-login.top/auth")
        self.assertGreaterEqual(res1["risk_score"], 70)
        self.assertEqual(res1["risk_level"], "DANGEROUS")
        self.assertEqual(res1["impersonated_brand"], "paypal")

        res2 = analyze_url_threat("http://192.168.1.55/login")
        self.assertGreaterEqual(res2["risk_score"], 45)

        res3 = analyze_url_threat("https://www.google.com/search?q=cybersecurity")
        self.assertEqual(res3["risk_level"], "SAFE")

    def test_api_health_endpoint(self):
        """Test GET /api/health diagnostics endpoint."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertIn("uptime_seconds", data)
        self.assertIn("system_version", data)

    def test_api_check_url_endpoint(self):
        """Test POST /api/check/url endpoint."""
        response = self.client.post("/api/check/url", json={"url": "http://paypa1-update.xyz/login"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("risk_score", data)
        self.assertIn("components", data)
        self.assertGreaterEqual(data["risk_score"], 60)

    def test_api_check_qr_endpoint(self):
        """Test POST /api/check/qr endpoint."""
        response = self.client.post("/api/check/qr", json={"qr_data": "http://sbi-kyc-verify.top/auth"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["payload_type"], "url")
        self.assertIn("risk_score", data)

    def test_api_analytics_charts_endpoint(self):
        """Test GET /api/analytics/charts endpoint."""
        response = self.client.get("/api/analytics/charts")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("categories", data)
        self.assertIn("verdicts", data)
        self.assertIn("scan_types", data)

    def test_api_system_apis_directory(self):
        """Test GET /api/system/apis endpoint for free APIs & directory."""
        response = self.client.get("/api/system/apis")
        self.assertEqual(response.status_code, 200)
        apis = response.json()
        self.assertTrue(any(a["id"] == "builtin_heuristics" for a in apis))
        self.assertTrue(any(a["id"] == "google_safe_browsing" for a in apis))
        self.assertTrue(any(a["id"] == "virustotal" for a in apis))


if __name__ == "__main__":
    unittest.main()
