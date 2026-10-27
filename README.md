# 🛡️ ShieldGuard AI 2.0 - Multi-Vector Phishing, Scam & Cyber Threat Intelligence Platform

> **Academic Final Year Project Demonstration & Enterprise Cyber Defense Platform**  
> *Developed with FastAPI, Python 3, Vanilla ES6+, Chart.js, and SQLite*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Online](https://img.shields.io/badge/System-Active%20Threat%20Shield-brightgreen.svg)]()
[![Free Tier: $0](https://img.shields.io/badge/Cost-%240.00%20(100%25%20Free%20Tier)-success.svg)]()

---

## 📌 Executive Summary

Modern cybercrime attacks are increasingly **multi-vector** and **hybrid** in nature. An attacker typically combines a **spoofed VoIP caller ID**, a **lookalike homoglyph domain email**, an **urgency-inducing social engineering SMS**, a **malicious QR code (Quishing)**, and a **subdomain-spoofed credential harvesting portal**.

**ShieldGuard AI 2.0** is an end-to-end Cyber Threat Intelligence Platform that correlates across 6 distinct attack surfaces simultaneously, computing real-time risk scores (0–100) with sub-30ms zero-cost latency.

---

## 🚀 Key Architectural Modules

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                      SHIELDGUARD AI SYSTEM ARCHITECTURE                     │
 └─────────────────────────────────────────────────────────────────────────────┘
                                       │
                        [ Client Web Interface (SPA) ]
             (Glassmorphic Cyber UI • Chart.js Visualizations • QR Decoder)
                                       │  HTTP / JSON (REST)
                                       ▼
                       [ FastAPI Gateway & Router Layer ]
                  (CORS • Health Diagnostics • Input Sanitization)
                                       │
     ┌──────────────────┬──────────────┼──────────────┬──────────────────┐
     ▼                  ▼              ▼              ▼                  ▼
[ Phone Engine ] [ Email Engine ] [ Content NLP ] [ URL Engine ]  [ QR Quishing ]
  • E.164 Parse    • Homoglyphs     • Urgency NLP   • Subdomain      • jsQR Canvas
  • Line Type      • MX Records     • Fake Prize    • IP Hosts       • Scheme Router
  • Wangiri Area   • Burner 500+    • KYC Harvest   • High-Risk TLD  • Link Scan
     └──────────────────┴──────────────┼──────────────┴──────────────────┘
                                       │
              ┌────────────────────────┴────────────────────────┐
              ▼                                                 ▼
   [ SQLite Threat Database ]                     [ Optional Cloud APIs ($0) ]
  • 12+ Seeded Attack Profiles                   • Google Safe Browsing (10k/day)
  • Community Upvoting Feed                      • VirusTotal v3 (500/day)
  • Real-Time Scan Logs                          • Google Gemini Flash (15 RPM)
```

1. 📱 **Telecom & Phone Intelligence (`/api/check/phone`)**:
   - Carrier & Line Type classification (Mobile, VoIP, Landline, Premium Rate, Toll-Free).
   - High-risk Wangiri toll callback trap detection (e.g. +1-876 Jamaica, +1-284 BVI).
   - E.164 normalization via Google `libphonenumber`.

2. 📧 **Email Threat & Typosquatting Engine (`/api/check/email`)**:
   - 500+ Disposable & burner email provider blacklist.
   - Levenshtein edit distance ($O(m \times n)$) and homoglyph matrix (0/o, 1/l) targeting top brands (PayPal, Microsoft, Google, Binance).
   - Live asynchronous DNS MX record verification.

3. 💬 **Message & Phishing Content Scanner (`/api/check/content`)**:
   - Social engineering pattern matching: Bank KYC suspensions, fake job lures, cryptocurrency drainers.
   - Psychological urgency & coercive panic trigger analysis.
   - **Interactive Live Phishing Highlighter Sandbox**: Color-coded forensic markers directly on text.

4. 🔗 **URL & Phishing Link Deep Inspector (`/api/check/url`)**:
   - Subdomain deception detection (e.g. `paypal.com.account-verify.top`).
   - Direct IP host detection (`http://192.168.1.55/login`).
   - High-abuse TLD scoring (`.xyz`, `.top`, `.work`, `.click`, `.buzz`, `.cfd`).
   - Obfuscated URL shortener detection (`bit.ly`, `tinyurl.com`, `t.co`).

5. 📷 **QR Code ("Quishing") Phishing Scanner (`/api/check/qr`)**:
   - Drag-and-drop QR code image decoder using client-side canvas and jsQR.
   - Immediate extraction and routing of embedded payloads into the Threat Intelligence pipeline.

6. 🌐 **360° Multi-Vector Correlation Engine (`/api/check/combined`)**:
   - Evaluates Phone + Email + Content in a single request with composite weighted scoring.

7. 📊 **Threat Analytics & Live Visualizations (`/api/analytics/charts`)**:
   - Interactive Chart.js charts: Category Distribution, Threat Severity Breakdown, and Real-Time Audit Feed.

8. 👥 **Crowdsourced Scam Watch Database (`/api/reports`)**:
   - Community-driven threat indexing with live keyword search and upvoting/downvoting.

---

## ⚡ Free APIs & Cost Breakdown ($0 / Month)

ShieldGuard is engineered to operate **100% Free** with no credit card required:

| API / Intelligence Service | Provider | Free Tier Limit | Cost | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **ShieldGuard Core Heuristics** | Local Server | **Unlimited** | **$0.00** | Typosquatting, homoglyphs, E.164, burner emails, urgency NLP |
| **Google Safe Browsing API v4** | Google Cloud | 10,000 queries / day | **$0.00** | Real-time global URL malware & phishing lookup |
| **VirusTotal API v3** | Chronicle | 500 queries / day (4/min) | **$0.00** | Multi-vendor antivirus URL/domain aggregation |
| **Google Gemini 1.5 Flash AI** | Google AI Studio | 15 RPM (1,500/day) | **$0.00** | Generative AI executive threat briefings |
| **IPQualityScore (IPQS)** | IPQS | 5,000 queries / month | **$0.00** | Phone fraud score & disposable email validation |

> **Note**: All cloud API integrations are **optional**. If no API keys are provided, ShieldGuard seamlessly operates on the local zero-latency multi-vector heuristic engine.

---

## 🛠️ Quick Start & Local Execution

### 1. Prerequisites
- Python 3.9+
- Modern Web Browser (Chrome, Firefox, Edge, Safari)

### 2. Installation
```bash
git clone https://github.com/prajapatiparth7905/SheildGuard-Ai-2.0.git
cd SheildGuard-Ai-2.0

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching Application
- **Windows 1-Click**: Double click `start_server.bat`
- **PowerShell**: `powershell -ExecutionPolicy Bypass -File start_server.ps1`
- **Terminal**: `python run.py`

Web Interface: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**  
Interactive Swagger Docs: **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**  
Health Diagnostics: **[http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)**

---

## ☁️ Recommended Production Server Hosting

For final year project presentations and cloud deployments:

### 1. Render.com (Recommended Free Hosting)
1. Push repository to GitHub.
2. Sign in to [render.com](https://render.com) and click **New Web Service**.
3. Connect your repository (`render.yaml` is pre-configured).
4. Click **Deploy**. Render automatically sets up HTTPS, CI/CD, and custom subdomains.

### 2. Railway.app / Fly.io
- Use the included `Dockerfile` and `fly.toml` for containerized hosting with persistent SQLite storage.

### 3. Hugging Face Spaces (Docker Free 16GB RAM)
1. Create a new Space on Hugging Face with the **Docker** SDK.
2. Push this repo. The included `Dockerfile` will automatically build and serve port 8000.

---

## 🧪 Automated Test Suite

Run the full automated test suite covering all engines and REST endpoints:

```bash
python test_system.py
```

Expected Output:
```text
Ran 11 tests in 0.20s ... OK (100% Pass)
```

---

## 📄 License
This project is licensed under the MIT License.
