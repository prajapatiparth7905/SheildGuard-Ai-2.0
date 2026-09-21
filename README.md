# 🛡️ ShieldGuard AI 2.0 - Advanced Spam & Scam Detection System

ShieldGuard AI is a multi-vector intelligence and threat detection platform built to identify, analyze, and neutralize spam calls, fraudulent emails, and phishing/smishing messages in real time.

---

## 🚀 Key Features

- 📱 **Phone Intelligence Engine (`/api/analyze/phone`)**:
  - Carrier & line-type detection (Mobile, Fixed Line, VoIP, Premium Rate, Toll-Free, Shared Cost).
  - Wangiri trap identification & high-risk international spoof prefix detection.
  - Number format normalization (E.164, National, International, RFC3966).
  - Risk score calculation (0–100) with detailed risk level indicators.

- 📧 **Email Threat Analyzer (`/api/analyze/email`)**:
  - Domain MX record verification & DNS checks.
  - Disposable / temporary email provider blacklist checking.
  - Free email provider detection (e.g., suspicious enterprise communication via free webmail).
  - Brand impersonation & Unicode homoglyph / lookalike domain detection.

- 💬 **Message & Phishing Content Scanner (`/api/analyze/content`)**:
  - Keyword pattern matching for financial traps, urgency tactics, lottery scams, and extortion.
  - Embedded URL and link analysis for deceptive, spoofed, and high-risk TLDs.
  - Brand misuse and spoofing detection.
  - Deep threat explanation and actionable security recommendations.

- 👥 **Community Scam Database & Threat Intelligence**:
  - Built-in SQLite database tracking reported scam numbers, emails, and phrases.
  - Upvote/Downvote crowdsourced reputation system.
  - Real-time audit logs and live statistics dashboard.

- 💻 **Interactive Cyberpunk / Modern Web Dashboard**:
  - Real-time single-page application with tabs for all analyzers.
  - Live statistics, quick samples for instant testing, and community reporting modal.
  - Dark-mode Swagger UI API docs (`/docs`).

- ⚡ **Interactive CLI (`cli.py`)**:
  - Command-line tool with interactive shell and batch command support.

---

## 📁 Project Structure

```text
├── app/
│   ├── data/                   # Knowledge bases, brand patterns, TLD lists, scam prefixes
│   ├── engines/                # Intelligence engines (phone, email, content analyzers)
│   ├── models/                 # Pydantic schemas and request/response models
│   ├── static/                 # Modern web dashboard (HTML, CSS, JS, dark swagger theme)
│   ├── database.py             # SQLite persistence, schema, seed data, stats
│   └── main.py                 # FastAPI application, CORS, routers & endpoints
├── data/
│   └── shieldguard.db          # Database file (auto-generated)
├── cli.py                      # Interactive Command Line Interface
├── package.json                # NPM configuration and script shortcuts
├── requirements.txt            # Python dependencies
├── run.py                      # Application bootstrap & auto-browser launch
└── test_system.py              # Test suite (unit & integration tests)
```

---

## 🛠️ Quick Start

### 1. Prerequisites
- Python 3.9+ installed
- Node.js & npm (optional, for npm script runner)

### 2. Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/prajapatiparth7905/SheildGuard-Ai-2.0.git
cd SheildGuard-Ai-2.0

# Install Python requirements
pip install -r requirements.txt
```

### 3. Running the Application

Using **NPM**:
```bash
npm run dev
```

Or directly with **Python**:
```bash
python run.py
```

The server will start at **`http://127.0.0.1:8000`** and open your default browser automatically.

---

## 🌐 API & Interactive Docs

Once running, explore the interactive documentation:
- **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc UI**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 💻 CLI Usage

ShieldGuard comes with a CLI for terminal users:

```bash
# Interactive Mode
python cli.py --interactive

# Analyze a Phone Number
python cli.py --phone "+14155552671"

# Analyze an Email
python cli.py --email "security@paypa1-update.com"

# Analyze a Message
python cli.py --content "URGENT: Your account has been suspended. Click http://bank-verify.top now!"
```

---

## 🧪 Running Tests

Execute the automated test suite:

```bash
npm test
# or
python test_system.py
```

---

## 📄 License

This project is licensed under the MIT License.
