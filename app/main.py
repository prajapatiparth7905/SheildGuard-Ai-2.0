"""
FastAPI Server & REST API Entrypoint for ShieldGuard Spam & Scam Detection System.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html

from app.database import (
    init_db, add_scam_report, get_all_scam_reports, 
    vote_scam_report, get_system_stats
)
from app.models.schemas import (
    PhoneCheckRequest, PhoneCheckResponse,
    EmailCheckRequest, EmailCheckResponse,
    ContentCheckRequest, ContentCheckResponse,
    CombinedCheckRequest, CombinedCheckResponse,
    BulkCheckRequest, BulkCheckResponse, BulkCheckItemResult,
    ScamReportCreate, ScamReportResponse, ReportVoteRequest
)
from app.engines.phone_analyzer import analyze_phone_number
from app.engines.email_analyzer import analyze_email_address
from app.engines.content_analyzer import analyze_message_content


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database & seed data
    init_db()
    yield
    # Shutdown


app = FastAPI(
    title="ShieldGuard AI - Spam & Scam Detection Intelligence API",
    description="Comprehensive API for detecting fraudulent phone numbers, malicious/disposable emails, and phishing message content.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None  # Custom dark-themed Swagger UI served at /docs
)

# Enable CORS for external integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static directory path
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)


# --- REST API Endpoints ---

@app.post("/api/check/phone", response_model=PhoneCheckResponse, tags=["Scam Detection"])
def check_phone(request: PhoneCheckRequest):
    """
    Scan a mobile or phone number for spam risk, carrier line type, Wangiri toll fraud, and community scam reports.
    """
    result = analyze_phone_number(request.phone_number, default_country=request.default_country or "US")
    return result


@app.post("/api/check/email", response_model=EmailCheckResponse, tags=["Scam Detection"])
def check_email(request: EmailCheckRequest):
    """
    Scan an email address for disposable domains, brand typosquatting, MX record readiness, and scam blacklists.
    """
    result = analyze_email_address(request.email, perform_dns_check=request.perform_dns_check)
    return result


@app.post("/api/check/content", response_model=ContentCheckResponse, tags=["Scam Detection"])
def check_content(request: ContentCheckRequest):
    """
    Scan SMS text, email body, or chat message for phishing patterns, urgency manipulation, and malicious URLs.
    """
    result = analyze_message_content(request.text)
    return result


@app.post("/api/check/combined", response_model=CombinedCheckResponse, tags=["Scam Detection"])
def check_combined(request: CombinedCheckRequest):
    """
    Perform a complete 360-degree assessment checking sender phone, sender email, and message body together.
    """
    phone_res = None
    email_res = None
    scores = []
    summary_threats = []
    all_recommendations = []

    if request.sender_phone and request.sender_phone.strip():
        phone_res = analyze_phone_number(request.sender_phone.strip())
        scores.append(phone_res["risk_score"])
        for tf in phone_res["threat_factors"]:
            summary_threats.append(f"[Phone] {tf['name']}: {tf['description']}")
        all_recommendations.extend(phone_res["recommendations"])

    if request.sender_email and request.sender_email.strip():
        email_res = analyze_email_address(request.sender_email.strip())
        scores.append(email_res["risk_score"])
        for tf in email_res["threat_factors"]:
            summary_threats.append(f"[Email] {tf['name']}: {tf['description']}")
        all_recommendations.extend(email_res["recommendations"])

    content_res = analyze_message_content(request.message_text)
    scores.append(content_res["risk_score"])
    for tf in content_res["threat_factors"]:
        summary_threats.append(f"[Content] {tf['name']}: {tf['description']}")
    all_recommendations.extend(content_res["recommendations"])

    # Composite overall score (weighted max + average blend)
    max_score = max(scores) if scores else 0
    avg_score = sum(scores) / len(scores) if scores else 0
    overall_score = min(100, int(0.7 * max_score + 0.3 * avg_score))

    if overall_score >= 70:
        overall_level = "DANGEROUS"
        verdict = "CRITICAL MULTI-VECTOR SCAM / PHISHING THREAT"
    elif overall_score >= 40:
        overall_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS THREAT INDICATORS DETECTED"
    elif overall_score >= 20:
        overall_level = "LOW_RISK"
        verdict = "LOW RISK"
    else:
        overall_level = "SAFE"
        verdict = "CLEAN / NO THREATS FOUND"

    return {
        "overall_risk_score": overall_score,
        "overall_risk_level": overall_level,
        "verdict": verdict,
        "phone_analysis": phone_res,
        "email_analysis": email_res,
        "content_analysis": content_res,
        "summary_threats": summary_threats,
        "recommendations": list(dict.fromkeys(all_recommendations))
    }


@app.post("/api/check/bulk", response_model=BulkCheckResponse, tags=["Bulk Scanner"])
def check_bulk(request: BulkCheckRequest):
    """
    Bulk process up to 100 phone numbers or email addresses in a single request.
    """
    results = []
    safe_cnt = 0
    suspicious_cnt = 0
    dangerous_cnt = 0

    for raw_item in request.items[:100]:
        item = raw_item.strip()
        if not item:
            continue

        # Detect item type (Email vs Phone)
        if "@" in item:
            item_type = "email"
            res = analyze_email_address(item, perform_dns_check=False)
            is_valid = res["is_valid"]
            score = res["risk_score"]
            level = res["risk_level"]
            verdict = res["verdict"]
            key_issue = res["threat_factors"][0]["name"] if res["threat_factors"] else "None (Clean)"
        else:
            item_type = "phone"
            res = analyze_phone_number(item)
            is_valid = res["is_valid"]
            score = res["risk_score"]
            level = res["risk_level"]
            verdict = res["verdict"]
            key_issue = res["threat_factors"][0]["name"] if res["threat_factors"] else "None (Clean)"

        if level == "DANGEROUS":
            dangerous_cnt += 1
        elif level == "SUSPICIOUS":
            suspicious_cnt += 1
        else:
            safe_cnt += 1

        results.append(BulkCheckItemResult(
            item=item,
            item_type=item_type,
            is_valid=is_valid,
            risk_score=score,
            risk_level=level,
            verdict=verdict,
            key_issue=key_issue
        ))

    return BulkCheckResponse(
        total_processed=len(results),
        safe_count=safe_cnt,
        suspicious_count=suspicious_cnt,
        dangerous_count=dangerous_cnt,
        results=results
    )


# --- Community Scam Reports & Analytics ---

@app.get("/api/reports", tags=["Community Scam Watch"])
def list_scam_reports(
    search: str = Query(None, description="Search keyword in identifier or description"),
    category: str = Query(None, description="Filter by scam category"),
    target_type: str = Query(None, description="Filter by 'phone' or 'email'"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """Retrieve community-reported scam numbers and emails."""
    reports = get_all_scam_reports(limit=limit, offset=offset, category=category, search=search, target_type=target_type)
    return reports


@app.post("/api/reports", tags=["Community Scam Watch"])
def create_scam_report(report: ScamReportCreate):
    """Submit a newly encountered scam phone number or email."""
    if not report.identifier.strip() or not report.description.strip():
        raise HTTPException(status_code=400, detail="Identifier and description are required.")

    report_id = add_scam_report(
        target_type=report.target_type,
        identifier=report.identifier,
        scam_category=report.scam_category,
        risk_level=report.risk_level or "HIGH",
        description=report.description,
        reported_by=report.reported_by or "Anonymous",
        evidence_url=report.evidence_url or ""
    )
    return {"status": "success", "message": "Scam report successfully submitted and indexed.", "report_id": report_id}


@app.post("/api/reports/{report_id}/vote", tags=["Community Scam Watch"])
def vote_report(report_id: int, vote: ReportVoteRequest):
    """Upvote or downvote a scam report to adjust community confidence."""
    updated = vote_scam_report(report_id, is_upvote=vote.is_upvote)
    if not updated:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"status": "success", "report": updated}


@app.get("/api/stats", tags=["System Analytics"])
def get_stats():
    """Retrieve overall detection statistics and top threat categories."""
    return get_system_stats()


# --- Frontend Static Files Serving ---

# Mount static folder
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=FileResponse, tags=["Web Interface"])
def serve_index():
    """Serve the single-page web dashboard."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "ShieldGuard API running. Access frontend or /docs for API documentation."}


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Serve Swagger API Documentation with modern Cyber Dark Theme."""
    response = get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title="ShieldGuard AI - Swagger API Documentation (Dark Mode)",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_favicon_url="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%233b82f6'><path d='M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4zm0 4l6 2.67V12c0 4.15-2.73 8.04-6 9.15-3.27-1.11-6-5-6-9.15V8.67L12 6z'/></svg>"
    )
    
    html_content = response.body.decode("utf-8")
    
    # Custom top banner in Swagger UI with Back to Dashboard link and Dark Mode badge
    custom_nav_banner = """
    <div style="background: #0f172a; border-bottom: 1px solid #334155; padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 18px;">🛡️</span>
        <strong style="color: #f8fafc; font-size: 15px;">ShieldGuard AI Swagger Docs</strong>
        <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.3);">🌙 Cyber Dark Mode</span>
      </div>
      <a href="/" style="background: #1e293b; color: #60a5fa; text-decoration: none; padding: 6px 14px; border-radius: 6px; font-size: 13px; font-weight: 600; border: 1px solid #334155; transition: all 0.2s;">
        ← Back to Threat Dashboard
      </a>
    </div>
    """
    
    # Inject dark stylesheet and custom banner
    html_content = html_content.replace(
        "</head>",
        '<link rel="stylesheet" type="text/css" href="/static/swagger_dark.css">\n</head>'
    )
    html_content = html_content.replace(
        "<body>",
        f"<body>\n{custom_nav_banner}"
    )
    
    return HTMLResponse(content=html_content)



