"""
FastAPI Server & REST API Entrypoint for ShieldGuard AI Cyber Threat Intelligence Platform.
"""

import os
import time
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html

from app.database import (
    init_db, add_scam_report, get_all_scam_reports, 
    vote_scam_report, get_system_stats, get_analytics_chart_data,
    get_recent_scan_logs
)
from app.models.schemas import (
    PhoneCheckRequest, PhoneCheckResponse,
    EmailCheckRequest, EmailCheckResponse,
    ContentCheckRequest, ContentCheckResponse,
    URLCheckRequest, URLCheckResponse,
    QRCheckRequest, QRCheckResponse,
    CombinedCheckRequest, CombinedCheckResponse,
    BulkCheckRequest, BulkCheckResponse, BulkCheckItemResult,
    ScamReportCreate, ScamReportResponse, ReportVoteRequest,
    HealthCheckResponse, ApiKeyUpdateRequest
)
from app.engines.phone_analyzer import analyze_phone_number
from app.engines.email_analyzer import analyze_email_address
from app.engines.content_analyzer import analyze_message_content
from app.engines.url_analyzer import analyze_url_threat
from app.engines.external_threats import (
    get_api_directory, update_api_key, check_google_safe_browsing,
    generate_ai_threat_briefing
)

# Application startup timestamp for uptime monitoring
START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database & seed threat data
    init_db()
    yield
    # Shutdown


app = FastAPI(
    title="ShieldGuard AI - Spam, Scam & Phishing Intelligence Platform API",
    description="Enterprise-grade REST API for detecting fraudulent phone numbers, typosquatting & disposable emails, phishing links, and deceptive message content.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None  # Custom cyber-themed Swagger UI served at /docs
)

# Enable CORS for cross-origin frontend hosting (Netlify, Vercel, Localhost, Render, etc.)
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


# --- System & Health Endpoints ---

@app.get("/api/health", response_model=HealthCheckResponse, tags=["System Diagnostics"])
def get_health_status():
    """
    Health check endpoint returning system status, latency ping, database connectivity, and uptime.
    """
    stats = get_system_stats()
    uptime = time.time() - START_TIME
    return HealthCheckResponse(
        status="ONLINE",
        uptime_seconds=round(uptime, 2),
        system_version="2.0.0",
        database_status="CONNECTED_SQLITE",
        total_records=stats["total_scam_reports"],
        total_scans_logged=stats["total_scans_performed"],
        active_engine="ShieldGuard Hybrid AI Core",
        timestamp=datetime.now().isoformat() + "Z"
    )


# --- Threat Detection REST API Endpoints ---

@app.post("/api/check/phone", response_model=PhoneCheckResponse, tags=["Scam Detection"])
async def check_phone(request: PhoneCheckRequest):
    """
    Scan a phone or mobile number for caller risk level, VoIP spoofing, Wangiri toll callback traps, and carrier info.
    """
    result = analyze_phone_number(request.phone_number, default_country=request.default_country or "US")
    
    # Optional AI threat narrative
    ai_briefing = await generate_ai_threat_briefing(
        scan_type="Phone Number",
        target=request.phone_number,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        threat_factors=result["threat_factors"]
    )
    result["ai_threat_briefing"] = ai_briefing
    return result


@app.post("/api/check/email", response_model=EmailCheckResponse, tags=["Scam Detection"])
async def check_email(request: EmailCheckRequest):
    """
    Scan an email address for disposable domains, brand typosquatting, MX record readiness, and scam blacklists.
    """
    result = analyze_email_address(request.email, perform_dns_check=request.perform_dns_check)
    
    ai_briefing = await generate_ai_threat_briefing(
        scan_type="Email Address",
        target=request.email,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        threat_factors=result["threat_factors"]
    )
    result["ai_threat_briefing"] = ai_briefing
    return result


@app.post("/api/check/content", response_model=ContentCheckResponse, tags=["Scam Detection"])
async def check_content(request: ContentCheckRequest):
    """
    Scan SMS text, email body, or chat message for phishing patterns, urgency manipulation, and malicious URLs.
    """
    result = analyze_message_content(request.text)
    
    ai_briefing = await generate_ai_threat_briefing(
        scan_type="Message Content",
        target=request.text[:40] + "...",
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        threat_factors=result["threat_factors"]
    )
    result["ai_threat_briefing"] = ai_briefing
    return result


@app.post("/api/check/url", response_model=URLCheckResponse, tags=["Scam Detection"])
async def check_url(request: URLCheckRequest):
    """
    Evaluate a destination URL for homoglyphs, brand typosquatting, high-risk TLDs, raw IP hosts, and phishing keywords.
    """
    result = analyze_url_threat(request.url)
    
    # Check optional live external Google Safe Browsing feed if configured
    external_feed = await check_google_safe_browsing(request.url)
    result["external_feed_result"] = external_feed
    
    if external_feed and external_feed.get("is_threat"):
        result["risk_score"] = max(result["risk_score"], 95)
        result["risk_level"] = "DANGEROUS"
        result["verdict"] = f"GOOGLE SAFE BROWSING: {external_feed.get('threat_type')}"
        result["threat_factors"].insert(0, {
            "name": f"Google Safe Browsing Flag ({external_feed.get('threat_type')})",
            "severity": "CRITICAL",
            "description": external_feed.get("description", "Confirmed malicious by Google Threat Intelligence."),
            "impact_score": 50
        })

    ai_briefing = await generate_ai_threat_briefing(
        scan_type="Web URL",
        target=request.url,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        threat_factors=result["threat_factors"]
    )
    result["ai_threat_briefing"] = ai_briefing
    return result


@app.post("/api/check/qr", response_model=QRCheckResponse, tags=["Scam Detection"])
async def check_qr(request: QRCheckRequest):
    """
    Analyze payload decoded from a QR code (Quishing scan) to detect malicious URLs, spoofed phone numbers, or fraudulent payment links.
    """
    raw_payload = request.qr_data.strip()
    threat_factors = []
    recommendations = []
    
    # Identify payload type
    if raw_payload.startswith(("http://", "https://", "www.")) or "." in raw_payload and "/" in raw_payload:
        payload_type = "url"
        url_res = analyze_url_threat(raw_payload)
        risk_score = url_res["risk_score"]
        risk_level = url_res["risk_level"]
        verdict = f"QR Phishing Link: {url_res['verdict']}"
        threat_factors = url_res["threat_factors"]
        recommendations = url_res["recommendations"]
        analysis_details = url_res
    elif raw_payload.startswith(("tel:", "+")) or (raw_payload.isdigit() and len(raw_payload) >= 7):
        payload_type = "phone"
        clean_num = raw_payload.replace("tel:", "")
        phone_res = analyze_phone_number(clean_num)
        risk_score = phone_res["risk_score"]
        risk_level = phone_res["risk_level"]
        verdict = f"QR Phone Trap: {phone_res['verdict']}"
        threat_factors = phone_res["threat_factors"]
        recommendations = phone_res["recommendations"]
        analysis_details = phone_res
    elif raw_payload.startswith("mailto:") or ("@" in raw_payload and "." in raw_payload):
        payload_type = "email"
        clean_email = raw_payload.replace("mailto:", "")
        email_res = analyze_email_address(clean_email)
        risk_score = email_res["risk_score"]
        risk_level = email_res["risk_level"]
        verdict = f"QR Email Scam: {email_res['verdict']}"
        threat_factors = email_res["threat_factors"]
        recommendations = email_res["recommendations"]
        analysis_details = email_res
    else:
        payload_type = "text"
        content_res = analyze_message_content(raw_payload)
        risk_score = content_res["risk_score"]
        risk_level = content_res["risk_level"]
        verdict = f"QR Text Content: {content_res['verdict']}"
        threat_factors = content_res["threat_factors"]
        recommendations = content_res["recommendations"]
        analysis_details = content_res

    return QRCheckResponse(
        raw_payload=raw_payload,
        payload_type=payload_type,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        analysis_details=analysis_details,
        threat_factors=threat_factors,
        recommendations=recommendations
    )


@app.post("/api/check/combined", response_model=CombinedCheckResponse, tags=["Scam Detection"])
async def check_combined(request: CombinedCheckRequest):
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

    # Composite overall score
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

    ai_briefing = await generate_ai_threat_briefing(
        scan_type="Multi-Vector Correlation",
        target="360° Combined Vector",
        risk_score=overall_score,
        risk_level=overall_level,
        threat_factors=[{"name": st} for st in summary_threats[:3]]
    )

    return {
        "overall_risk_score": overall_score,
        "overall_risk_level": overall_level,
        "verdict": verdict,
        "phone_analysis": phone_res,
        "email_analysis": email_res,
        "content_analysis": content_res,
        "summary_threats": summary_threats,
        "recommendations": list(dict.fromkeys(all_recommendations)),
        "ai_threat_briefing": ai_briefing
    }


@app.post("/api/check/bulk", response_model=BulkCheckResponse, tags=["Bulk Scanner"])
def check_bulk(request: BulkCheckRequest):
    """
    Bulk process up to 100 phone numbers, email addresses, or URLs in a single request.
    """
    results = []
    safe_cnt = 0
    suspicious_cnt = 0
    dangerous_cnt = 0

    for raw_item in request.items[:100]:
        item = raw_item.strip()
        if not item:
            continue

        if item.startswith(("http://", "https://", "www.")) or (len(item.split(".")) >= 2 and "/" in item):
            item_type = "url"
            res = analyze_url_threat(item)
            is_valid = res["is_valid"]
            score = res["risk_score"]
            level = res["risk_level"]
            verdict = res["verdict"]
            key_issue = res["threat_factors"][0]["name"] if res["threat_factors"] else "None (Clean)"
        elif "@" in item:
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


# --- Analytics & Visualizations Endpoints ---

@app.get("/api/analytics/charts", tags=["System Analytics"])
def get_chart_analytics():
    """
    Retrieve structured datasets for Chart.js threat category charts and risk breakdown.
    """
    return get_analytics_chart_data()


@app.get("/api/analytics/recent", tags=["System Analytics"])
def get_recent_scans():
    """
    Retrieve live stream of the 10 most recent threat scans.
    """
    return get_recent_scan_logs(limit=10)


@app.get("/api/stats", tags=["System Analytics"])
def get_stats():
    """Retrieve overall detection statistics and top threat categories."""
    return get_system_stats()


# --- Community Scam Watch & Reports ---

@app.get("/api/reports", tags=["Community Scam Watch"])
def list_scam_reports(
    search: str = Query(None, description="Search keyword in identifier or description"),
    category: str = Query(None, description="Filter by scam category"),
    target_type: str = Query(None, description="Filter by 'phone', 'email', or 'url'"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """Retrieve community-reported scam numbers, emails, and URLs."""
    reports = get_all_scam_reports(limit=limit, offset=offset, category=category, search=search, target_type=target_type)
    return reports


@app.post("/api/reports", tags=["Community Scam Watch"])
def create_scam_report(report: ScamReportCreate):
    """Submit a newly encountered scam phone number, email, or phishing link."""
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


# --- API Directory & Configuration ---

@app.get("/api/system/apis", tags=["System Diagnostics"])
def list_supported_apis():
    """
    Get detailed breakdown of all built-in and external APIs with free tier limits and pricing ($0).
    """
    return get_api_directory()


@app.post("/api/system/config-keys", tags=["System Diagnostics"])
def set_api_key(req: ApiKeyUpdateRequest):
    """Configure external API keys at runtime without server restart."""
    success = update_api_key(req.api_id, req.api_key)
    if not success:
        raise HTTPException(status_code=400, detail=f"Unsupported API identifier '{req.api_id}'")
    return {"status": "success", "message": f"API Key for {req.api_id} saved successfully."}


# --- Frontend Static Serving ---

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=FileResponse, tags=["Web Interface"])
def serve_index():
    """Serve the single-page web dashboard."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "ShieldGuard AI Platform API running. Access frontend or /docs for documentation."}


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Serve Swagger API Documentation with Cyber Dark Theme."""
    response = get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title="ShieldGuard AI - Swagger API Documentation (Cyber Dark Theme)",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_favicon_url="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%233b82f6'><path d='M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4zm0 4l6 2.67V12c0 4.15-2.73 8.04-6 9.15-3.27-1.11-6-5-6-9.15V8.67L12 6z'/></svg>"
    )
    
    html_content = response.body.decode("utf-8")
    
    custom_nav_banner = """
    <div style="background: #0f172a; border-bottom: 1px solid #334155; padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 18px;">🛡️</span>
        <strong style="color: #f8fafc; font-size: 15px;">ShieldGuard AI 2.0 REST API Documentation</strong>
        <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.3);">⚡ Live Swagger Specs</span>
      </div>
      <a href="/" style="background: #1e293b; color: #60a5fa; text-decoration: none; padding: 6px 14px; border-radius: 6px; font-size: 13px; font-weight: 600; border: 1px solid #334155; transition: all 0.2s;">
        ← Back to Threat Dashboard
      </a>
    </div>
    """
    
    html_content = html_content.replace(
        "</head>",
        '<link rel="stylesheet" type="text/css" href="/static/swagger_dark.css">\n</head>'
    )
    html_content = html_content.replace(
        "<body>",
        f"<body>\n{custom_nav_banner}"
    )
    
    return HTMLResponse(content=html_content)
