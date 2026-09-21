"""
Pydantic Models & Schemas for Request/Response Payloads.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime


class ThreatFactor(BaseModel):
    name: str
    severity: str  # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description: str
    impact_score: int


# Phone Check Models
class PhoneCheckRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number with or without international country code (e.g., +18765550199 or 9876543210)")
    default_country: Optional[str] = Field("US", description="Default ISO 2-letter country code if missing from number")


class PhoneDetails(BaseModel):
    raw_input: str
    e164_format: Optional[str] = None
    national_format: Optional[str] = None
    international_format: Optional[str] = None
    country_code: Optional[int] = None
    country_iso: Optional[str] = None
    location_name: Optional[str] = None
    carrier_name: Optional[str] = None
    line_type: Optional[str] = None  # Mobile, Fixed Line, VoIP, Toll Free, Premium Rate, etc.
    is_valid_format: bool
    is_possible: bool


class PhoneCheckResponse(BaseModel):
    phone_number: str
    is_valid: bool
    risk_score: int  # 0 to 100
    risk_level: str  # 'SAFE', 'LOW_RISK', 'SUSPICIOUS', 'DANGEROUS'
    verdict: str
    phone_details: PhoneDetails
    threat_factors: List[ThreatFactor]
    community_reports: List[Dict[str, Any]]
    recommendations: List[str]


# Email Check Models
class EmailCheckRequest(BaseModel):
    email: str = Field(..., description="Email address to analyze (e.g., security@paypa1-update.com)")
    perform_dns_check: Optional[bool] = Field(True, description="Whether to query live MX and DNS records")


class EmailDetails(BaseModel):
    raw_email: str
    local_part: str
    domain: str
    is_valid_syntax: bool
    is_disposable: bool
    is_free_provider: bool
    is_suspicious_tld: bool
    tld: str
    mx_records_found: bool
    mx_hosts: List[str] = []
    dns_resolvable: bool
    impersonated_brand: Optional[str] = None
    typosquatting_detected: bool = False


class EmailCheckResponse(BaseModel):
    email: str
    is_valid: bool
    risk_score: int  # 0 to 100
    risk_level: str  # 'SAFE', 'LOW_RISK', 'SUSPICIOUS', 'DANGEROUS'
    verdict: str
    email_details: EmailDetails
    threat_factors: List[ThreatFactor]
    community_reports: List[Dict[str, Any]]
    recommendations: List[str]


# Content / Message Check Models
class ContentCheckRequest(BaseModel):
    text: str = Field(..., description="SMS, Email body, WhatsApp text, or message to scan for scams and phishing")


class ContentCheckResponse(BaseModel):
    risk_score: int  # 0 to 100
    risk_level: str  # 'SAFE', 'LOW_RISK', 'SUSPICIOUS', 'DANGEROUS'
    verdict: str
    detected_categories: List[str]
    flagged_keywords: List[str]
    extracted_urls: List[str]
    threat_factors: List[ThreatFactor]
    recommendations: List[str]


# Combined Check Models
class CombinedCheckRequest(BaseModel):
    sender_phone: Optional[str] = None
    sender_email: Optional[str] = None
    message_text: str = Field(..., description="Message text or email body")


class CombinedCheckResponse(BaseModel):
    overall_risk_score: int
    overall_risk_level: str
    verdict: str
    phone_analysis: Optional[PhoneCheckResponse] = None
    email_analysis: Optional[EmailCheckResponse] = None
    content_analysis: ContentCheckResponse
    summary_threats: List[str]
    recommendations: List[str]


# Bulk Check Models
class BulkCheckRequest(BaseModel):
    items: List[str] = Field(..., description="List of phone numbers or email addresses")


class BulkCheckItemResult(BaseModel):
    item: str
    item_type: str  # 'phone' or 'email' or 'unknown'
    is_valid: bool
    risk_score: int
    risk_level: str
    verdict: str
    key_issue: str


class BulkCheckResponse(BaseModel):
    total_processed: int
    safe_count: int
    suspicious_count: int
    dangerous_count: int
    results: List[BulkCheckItemResult]


# Scam Report Models
class ScamReportCreate(BaseModel):
    target_type: str = Field(..., description="'phone', 'email', 'domain', or 'message'")
    identifier: str = Field(..., description="Phone number or email being reported")
    scam_category: str = Field(..., description="e.g. 'Bank KYC', 'Tech Support', 'Lottery', 'Job Offer', 'Courier Delivery', 'Romance Scam', etc.")
    risk_level: Optional[str] = Field("HIGH", description="'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")
    description: str = Field(..., description="Detailed description of the scam attempt, what the caller/sender demanded, etc.")
    reported_by: Optional[str] = Field("Anonymous", description="Name or handle of reporter")
    evidence_url: Optional[str] = Field("", description="Optional URL to screenshot or proof")


class ScamReportResponse(BaseModel):
    id: int
    target_type: str
    identifier: str
    scam_category: str
    risk_level: str
    description: str
    reported_by: str
    upvotes: int
    downvotes: int
    evidence_url: str
    created_at: str


class ReportVoteRequest(BaseModel):
    report_id: int
    is_upvote: bool = True


