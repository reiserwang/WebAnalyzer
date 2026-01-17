from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class ScanRequest(BaseModel):
    domain: str
    modules: Optional[List[str]] = None  # None means run all, or we can specify
    run_all: bool = True
    scan_mode: str = "domain" # 'domain' or 'local'

class ScanResponse(BaseModel):
    domain: str
    results: Dict[str, Any]

class SslInfo(BaseModel):
    issuer: Dict[str, Any]
    subject: Dict[str, Any]
    version: int
    notBefore: str
    notAfter: str
    subjectAltName: Optional[List[Any]] = None

class RedirectChain(BaseModel):
    url: str
    status_code: int

class WebsiteInfo(BaseModel):
    http_status: Optional[Any] = None
    https_status: Optional[Any] = None
    response_time: Optional[float] = None
    http_response: Optional[str] = None
    https_response: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    https_headers: Optional[Dict[str, str]] = None
    ssl_info: Optional[SslInfo] = None
    is_accessible: bool
    redirect_chain: List[RedirectChain]

class DnsInfo(BaseModel):
    a_records: List[str]
    aaaa_records: List[str]
    cname_records: List[str]
    mx_records: List[str]
    txt_records: List[str]
    ns_records: List[str]
    has_valid_dns: bool

class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    is_registered: bool

class SubdomainTakeoverResult(BaseModel):
    subdomain: str
    timestamp: str
    dns_info: DnsInfo
    website_info: WebsiteInfo
    whois_info: Optional[WhoisInfo] = None
    vulnerable: bool
    service: str
    vulnerability_type: str
    confidence: str
    cname: Optional[str] = None
    description: Optional[str] = None
    exploitation_difficulty: Optional[str] = None
    mitigation: Optional[str] = None

class SubdomainTakeoverResponse(BaseModel):
    subdomain: str
    result: Optional[SubdomainTakeoverResult] = None
    message: str = "No takeover vulnerability detected."
