import logging
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from api.schemas import ScanRequest, ScanResponse, SubdomainTakeoverResponse, SubdomainTakeoverResult
from api.engine import AnalyzerEngine
import traceback
from urllib.parse import urlparse
from modules.subdomain_takeover import SubdomainTakeover

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("api")

app = FastAPI(title="WebAnalyzer API", version="1.0.0")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)}
    )

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for dev, restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = AnalyzerEngine()

def extract_domain_from_url(url: str) -> str:
    """
    Extracts the domain from a given URL.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not domain:
        raise ValueError("Invalid URL: Could not extract domain.")
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain

@app.post("/api/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest):
    """
    Run the WebAnalyzer scan on the provided domain.
    """
    logger.info(f"Received scan request for domain: {request.domain} with modules: {request.modules}")
    try:
        results = await engine.run_scan(request.domain, request.modules)
        logger.info(f"Scan complete for {request.domain}")
        return ScanResponse(domain=request.domain, results=results)
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

from pydantic import BaseModel
class MSFExecuteRequest(BaseModel):
    module: str
    options: dict
    action: str = 'execute' # execute or check

@app.post("/api/msf/execute")
async def execute_msf_module(request: MSFExecuteRequest):
    """
    Execute a Metasploit module via RPC.
    """
    from modules.msf_suggester import MetasploitSuggester
    logger.info(f"MSF Execution Request: {request.module} Action: {request.action}")
    suggester = MetasploitSuggester()
    result = await suggester.execute_module(request.module, request.options, action=request.action)
    return result

@app.get("/api/analyze/subdomain-takeover", response_model=SubdomainTakeoverResponse)
async def analyze_subdomain_takeover(url: str = Query(..., description="The URL to check for subdomain takeover vulnerability.")):
    """
    Analyzes a given URL for potential subdomain takeover vulnerabilities.
    """
    logger.info(f"Received subdomain takeover analysis request for URL: {url}")
    try:
        domain = extract_domain_from_url(url)
        
        # Instantiate SubdomainTakeover, passing the main domain for logging/output structure
        # The actual check will be done on the full URL (treated as a subdomain in this context)
        subdomain_analyzer = SubdomainTakeover(domain=domain, logger=logger)
        
        # The check_takeover_vulnerability method expects a subdomain string
        # We pass the full URL as the subdomain to be checked
        result = subdomain_analyzer.check_takeover_vulnerability(url)
        
        if result:
            logger.warning(f"Subdomain takeover vulnerability detected for {url}")
            return SubdomainTakeoverResponse(
                subdomain=url,
                result=SubdomainTakeoverResult(**result),
                message="Subdomain takeover vulnerability detected."
            )
        else:
            logger.info(f"No subdomain takeover vulnerability detected for {url}")
            return SubdomainTakeoverResponse(
                subdomain=url,
                result=None,
                message="No subdomain takeover vulnerability detected."
            )
    except ValueError as e:
        logger.error(f"Invalid URL provided: {url} - {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid URL: {e}")
    except Exception as e:
        logger.error(f"Error during subdomain takeover analysis for {url}: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Internal Server Error during analysis: {e}")

@app.get("/api/msf/job/{job_id}")
def get_msf_job_status(job_id: str):
    """
    Get the status of a specific Metasploit job.
    """
    from modules.msf_deep_scan import MSFDeepScanner
    # Target doesn't matter for status check
    scanner = MSFDeepScanner(target="127.0.0.1")
    return scanner.check_job_status(job_id)

@app.get("/api/health")
def health_check():
    return {"status": "ok"}
