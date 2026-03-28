from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from scanners.subdomains import find_subdomains
from scanners.directories import scan_directories
from scanners.ports import scan_ports
from scanners.vulns import scan_vulnerabilities
from scanners.dns_whois import dns_lookup, whois_lookup, extract_email_security

app = FastAPI()

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "Free Cyber Scan API Running"}

@app.get("/scan")
async def scan(domain: str):
    response = {"domain": domain}

    # Subdomains (crt.sh)
    response["subdomains"] = await find_subdomains(domain)

    # Directory scan (HTTP headers)
    response["directories"] = await scan_directories(domain)

    # Port scan (HackerTarget Nmap)
    response["ports"] = await scan_ports(domain)

    # Vulnerability scan (CVE + TLS + headers + CMS)
    response["vulnerabilities"] = await scan_vulnerabilities(domain)

    # DNS + WHOIS
    dns_result = await dns_lookup(domain)
    whois_result = await whois_lookup(domain)

    response["dns"] = dns_result
    response["whois"] = whois_result

    # Email security (SPF/DMARC)
    response["email_security"] = extract_email_security(dns_result)

    return response
