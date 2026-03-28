from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from subdomains import find_subdomains
from directories import scan_directories
from ports import scan_ports
from vulns import scan_vulnerabilities
from dns_whois import dns_lookup, whois_lookup, extract_email_security

app = FastAPI()

# CORS for your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/scan")
async def scan(domain: str):
    response = {"domain": domain}

    # Subdomains
    subdomains = await find_subdomains(domain)
    response["subdomains"] = subdomains

    # Directory Scan (urlscan.io)
    directories = await scan_directories(domain)
    response["directories"] = directories

    # Port Scan (Shodan)
    ports = await scan_ports(domain)
    response["ports"] = ports

    # Vulnerability Scan (CriminalIP)
    vulns = await scan_vulnerabilities(domain)
    response["vulnerabilities"] = vulns

    # DNS Lookup
    dns_result = await dns_lookup(domain)
    response["dns"] = dns_result

    # WHOIS Lookup
    whois_result = await whois_lookup(domain)
    response["whois"] = whois_result

    # SPF / DMARC Email Security
    email_security = extract_email_security(dns_result)
    response["email_security"] = email_security

    return response


@app.get("/")
def home():
    return {"message": "Privacy Scan API Running"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
