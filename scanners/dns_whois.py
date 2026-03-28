import os
import httpx

DNS_URL = os.getenv("https://api.hackertarget.com/dnslookup/?q=")
WHOIS_URL = os.getenv("https://api.hackertarget.com/whois/?q=")

async def dns_lookup(domain: str):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{DNS_URL}{domain}", timeout=15)
            return r.text
    except:
        return "DNS lookup failed"

async def whois_lookup(domain: str):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{WHOIS_URL}{domain}", timeout=15)
            return r.text
    except:
        return "WHOIS lookup failed"

def extract_email_security(dns_text: str):
    spf = None
    dmarc = None

    for line in dns_text.splitlines():
        if "v=spf1" in line.lower():
            spf = line.strip()
        if "v=dmarc1" in line.lower():
            dmarc = line.strip()

    score = "Strong"
    warnings = []

    if not spf:
        score = "Weak"
        warnings.append("Missing SPF record")
    if not dmarc:
        score = "Weak"
        warnings.append("Missing DMARC record")

    return {
        "spf": spf,
        "dmarc": dmarc,
        "email_security_score": score,
        "warnings": warnings
    }
