import httpx

async def dns_lookup(domain: str):
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=ANY"
    headers = {"accept": "application/dns-json"}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers, timeout=20)
            return r.json()
    except:
        return {"error": "DNS lookup failed"}

async def whois_lookup(domain: str):
    url = f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={domain}"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=20)
            return r.json()
    except:
        return {"error": "WHOIS lookup failed"}

def extract_email_security(dns_json):
    spf = None
    dmarc = None

    if "Answer" in dns_json:
        for record in dns_json["Answer"]:
            if "v=spf1" in record.get("data", "").lower():
                spf = record["data"]
            if "v=dmarc1" in record.get("data", "").lower():
                dmarc = record["data"]

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
