import httpx
import re

SSL_LABS = "https://api.ssllabs.com/api/v3/analyze?host="
CVE_API = "https://cve.circl.lu/api/search/"

async def fetch_headers(domain: str):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"https://{domain}", timeout=20)
            return r.headers
    except:
        return {}

async def fetch_ssl(domain: str):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(SSL_LABS + domain, timeout=40)
            return r.json()
    except:
        return {"error": "SSL scan failed"}

async def lookup_cve(tech: str):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(CVE_API + tech, timeout=20)
            data = r.json()
            if isinstance(data, list):
                return [item.get("id") for item in data[:5]]
            return []
    except:
        return []

def analyze_security_headers(headers):
    issues = []

    h = {k.lower(): v for k, v in headers.items()}

    if "x-frame-options" not in h:
        issues.append("Missing X-Frame-Options (clickjacking risk)")
    if "strict-transport-security" not in h:
        issues.append("Missing HSTS (MITM risk)")
    if "x-content-type-options" not in h:
        issues.append("Missing X-Content-Type-Options (MIME sniffing risk)")
    if "content-security-policy" not in h:
        issues.append("Missing CSP (XSS risk)")

    return issues

def detect_technologies(headers):
    tech = []
    server = headers.get("server", "").lower()

    if "apache" in server:
        tech.append("apache")
    if "nginx" in server:
        tech.append("nginx")
    if "iis" in server:
        tech.append("microsoft iis")
    if "cloudflare" in server:
        tech.append("cloudflare")

    powered = headers.get("x-powered-by", "").lower()
    if "php" in powered:
        tech.append("php")
    if "wordpress" in powered:
        tech.append("wordpress")

    return tech

async def scan_vulnerabilities(domain: str):
    headers = await fetch_headers(domain)
    ssl = await fetch_ssl(domain)

    vulnerabilities = []

    # 1. Security headers
    header_issues = analyze_security_headers(headers)
    vulnerabilities.extend(header_issues)

    # 2. Tech stack
    tech_stack = detect_technologies(headers)

    tech_cves = {}
    for tech in tech_stack:
        tech_cves[tech] = await lookup_cve(tech)

    # 3. SSL issues
    if "endpoints" in ssl:
        endpoint = ssl["endpoints"][0]
        grade = endpoint.get("grade", "Unknown")
        if grade not in ["A+", "A", "A-"]:
            vulnerabilities.append(f"Weak SSL grade: {grade}")

    # 4. CMS vulnerabilities
    if "wordpress" in tech_stack:
        vulnerabilities.append("WordPress detected — check for plugin vulnerabilities")

    return {
        "security_headers": header_issues,
        "tech_stack": tech_stack,
        "cve_matches": tech_cves,
        "ssl_report": ssl,
        "overall_vulnerabilities": vulnerabilities
    }
