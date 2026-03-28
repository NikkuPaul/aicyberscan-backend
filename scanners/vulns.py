import httpx
import re

CVE_API = "https://cve.circl.lu/api/search/"


async def fetch_headers(domain: str):
    url = f"https://api.hackertarget.com/httpheaders/?q={domain}"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=20)
            return r.text.lower()
    except:
        return ""


async def fetch_tls(domain: str):
    url = f"https://api.hackertarget.com/sslinfo/?q={domain}"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=20)
            return r.text.lower()
    except:
        return ""


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


def analyze_security_headers(headers: str):
    issues = []

    if "x-frame-options" not in headers:
        issues.append("Missing X-Frame-Options (clickjacking risk)")

    if "strict-transport-security" not in headers:
        issues.append("Missing HSTS (MITM risk)")

    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options (MIME sniffing risk)")

    if "content-security-policy" not in headers:
        issues.append("Missing CSP (XSS risk)")

    return issues


def detect_technologies(headers: str):
    tech = []

    if "apache" in headers:
        tech.append("apache")
    if "nginx" in headers:
        tech.append("nginx")
    if "php" in headers:
        tech.append("php")
    if "wordpress" in headers:
        tech.append("wordpress")
    if "cloudflare" in headers:
        tech.append("cloudflare")
    if "iis" in headers:
        tech.append("microsoft iis")

    return tech


async def scan_vulnerabilities(domain: str):
    headers = await fetch_headers(domain)
    tls = await fetch_tls(domain)

    vulnerabilities = []

    # 1. Security header issues
    header_issues = analyze_security_headers(headers)
    vulnerabilities.extend(header_issues)

    # 2. Technology detection
    tech_stack = detect_technologies(headers)

    tech_cves = {}
    for tech in tech_stack:
        tech_cves[tech] = await lookup_cve(tech)

    # 3. TLS issues
    if "expired" in tls:
        vulnerabilities.append("SSL certificate expired")
    if "self-signed" in tls:
        vulnerabilities.append("Self-signed SSL certificate")
    if "tlsv1" in tls:
        vulnerabilities.append("Weak TLS version detected (TLS 1.0)")

    # 4. CMS vulnerabilities
    if "wordpress" in tech_stack:
        vulnerabilities.append("WordPress detected — check for plugin vulnerabilities")

    # 5. Subdomain takeover (basic check)
    if "no a records" in headers:
        vulnerabilities.append("Possible subdomain takeover risk")

    return {
        "security_headers": header_issues,
        "tech_stack": tech_stack,
        "cve_matches": tech_cves,
        "tls_issues": tls,
        "overall_vulnerabilities": vulnerabilities
    }
