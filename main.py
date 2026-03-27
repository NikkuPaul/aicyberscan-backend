from fastapi import FastAPI
import httpx, ssl, socket

app = FastAPI()

@app.post("/scan")
async def scan(data: dict):
    domain = data["domain"]

    ssl_info = await check_ssl(domain)
    headers_info = await check_headers(domain)

    return {
        "domain": domain,
        "ssl": ssl_info,
        "headers": headers_info
    }

async def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": cert["issuer"],
                    "expires": cert["notAfter"]
                }
    except:
        return {"valid": False}

async def check_headers(domain):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"https://{domain}", timeout=10)
            headers = r.headers

            required = [
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy"
            ]

            present = []
            missing = []

            for h in required:
                if h in headers:
                    present.append(h)
                else:
                    missing.append(h)

            return {
                "present": present,
                "missing": missing
            }
    except:
        return {"error": "header scan failed"}
