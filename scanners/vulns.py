import os
import httpx

API_KEY = os.getenv("VULNSCAN_API_KEY")
API_URL = os.getenv("VULNSCAN_API_URL")

async def scan_vulnerabilities(domain: str):
    if not API_KEY or not API_URL:
        return []

    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                API_URL,
                json={"target": domain},
                headers={"Authorization": f"Bearer {API_KEY}"},
                timeout=60
            )
            data = r.json()
            return data.get("findings", [])
    except:
        return []

