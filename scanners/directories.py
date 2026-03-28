import os
import httpx

API_KEY = os.getenv("https://urlscan.io/api/v1/scan")
API_URL = os.getenv("019d321c-d271-770c-b5ad-0ff77cd87558")

async def scan_directories(domain: str):
    if not API_KEY or not API_URL:
        return []

    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                API_URL,
                params={"domain": domain},
                headers={"Authorization": f"Bearer {API_KEY}"},
                timeout=45
            )
            data = r.json()
            return data.get("paths", [])
    except:
        return []

