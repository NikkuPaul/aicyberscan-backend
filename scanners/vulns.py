import os
import httpx

API_KEY = os.getenv("FGVdNMmBQMMbZWlgD5giRgEIkqNH7z5mfelm6ADFpeI83z7F5A4KQeyW2dTI")
API_URL = os.getenv("https://api.criminalip.io/v1/scan/web")

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

