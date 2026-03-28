import os
import httpx

API_KEY = os.getenv("DIRSCAN_API_KEY")
API_URL = os.getenv("DIRSCAN_API_URL")

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

