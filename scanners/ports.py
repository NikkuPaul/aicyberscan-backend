import os
import httpx

API_KEY = os.getenv("PORTSCAN_API_KEY")
API_URL = os.getenv("PORTSCAN_API_URL")

async def scan_ports(domain: str):
    if not API_KEY or not API_URL:
        return []

    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                API_URL,
                params={"target": domain},
                headers={"Authorization": f"Bearer {API_KEY}"},
                timeout=45
            )
            data = r.json()
            return data.get("open_ports", [])
    except:
        return []

