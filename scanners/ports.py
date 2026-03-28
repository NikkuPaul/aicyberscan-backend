import os
import httpx

API_KEY = os.getenv("qsJ37urm0JKptNhBkALpEFiT6wq12GeG")
API_URL = os.getenv("https://api.shodan.io/shodan/host")

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

