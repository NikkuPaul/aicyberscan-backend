import os
import httpx

API_KEY = os.getenv("SUBDOMAIN_API_KEY")
API_URL = os.getenv("SUBDOMAIN_API_URL")

async def find_subdomains(domain: str):
    if not API_KEY or not API_URL:
        return []

    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                API_URL,
                params={"domain": domain},
                headers={"Authorization": f"Bearer {API_KEY}"},
                timeout=30
            )
            data = r.json()
            return data.get("subdomains", [])
    except:
        return []
