import os
import httpx

API_URL = os.getenv("https://api.hackertarget.com/hostsearch/?q=")

async def find_subdomains(domain: str):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{API_URL}{domain}", timeout=15)
            text = r.text

            # HackerTarget returns CSV lines: subdomain,IP
            lines = text.splitlines()
            subs = [line.split(",")[0] for line in lines if "," in line]

            return subs
    except:
        return []
