import httpx
import json

async def find_subdomains(domain: str):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=20)
            data = json.loads(r.text)
            subs = list({entry["name_value"] for entry in data})
            return subs
    except:
        return []
