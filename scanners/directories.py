import httpx

async def scan_directories(domain: str):
    url = f"https://api.hackertarget.com/httpheaders/?q={domain}"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=20)
            return r.text
    except:
        return "Directory scan failed"
