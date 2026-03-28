import httpx

async def scan_ports(domain: str):
    url = f"https://api.hackertarget.com/nmap/?q={domain}"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=20)
            return r.text
    except:
        return "Port scan failed"
