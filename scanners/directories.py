import httpx

async def scan_directories(domain: str):
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=25)
            data = r.json()
            urls = [row[0] for row in data[1:50]]  # limit to 50 URLs
            return urls
    except:
        return []
