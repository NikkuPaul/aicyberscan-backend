import os
import httpx

API_KEY = os.getenv("TECHSTACK_API_KEY")
API_URL = os.getenv("TECHSTACK_API_URL")  # e.g. https://api.example.com/tech

async def detect_tech_stack(domain: str):
    if not API_KEY or not API_URL:
        return []

    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                API_URL,
                params={"domain": domain},
                headers={"Authorization": f"Bearer {API_KEY}"},
                timeout=15
            )
            data = r.json()
            # adjust this to your provider's response
            return data.get("technologies", [])
    except:
        return []

