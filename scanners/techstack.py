import os
import httpx

API_KEY = os.getenv("ed8119ca-0d4d-44c0-acb1-8c6048b98513")
API_URL = os.getenv("https://api.builtwith.com/v21/api.json")  # e.g. https://api.example.com/tech

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

