import httpx
import asyncio

async def test():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        r = await client.post("/api/auth/token", data={"username": "admin", "password": "Admin@12345"})
        if r.status_code != 200:
            print("Auth failed", r.text)
            return
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        endpoints = [
            ("GET", "/api/advanced/overview", None),
            ("GET", "/api/advanced/patch-priority", None),
            ("POST", "/api/advanced/threat-analyst", {"query": "CVE-2023-1234"}),
            ("POST", "/api/advanced/attack-surface", {"domain": "example.com"}),
            ("POST", "/api/advanced/watchlist/preview", {"keywords": ["test"]}),
            ("POST", "/api/advanced/leak-check", {"keyword": "test.com"}),
        ]
        
        for method, url, data in endpoints:
            print(f"Testing {url}...")
            if method == "GET":
                r = await client.get(url, headers=headers)
            else:
                r = await client.post(url, headers=headers, json=data)
            print(f"Status: {r.status_code}")
            if r.status_code != 200:
                print(r.text)

asyncio.run(test())
