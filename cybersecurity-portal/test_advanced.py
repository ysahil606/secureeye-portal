import httpx
import asyncio

async def test():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        # get token
        r = await client.post("/auth/token", data={"username": "admin", "password": "password"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        endpoints = [
            ("GET", "/advanced/overview", None),
            ("GET", "/advanced/patch-priority", None),
            ("POST", "/advanced/threat-analyst", {"query": "CVE-2023-1234"}),
            ("POST", "/advanced/attack-surface", {"domain": "example.com"}),
            ("POST", "/advanced/watchlist/preview", {"keywords": ["test"]}),
            ("POST", "/advanced/leak-check", {"keyword": "test.com"}),
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
