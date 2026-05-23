import httpx
import asyncio

async def test():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            r = await client.get('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv')
            print('EDB Status:', r.status_code)
        except Exception as e:
            print('EDB Error:', e)
            
        try:
            r = await client.get('https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=1864660085')
            print('PZ Status:', r.status_code)
            if r.status_code != 200:
                print('PZ Text:', r.text[:200])
        except Exception as e:
            print('PZ Error:', e)

asyncio.run(test())
