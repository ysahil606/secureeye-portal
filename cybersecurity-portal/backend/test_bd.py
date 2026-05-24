import asyncio
import httpx
from config import settings

async def t():
    r = await httpx.AsyncClient().get(
        'https://breachdirectory.p.rapidapi.com/?func=auto&term=test@gmail.com',
        headers={'X-RapidAPI-Key': settings.BREACH_DIRECTORY_API_KEY, 'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com'},
        follow_redirects=True
    )
    print("Status:", r.status_code)
    print("Response:", r.text[:200])

asyncio.run(t())
