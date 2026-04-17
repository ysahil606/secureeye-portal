import asyncio
from services.threat_feeds import search_live_sources
from config import settings

async def main():
    print(f"Current Provider: {settings.WEB_SEARCH_PROVIDER}")
    print("Testing live search for: 91.92.241.211")
    try:
        results = await search_live_sources("91.92.241.211")
        print(f"Results found: {len(results.get('items', []))}")
        print(f"Provider used: {results.get('provider')}")
        print(f"Hint: {results.get('configuration_hint')}")
    except Exception as e:
        print(f"Search failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
