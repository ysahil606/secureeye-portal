import asyncio
import logging
from services.auto_enricher import auto_enrich_priority_iocs

logging.basicConfig(level=logging.INFO)

async def main():
    await auto_enrich_priority_iocs()

if __name__ == "__main__":
    asyncio.run(main())
