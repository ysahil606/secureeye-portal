import asyncio
import logging
from services.ioc_scorer import score_ioc

logging.basicConfig(level=logging.INFO)

async def test_all_sources():
    print("Testing IP: 60.205.186.162 (Testing Shodan, AbuseIPDB, ip-api, GreyNoise, Pulsedive)")
    result_ip = await score_ioc("60.205.186.162", "ip")
    print(f"\nIP Result: {result_ip}")
    
    print("\nTesting Hash: a9d70b0d5c4b88aef79d385e8b96f864a1782abc59633cc382d9c4ab2b3276b8 (Testing MalwareBazaar, ThreatFox, OTX, Pulsedive)")
    result_hash = await score_ioc("a9d70b0d5c4b88aef79d385e8b96f864a1782abc59633cc382d9c4ab2b3276b8", "hash")
    print(f"\nHash Result: {result_hash}")

if __name__ == "__main__":
    asyncio.run(test_all_sources())
