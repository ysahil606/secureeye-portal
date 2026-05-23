import asyncio, sys
sys.path.insert(0, '.')
from services.ioc_lookup import enrich_ioc

async def main():
    print("=== Testing IP: 176.65.139.9 ===")
    results = await enrich_ioc('176.65.139.9', 'ip')
    print(f"Got {len(results)} results")
    for r in results:
        print(f"  [{r['source_name']}] malicious={r.get('malicious')} confidence={r.get('confidence')}%")
        print(f"    {r['title'][:80]}")
    
    print("\n=== Testing HASH: 44d88612fea8a8f36de82e1278abb02f ===")
    results2 = await enrich_ioc('44d88612fea8a8f36de82e1278abb02f', 'hash')
    print(f"Got {len(results2)} results")
    for r in results2:
        print(f"  [{r['source_name']}] {r['title'][:80]}")

asyncio.run(main())
