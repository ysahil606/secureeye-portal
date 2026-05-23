import asyncio, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, '.')

from services.ioc_lookup import enrich_ioc, _VIRUSTOTAL_KEY, _ABUSEIPDB_KEY, _GREYNOISE_KEY, _OTX_KEY

print("=== API Keys Loaded ===")
print(f"  VirusTotal: {'YES (' + _VIRUSTOTAL_KEY[:8] + '...)' if _VIRUSTOTAL_KEY else 'NOT SET'}")
print(f"  AbuseIPDB:  {'YES (' + _ABUSEIPDB_KEY[:8] + '...)' if _ABUSEIPDB_KEY else 'NOT SET'}")
print(f"  GreyNoise:  {'YES' if _GREYNOISE_KEY else 'NOT SET'}")
print(f"  OTX:        {'YES' if _OTX_KEY else 'NOT SET'}")
print()

async def main():
    print("=== Testing IP: 176.65.139.9 ===")
    results = await enrich_ioc('176.65.139.9', 'ip')
    print(f"Got {len(results)} results")
    for r in results:
        mal = r.get('malicious')
        badge = "MALICIOUS" if mal is True else ("SUSPICIOUS" if mal is None else "CLEAN")
        print(f"  [{r['source_name']}] {badge} | confidence={r.get('confidence')}%")
        print(f"    {r['title'][:90]}")

    print()
    print("=== Testing HASH (EICAR MD5): 44d88612fea8a8f36de82e1278abb02f ===")
    results2 = await enrich_ioc('44d88612fea8a8f36de82e1278abb02f', 'hash')
    print(f"Got {len(results2)} results")
    for r in results2:
        print(f"  [{r['source_name']}] {r['title'][:80]}")

    print()
    print("=== Testing DOMAIN: malware.com ===")
    results3 = await enrich_ioc('malware.com', 'domain')
    print(f"Got {len(results3)} results")
    for r in results3:
        print(f"  [{r['source_name']}] {r['title'][:80]}")

asyncio.run(main())
