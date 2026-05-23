import asyncio, httpx, io

async def test():
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
        # URLHaus CSV
        r = await c.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
        print(f"URLHaus CSV: {r.status_code} len={len(r.content)}")
        if r.status_code == 200:
            print(f"  Preview: {r.text[:100].strip()}...")

        # MalwareBazaar CSV
        r2 = await c.get("https://bazaar.abuse.ch/export/csv/recent/")
        print(f"MalwareBazaar CSV: {r2.status_code} len={len(r2.content)}")
        if r2.status_code == 200:
            print(f"  Preview: {r2.text[:100].strip()}...")

        # ThreatFox CSV
        r3 = await c.get("https://threatfox.abuse.ch/export/csv/recent/")
        print(f"ThreatFox CSV: {r3.status_code} len={len(r3.content)}")
        if r3.status_code == 200:
            print(f"  Preview: {r3.text[:100].strip()}...")

        # C2 Tracker (Emerging Threats Compromised IPs)
        c2_url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        r4 = await c.get(c2_url)
        lines = [l for l in r4.text.splitlines() if l.strip() and not l.startswith("#")] if r4.status_code == 200 else []
        print(f"C2Tracker (Emerging Threats): {r4.status_code} lines={len(lines)}")

        # CI Badguys (Replacing deprecated SSL Blacklist)
        r5 = await c.get("http://cinsscore.com/list/ci-badguys.txt")
        lines5 = [l for l in r5.text.splitlines() if l.strip() and not l.startswith("#")] if r5.status_code == 200 else []
        print(f"CI Badguys IP List: {r5.status_code} data_lines={len(lines5)} preview={lines5[:2]}")

asyncio.run(test())
