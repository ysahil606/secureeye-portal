"""
Diagnostic: Test all 14 raw IOC feed sources using EXACT same endpoints as production backend.
Run: python test_feeds.py
"""
import asyncio
import httpx
import csv
import io
import xml.etree.ElementTree as ET

TIMEOUT = 25
IP_RE = __import__("re").compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


async def test_source(name, coro):
    try:
        result = await asyncio.wait_for(coro, timeout=TIMEOUT)
        count = result.get("count", 0)
        status = "OK" if count > 0 else "ZERO"
        err = result.get("error", "")
        mark = "[OK]" if count > 0 else "[!!]"
        print(f"  {mark}  {name:<22} {status}  count={count}  {err}")
        return count
    except asyncio.TimeoutError:
        print(f"  [TO]  {name:<22} TIMEOUT")
        return -1
    except Exception as e:
        print(f"  [ER]  {name:<22} ERROR: {e}")
        return -1


async def check_urlhaus():
    """Plain CSV text — no auth"""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://urlhaus.abuse.ch/downloads/csv_recent/")
        if r.status_code != 200:
            return {"count": 0, "error": f"HTTP {r.status_code}"}
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        urls = [l for l in lines if "http" in l]
        return {"count": len(urls)}


async def check_feodotracker():
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        r = await c.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        if r.status_code == 200:
            return {"count": len(r.json())}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_feododomains():
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://feodotracker.abuse.ch/blocklist/?download=domainblocklist")
        if r.status_code == 200:
            domains = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#") and "." in l]
            return {"count": len(domains)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_malwarebazaar():
    """Plain CSV text export — no auth"""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://bazaar.abuse.ch/export/csv/recent/")
        if r.status_code != 200:
            return {"count": 0, "error": f"HTTP {r.status_code}"}
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        reader = list(csv.DictReader(lines))
        hashes = [row for row in reader if len(row.get("sha256_hash", "").strip().strip('"')) == 64]
        return {"count": len(hashes)}


async def check_threatfox():
    """Plain CSV text export — no auth"""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://threatfox.abuse.ch/export/csv/recent/")
        if r.status_code != 200:
            return {"count": 0, "error": f"HTTP {r.status_code}"}
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        reader = list(csv.DictReader(lines))
        return {"count": len(reader)}


async def check_sslblacklist():
    """Aggressive domain/IP list"""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://sslbl.abuse.ch/blacklist/sslblacklist_aggressive.csv")
        print(f"       SSL Aggressive: {r.status_code} len={len(r.content)}")
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
            return {"count": len(lines), "error": f"data_lines={len(lines)}"}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_dshield():
    """XML API"""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://isc.sans.edu/api/sources/attacks/1000/")
        if r.status_code == 200:
            root = ET.fromstring(r.text)
            ips = [s.findtext("ip") for s in root if s.findtext("ip")]
            return {"count": len(ips)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_blocklistde():
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://lists.blocklist.de/lists/all.txt")
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
            return {"count": len(lines)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_spamhaus():
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://www.spamhaus.org/drop/drop.txt")
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith(";")]
            return {"count": len(lines)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_c2tracker():
    """Now backed by FeodoTracker aggressive JSON"""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json")
        if r.status_code == 200:
            data = r.json()
            ips = [e.get("ip_address") for e in data if e.get("ip_address")]
            return {"count": len(ips), "error": "Feodo aggressive JSON"}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_emerging():
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt")
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
            return {"count": len(lines)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_tor():
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://check.torproject.org/torbulkexitlist")
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            return {"count": len(lines)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_openphish():
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as c:
        r = await c.get("https://openphish.com/feed.txt")
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            return {"count": len(lines)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def check_phishtank():
    async with httpx.AsyncClient(timeout=45, follow_redirects=True) as c:
        r = await c.get(
            "https://data.phishtank.com/data/online-valid.csv",
            headers={"User-Agent": "phishtank/secureeye-portal"},
        )
        if r.status_code == 200:
            lines = r.text.splitlines()
            reader = list(csv.DictReader(lines))
            urls = [row for row in reader if row.get("url", "").startswith("http")]
            return {"count": len(urls)}
        return {"count": 0, "error": f"HTTP {r.status_code}"}


async def main():
    print("\n" + "=" * 65)
    print("  SecureEye — Raw IOC Feed Diagnostics (Production Endpoints)")
    print("=" * 65)

    tests = [
        ("URLHaus",          check_urlhaus()),
        ("FeodoTracker",     check_feodotracker()),
        ("FeodoDomains",     check_feododomains()),
        ("MalwareBazaar",    check_malwarebazaar()),
        ("ThreatFox",        check_threatfox()),
        ("SSL Blacklist",    check_sslblacklist()),
        ("DShield/SANS",     check_dshield()),
        ("Blocklist.de",     check_blocklistde()),
        ("Spamhaus DROP",    check_spamhaus()),
        ("C2 Tracker",       check_c2tracker()),
        ("Emerging Threats", check_emerging()),
        ("Tor Exits",        check_tor()),
        ("OpenPhish",        check_openphish()),
        ("PhishTank",        check_phishtank()),
    ]

    print()
    results = []
    for name, coro in tests:
        count = await test_source(name, coro)
        results.append((name, count))

    working  = [(n, c) for n, c in results if c > 0]
    broken   = [(n, c) for n, c in results if c == 0]
    timedout = [(n, c) for n, c in results if c == -1]

    print()
    print("=" * 65)
    print(f"  SUMMARY: {len(working)}/14 working | {len(broken)} returning 0 | {len(timedout)} timeout")
    if broken:
        print("\n  NEEDS FIX:")
        for n, _ in broken:
            print(f"    - {n}")
    if working:
        print("\n  WORKING:")
        for n, c in working:
            print(f"    + {n} ({c} IOCs)")
    print("=" * 65 + "\n")


asyncio.run(main())
