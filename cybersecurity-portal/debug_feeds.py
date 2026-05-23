"""Test the exact same logic now deployed in raw_ioc_feed.py for the 4 problem sources."""
import asyncio, httpx, csv, io, xml.etree.ElementTree as ET
import re

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

async def test():
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:

        # ── MalwareBazaar: positional CSV reader, col 1 = sha256 ─────────────────
        r = await c.get("https://bazaar.abuse.ch/export/csv/recent/")
        count = 0
        for row in csv.reader(io.StringIO(r.text)):
            if not row or row[0].startswith("#") or len(row) < 9:
                continue
            sha256 = row[1].strip().strip('"')
            if sha256 and len(sha256) == 64:
                count += 1
        print(f"MalwareBazaar (positional CSV): HTTP {r.status_code} | {count} valid hashes")

        # ── SSL Blacklist: sslblacklist.csv ───────────────────────────────────────
        r2 = await c.get("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
        sha1s = []
        for line in r2.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                sha1 = parts[1].strip()
                if len(sha1) == 40:
                    sha1s.append(sha1)
        print(f"SSL Blacklist (sslblacklist.csv): HTTP {r2.status_code} | {len(sha1s)} SHA1 fingerprints | preview: {sha1s[:2]}")

        # ── DShield: /999/ XML ────────────────────────────────────────────────────
        r3 = await c.get("https://isc.sans.edu/api/sources/attacks/999/")
        root = ET.fromstring(r3.text)
        ips = [s.findtext("ip") for s in root if s.findtext("ip") and IP_RE.match(s.findtext("ip") or "")]
        print(f"DShield /999/: HTTP {r3.status_code} | {len(ips)} IPs | preview: {ips[:3]}")

        # ── C2 Tracker: Spamhaus EDROP ────────────────────────────────────────────
        r4 = await c.get("https://www.spamhaus.org/drop/edrop.txt")
        entries = []
        for line in r4.text.splitlines():
            line = line.strip()
            if line and not line.startswith(";"):
                ip = line.split(";")[0].strip().split("/")[0]
                if IP_RE.match(ip):
                    entries.append(ip)
        print(f"C2 Tracker (Spamhaus EDROP): HTTP {r4.status_code} | {len(entries)} CIDRs | preview: {entries[:3]}")

asyncio.run(test())
