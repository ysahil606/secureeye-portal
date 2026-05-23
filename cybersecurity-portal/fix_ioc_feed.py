"""Repair corrupted raw_ioc_feed.py by reconstructing the broken section."""
with open('backend/services/raw_ioc_feed.py', encoding='utf-8') as f:
    content = f.read()

lines = content.splitlines(keepends=True)

# Identify: corrupt block starts where "    async def fetch_c2_tracker" appears
# inside the blocklistde append dict around line 467

start_idx = None
for i, line in enumerate(lines):
    if 460 < i < 475 and 'async def fetch_c2_tracker' in line and line.startswith('    async'):
        start_idx = i
        break

print(f"Corrupt injection at line {start_idx+1 if start_idx else 'NOT FOUND'}")

if start_idx is None:
    print("File may already be fixed!")
    import ast
    try:
        ast.parse(content)
        print("SYNTAX OK")
    except SyntaxError as e:
        print(f"SYNTAX ERROR: {e}")
    exit(0)

# We will reconstruct from scratch around this section.
# Keep lines 0..start_idx-2 (all content before "Repeated attack attempts" line)
# Then inject the proper complete functions for:
#  - Close of fetch_blocklistde
#  - fetch_spamhaus_drop  
#  - fetch_c2_tracker
# Then resume from fetch_emerging_threats onwards

# Find where fetch_emerging_threats starts
emerging_idx = None
for i, line in enumerate(lines):
    if 'async def fetch_emerging_threats' in line:
        emerging_idx = i
        break

print(f"fetch_emerging_threats at line {emerging_idx+1}")

FIXED_BLOCK = '''                "threat": "Repeated attack attempts",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "Blocklist.de",
            })
            count += 1
    except Exception as e:
        logger.warning(f"Blocklist.de feed failed: {e}")
    return results


# \u2500\u2500 Source 9: Spamhaus DROP \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async def fetch_spamhaus_drop(limit: int = 200) -> List[dict]:
    """Spamhaus DROP \u2014 Hijacked IP space used for spam/attacks."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(SPAMHAUS_DROP_URL)
        if r.status_code != 200:
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split(";")
            cidr = parts[0].strip()
            sbl  = parts[1].strip() if len(parts) > 1 else ""
            ip   = cidr.split("/")[0]
            if not ip or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": cidr,
                "ioc_type": "ip",
                "source": "Spamhaus DROP",
                "source_url": f"https://www.spamhaus.org/sbl/query/{sbl.strip()}" if sbl else "https://www.spamhaus.org/drop/",
                "severity": "high",
                "threat_score": 75.0,
                "tags": ["spam", "hijacked", "bogon", "drop_list"],
                "threat": f"Hijacked IP space ({sbl})",
                "status": "blacklisted",
                "sbl_ref": sbl,
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "Spamhaus DROP",
            })
            count += 1
    except Exception as e:
        logger.warning(f"Spamhaus DROP feed failed: {e}")
    return results


# \u2500\u2500 Source 10: C2 Tracker (Emerging Threats compromised IPs) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
async def fetch_c2_tracker(limit: int = 300) -> List[dict]:
    """
    C2 Tracker \u2014 Emerging Threats compromised-ips.txt (1500+ confirmed C2/compromised IPs).
    The original montysecurity/C2-Tracker GitHub repo is offline; this replaces it.
    """
    results = []
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
        if r.status_code != 200:
            logger.warning(f"C2 Tracker (ET) HTTP {r.status_code}")
            return results
        count = 0
        for line in r.text.splitlines():
            if count >= limit:
                break
            ip = line.strip()
            if not ip or ip.startswith("#") or not _IP_REGEX.match(ip):
                continue
            results.append({
                "value": ip,
                "ioc_type": "ip",
                "source": "C2 Tracker",
                "source_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "severity": "high",
                "threat_score": 80.0,
                "tags": ["c2", "compromised", "emerging_threats", "command_control"],
                "threat": "C2 / Compromised Infrastructure",
                "status": "active",
                "first_seen": _now_iso(),
                "fetched_at": _now_iso(),
                "feed": "C2 Tracker",
            })
            count += 1
    except Exception as e:
        logger.warning(f"C2 Tracker feed failed: {e}")
    return results


'''

# Build new content
new_lines = []
# Part 1: everything before the corrupted injection (before "Repeated attack attempts" line)
for i in range(start_idx - 1):
    new_lines.append(lines[i])

# Part 2: the fixed block
new_lines.append(FIXED_BLOCK)

# Part 3: everything from fetch_emerging_threats onwards
for i in range(emerging_idx, len(lines)):
    new_lines.append(lines[i])

new_content = ''.join(new_lines)

import ast
try:
    ast.parse(new_content)
    print('SYNTAX OK - writing fixed file')
    with open('backend/services/raw_ioc_feed.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print('File repaired successfully!')
    
    # Verify all functions are present
    fns = [l.strip() for l in new_content.splitlines() if l.strip().startswith('async def ')]
    print(f"\nFunctions ({len(fns)}):")
    for fn in fns:
        print(f"  {fn[:60]}")
except SyntaxError as e:
    print(f'SYNTAX ERROR line {e.lineno}: {e.msg}')
    err_lines = new_content.splitlines()
    for k, l in enumerate(err_lines[max(0, e.lineno-4):e.lineno+4], max(0, e.lineno-4)+1):
        print(f'  {k}: {l}')
