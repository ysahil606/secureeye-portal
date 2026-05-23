import requests

url = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
try:
    r = requests.get(url, timeout=10)
    print(f"Status: {r.status_code}")
    data = r.json()
    print(f"Events: {len(data)}")
    first_key = list(data.keys())[0] if data else None
    print(f"First event: {data[first_key] if first_key else None}")
except Exception as e:
    print(f"Error: {e}")
