import requests, json, sys
sys.stdout.reconfigure(encoding='utf-8')

# Login
r = requests.post('http://localhost:8000/auth/token', data={'username':'admin','password':'Admin@12345'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Test IP lookup
print("=== Testing IP: 176.65.139.9 ===")
resp = requests.get('http://localhost:8000/admin/iocs/live-search', 
    params={'search': '176.65.139.9'}, headers=headers)
print(f"Status: {resp.status_code}")
d = resp.json()
print(f"Search mode: {d.get('search_mode')}")
print(f"External items: {len(d.get('external_items', []))}")
for x in d.get('external_items', []):
    print(f"  [{x['source_name']}] {x.get('description','')[:100]}")

print("\n=== Testing malware hash ===")
resp2 = requests.get('http://localhost:8000/admin/iocs/live-search',
    params={'search': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, headers=headers)
print(f"Status: {resp2.status_code}")
d2 = resp2.json()
print(f"External items: {len(d2.get('external_items', []))}")
