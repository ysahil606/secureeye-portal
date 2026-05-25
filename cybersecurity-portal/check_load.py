import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URLs_TO_TRY = ["http://localhost:8000/api", "https://secureeye-api.onrender.com/api"]

URL = None
for test_url in URLs_TO_TRY:
    try:
        requests.get(f"{test_url}/health", verify=False, timeout=5)
        URL = test_url
        break
    except:
        pass

if not URL:
    print("Could not reach any backend server.")
    exit(1)


try:
    # 1. Login to get token
    print("Logging in to", URL)
    resp = requests.post(
        f"{URL}/auth/token",
        data={"username": "admin", "password": "Admin@12345"},
        verify=False
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    print("Obtained token.")

    # 2. Get system metrics
    headers = {"Authorization": f"Bearer {token}"}
    metrics_resp = requests.get(f"{URL}/admin/system/metrics", headers=headers, verify=False)
    metrics_resp.raise_for_status()
    
    print("--- SERVER METRICS ---")
    print(json.dumps(metrics_resp.json(), indent=2))
except Exception as e:
    print("Error:", e)
    if hasattr(e, 'response') and e.response is not None:
        print(e.response.text)
