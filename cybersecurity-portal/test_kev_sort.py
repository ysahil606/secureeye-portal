import requests

try:
    r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    data = r.json()
    kev_data = data.get("vulnerabilities", [])
    
    kev_data.sort(key=lambda x: (x.get("dateAdded", ""), x.get("cveID", "")), reverse=True)
    
    print("TOP 10 CVEs after sorting:")
    for v in kev_data[:10]:
        print(f"{v.get('cveID')} - {v.get('dateAdded')} - {v.get('vulnerabilityName')}")
        
except Exception as e:
    print(f"Error: {e}")
