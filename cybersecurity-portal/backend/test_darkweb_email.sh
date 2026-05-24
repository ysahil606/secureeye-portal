#!/bin/bash
source /home/ubuntu/backend/venv/bin/activate
cd /home/ubuntu/backend

TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  --data-raw '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("access_token","FAIL"))')

echo "Token status: ${TOKEN:0:10}..."

RESULT=$(curl -s "http://localhost:8000/api/darkweb/scan?q=test@example.com" \
  -H "Authorization: Bearer ${TOKEN}")

echo "Parsed:"
echo "$RESULT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('Exposure:', d.get('exposure_level'))
    print('Leaks:', len(d.get('leaks', [])))
    print('Mentions:', len(d.get('mentions', [])))
    print('Sources:', d.get('sources_checked', []))
    for l in d.get('leaks', [])[:10]:
        print('  LEAK:', l.get('source'), '|', str(l.get('hint',''))[:60])
except Exception as e:
    print('Parse error:', e)
"
