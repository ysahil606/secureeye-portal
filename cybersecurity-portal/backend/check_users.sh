#!/bin/bash
# Check admin password and run darkweb test
source /home/ubuntu/backend/venv/bin/activate
cd /home/ubuntu/backend

echo "=== Admin password hash ==="
python3 << 'EOF'
from database import SessionLocal
from models import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
db = SessionLocal()
users = db.query(User).all()
for u in users:
    print(f"  {u.username} | hash: {u.hashed_password[:40]}")
db.close()
EOF
