import sys
sys.path.insert(0, '/home/ubuntu/backend')
from database import SessionLocal
from models import Advisory, IOC, User, FeedLog, SeverityLevel
from sqlalchemy import func

db = SessionLocal()

print("=== IOC Types ===")
types = db.query(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).all()
for t in types:
    print(f"  {t[0]}: {t[1]}")

print("\n=== Feed Log Sources (Top 10) ===")
sources = db.query(FeedLog.feed_source, func.count(FeedLog.id)).group_by(FeedLog.feed_source).order_by(func.count(FeedLog.id).desc()).limit(10).all()
for s in sources:
    print(f"  {s[0]}: {s[1]} runs")

print("\n=== Latest Feed Runs ===")
latest = db.query(FeedLog).order_by(FeedLog.run_at.desc()).limit(5).all()
for f in latest:
    print(f"  {f.feed_source} | {f.status} | new={f.items_new} | {f.run_at}")

print("\n=== User List ===")
users = db.query(User).all()
for u in users:
    print(f"  {u.username} | role={u.role} | active={u.is_active}")

print("\n=== Models Available ===")
import inspect, models
classes = [name for name, obj in inspect.getmembers(models) if inspect.isclass(obj)]
print(" ", classes)

db.close()
