import asyncio
import sys
from database import SessionLocal
from routes.advanced import sync_misp, get_misp_status

async def main():
    db = SessionLocal()
    try:
        print("Checking initial status...")
        status = get_misp_status(db)
        print(f"Stats: {status['stats']}")
        print(f"Logs count: {len(status['logs'])}")

        print("\nTriggering sync...")
        res = await sync_misp(db)
        print(f"Sync result: {res}")

        print("\nChecking new status...")
        status2 = get_misp_status(db)
        print(f"Stats: {status2['stats']}")
        if status2['logs']:
            latest = status2['logs'][0]
            print(f"Latest log: {latest['source']} -> {latest['status']} (new: {latest['items_new']})")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())
