import sqlite3
import os

db_path = 'backend/secureeye.db'
if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
else:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("--- DB STATS ---")
    try:
        cursor.execute("SELECT count(*) FROM advisories")
        print(f"Advisories: {cursor.fetchone()[0]}")
        
        cursor.execute("SELECT count(*) FROM iocs")
        print(f"IOCs: {cursor.fetchone()[0]}")
        
        cursor.execute("SELECT count(*) FROM sectors")
        print(f"Sectors: {cursor.fetchone()[0]}")
        
        # Check for recent advisories
        cursor.execute("SELECT count(*) FROM advisories WHERE published_at > datetime('now', '-7 days')")
        print(f"Recent (7d): {cursor.fetchone()[0]}")
        
    except Exception as e:
        print(f"Error: {e}")
    conn.close()
