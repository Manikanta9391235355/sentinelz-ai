import sys
import os
sys.path.insert(0, '/opt/sentinelz-ai')

from backend.app.database import engine, Base, SessionLocal
from backend.app.services.seeder import seed_database

print("[INIT] Creating database tables...")
Base.metadata.create_all(bind=engine)

print("[INIT] Seeding baseline accounts and synthetic telemetry...")
db = SessionLocal()
result = seed_database(db)
db.close()

print(f"[SUCCESS] Database initialized successfully: {result}")
