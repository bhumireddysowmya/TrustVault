"""Create or upgrade the TrustVault SQLite schema using the application's models."""
from main import Base, engine, DB_PATH

Base.metadata.create_all(engine)
print(f"TrustVault database is ready: {DB_PATH}")
