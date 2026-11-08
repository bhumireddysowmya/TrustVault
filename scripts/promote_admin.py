"""One-time local bootstrap for an existing account. Run from a trusted shell only."""
import os
from sqlalchemy import select
from main import SessionLocal, User, audit

email = os.environ.get("TRUSTVAULT_ADMIN_EMAIL", "").strip().lower()
if not email:
    raise SystemExit("Set TRUSTVAULT_ADMIN_EMAIL to the already-registered account email")

db = SessionLocal()
try:
    user = db.scalar(select(User).where(User.email == email))
    if not user:
        raise SystemExit(f"No registered account found for {email}. Register it first.")
    if user.role != "admin":
        old_role = user.role
        user.role = "admin"
        db.commit()
        audit(db, user.id, "ADMIN_BOOTSTRAPPED", details={"old_role": old_role, "new_role": "admin"})
    print(f"Administrator role is configured for {user.email} (user ID {user.id}).")
finally:
    db.close()
