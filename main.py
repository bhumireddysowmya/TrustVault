"""TrustVault: encrypted document sharing with server-side authorization and audit logging.

The server stores encrypted document bytes only. It enforces document permissions on
all document operations; browser-side encryption does not replace authorization.
"""
import os, uuid, json, hashlib, base64, re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form, Query, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, String, Integer, Text, DateTime, ForeignKey, UniqueConstraint, select, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
bearer_scheme = HTTPBearer()
ROOT = Path(__file__).parent
DATA = Path(os.environ.get("TRUSTVAULT_DATA_DIR", os.environ.get("SECUREVAULT_DATA_DIR", ROOT / "data"))).resolve()
STORE = DATA / "encrypted"
DATA.mkdir(exist_ok=True, parents=True)
STORE.mkdir(exist_ok=True, parents=True)
DB_PATH = DATA / "securevault.db"  # retain the existing database filename for in-place upgrade
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
APP_ENV = os.environ.get("APP_ENV", "development").lower()
JWT_SECRET = os.environ.get("TRUSTVAULT_JWT_SECRET") or os.environ.get("SECUREVAULT_JWT_SECRET") or "local-development-secret-change-before-deployment"
if APP_ENV == "production":
    if not os.environ.get("TRUSTVAULT_JWT_SECRET") or len(os.environ.get("TRUSTVAULT_JWT_SECRET", "")) < 32:
        raise RuntimeError("Set a random TRUSTVAULT_JWT_SECRET of at least 32 characters in production")
    audit_key_path = os.environ.get("TRUSTVAULT_AUDIT_PRIVATE_KEY")
    if not audit_key_path or not Path(audit_key_path).expanduser().is_file():
        raise RuntimeError("Set TRUSTVAULT_AUDIT_PRIVATE_KEY to an existing protected PEM file in production")
MAX_BYTES = 20 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".txt", ".png", ".jpg", ".jpeg", ".xlsx", ".pptx", ".csv"}


def signer_load():
    # Production deployments should provide TRUSTVAULT_AUDIT_PRIVATE_KEY as a PEM file path
    # and keep it outside the application/data directory with restricted access.
    configured = os.environ.get("TRUSTVAULT_AUDIT_PRIVATE_KEY")
    p = Path(configured).expanduser() if configured else DATA / "audit-signing-key.pem"
    if p.exists():
        return serialization.load_pem_private_key(p.read_bytes(), password=None)
    k = Ed25519PrivateKey.generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return k


signer = signer_load()

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    public_key: Mapped[str] = mapped_column(Text)
    private_key_bundle: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="owner")

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(150))
    stored_name: Mapped[str] = mapped_column(String(100), unique=True)
    category: Mapped[str] = mapped_column(String(80), default="General")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("document_id", "user_id", name="uq_permission_document_user"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    wrapped_key: Mapped[str] = mapped_column(Text)
    permission: Mapped[str] = mapped_column(String(20), default="read")  # owner, read, edit

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    actor_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    details: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    signature: Mapped[str] = mapped_column(Text)

Base.metadata.create_all(engine)

# Small SQLite migration for databases created by the earlier SecureVault prototype.
def migrate_legacy_schema():
    insp = inspect(engine)
    if "users" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("users")}
        if "role" not in cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'owner'"))
    if "permissions" in insp.get_table_names():
        with engine.begin() as conn:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_permission_document_user ON permissions(document_id, user_id)"))
    if "documents" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("documents")}
        with engine.begin() as conn:
            if "category" not in cols:
                conn.execute(text("ALTER TABLE documents ADD COLUMN category VARCHAR(80) NOT NULL DEFAULT 'General'"))
            if "updated_at" not in cols:
                conn.execute(text("ALTER TABLE documents ADD COLUMN updated_at DATETIME"))
                conn.execute(text("UPDATE documents SET updated_at = created_at WHERE updated_at IS NULL"))

migrate_legacy_schema()


def db_dep():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()

def b64(x):
    return base64.b64encode(x).decode()


def audit(db: Session, actor, action, doc=None, details=None):
    """Append a hash-linked, signed event with identity snapshots."""

    last = db.scalar(
        select(Audit).order_by(Audit.id.desc())
    )
    prev = last.event_hash if last else "0" * 64

    ts = datetime.now(timezone.utc).isoformat()

    # Identify the person who performed the action
    actor_id = actor.id if isinstance(actor, User) else actor
    event_details = dict(details or {})

    actor_user = db.get(User, actor_id) if actor_id is not None else None

    if actor_user:
        event_details["actor_snapshot"] = {
            "name": actor_user.name,
            "email": actor_user.email,
            "role": actor_user.role
        }

    # Identify the affected user, if this is a user-related action
    target_id = event_details.get("target_user_id")

    if target_id is not None:
        try:
            target_user = db.get(User, int(target_id))
        except (TypeError, ValueError):
            target_user = None

        if target_user:
            event_details["target_user_snapshot"] = {
                "name": target_user.name,
                "email": target_user.email,
                "role": target_user.role
            }

    # Save the document name for future reference
    if doc is not None:
        document = db.get(Document, doc)

        if document:
            event_details["document_snapshot"] = {
                "filename": document.filename
            }

    payload = {
        "document_id": doc,
        "actor_id": actor_id,
        "action": action,
        "details": event_details,
        "timestamp": ts,
        "previous_hash": prev
    }

    digest = hashlib.sha256(canonical(payload)).hexdigest()

    db.add(Audit(
        document_id=doc,
        actor_id=actor_id,
        action=action,
        details=json.dumps(event_details, sort_keys=True),
        timestamp=datetime.fromisoformat(ts),
        previous_hash=prev,
        event_hash=digest,
        signature=b64(signer.sign(digest.encode()))
    ))

    db.commit()


def token_for(u):
    return jwt.encode({"sub": str(u.id), "exp": datetime.now(timezone.utc) + timedelta(hours=4)}, JWT_SECRET, algorithm="HS256")

def auth(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: Session = Depends(db_dep)
):
    try:
        uid = int(
            jwt.decode(
                credentials.credentials,
                JWT_SECRET,
                algorithms=["HS256"]
            )["sub"]
        )
    except (JWTError, ValueError, KeyError):
        raise HTTPException(401, "Session expired")

    u = db.get(User, uid)

    if not u:
        raise HTTPException(401, "User not found")

    return u

def require_admin(u: User = Depends(auth), db: Session = Depends(db_dep)):
    if u.role != "admin":
        audit(db, u.id, "ADMIN_ACTION_DENIED", details={"role": u.role})
        raise HTTPException(403, "Administrator role required")
    return u

def permission(db, did, uid):
    return db.scalar(select(Permission).where(Permission.document_id == did, Permission.user_id == uid))

def require_document_access(db, did, user, allowed=("owner", "read", "edit")):
    d = db.get(Document, did)
    p = permission(db, did, user.id)
    if not d or not p or p.permission not in allowed or (user.role == "viewer" and p.permission != "read"):
        audit(db, user.id, "ACCESS_DENIED", did, {"operation": "document_access"})
        raise HTTPException(403, "Access denied: you are not authorized for this document")
    return d, p

def require_owner_or_admin(db, did, user):
    d = db.get(Document, did)
    if not d or (user.role != "admin" and (d.owner_id != user.id or user.role == "viewer")):
        audit(db, user.id, "OWNER_ACTION_DENIED", did, {"operation": "owner_only"})
        raise HTTPException(403, "Only the document owner or administrator can perform this action")
    return d

def user_payload(u):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role,
            "public_key": u.public_key, "private_key_bundle": u.private_key_bundle}

app = FastAPI(title="TrustVault", version="1.0.0", description="Secure document sharing with a tamper-evident audit trail")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")

class Register(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    public_key: str
    private_key_bundle: str
class Login(BaseModel):
    email: EmailStr
    password: str
class Share(BaseModel):
    email: EmailStr
    wrapped_key: str = Field(min_length=16, max_length=4096)
    permission: str = "read"
class DocumentUpdate(BaseModel):
    filename: Optional[str] = Field(default=None, min_length=1, max_length=255)
    category: Optional[str] = Field(default=None, max_length=80)
class RoleUpdate(BaseModel):
    role: str

@app.post("/api/register")
def register(x: Register, db: Session = Depends(db_dep)):
    email = x.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered")
    if len(x.password.encode("utf-8")) > 72:
        raise HTTPException(400, "Password must be at most 72 UTF-8 bytes for bcrypt")
    if len(x.public_key) > 5000 or "BEGIN PUBLIC KEY" not in x.public_key or len(x.private_key_bundle) > 10000:
        raise HTTPException(400, "Invalid encryption key material")
    admin_email = os.environ.get("TRUSTVAULT_ADMIN_EMAIL", "").lower().strip()
    role = "admin" if admin_email and email == admin_email else "owner"
    u = User(name=x.name.strip(), email=email, password_hash=pwd.hash(x.password),
             public_key=x.public_key, private_key_bundle=x.private_key_bundle, role=role)
    db.add(u); db.commit(); db.refresh(u)
    audit(db, u.id, "ACCOUNT_REGISTERED", details={"role": role})
    return {"token": token_for(u), "user": user_payload(u)}

@app.post("/api/login")
def login(x: Login, db: Session = Depends(db_dep)):
    u = db.scalar(select(User).where(User.email == x.email.lower()))
    if len(x.password.encode("utf-8")) > 72 or not u or not pwd.verify(x.password, u.password_hash):
        audit(db, None, "LOGIN_FAILED", details={"email": x.email.lower()})
        raise HTTPException(401, "Incorrect email or password")
    audit(db, u.id, "LOGIN_SUCCESS")
    return {"token": token_for(u), "user": user_payload(u)}

@app.get("/api/me")
def me(u: User = Depends(auth)):
    return {"id": u.id, "name": u.name, "email": u.email, "role": u.role}

@app.get("/api/lookup")
def lookup(email: str, u: User = Depends(auth), db: Session = Depends(db_dep)):
    r = db.scalar(select(User).where(User.email == email.lower()))
    if not r: raise HTTPException(404, "Recipient has not registered yet")
    return {"email": r.email, "public_key": r.public_key}

@app.post("/api/documents")
async def upload(file: UploadFile = File(...), wrapped_key: str = Form(...), category: str = Form("General"),
                 u: User = Depends(auth), db: Session = Depends(db_dep)):
    if u.role == "viewer":
        audit(db, u.id, "UPLOAD_DENIED", details={"reason": "viewer_role"})
        raise HTTPException(403, "Viewer accounts cannot upload documents")
    filename = Path(file.filename or "file").name[:255]
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        audit(db, u.id, "UPLOAD_DENIED", details={"filename": filename, "reason": "unsupported_extension"})
        raise HTTPException(400, "Unsupported file extension")
    if len(wrapped_key) < 16:
        audit(db, u.id, "UPLOAD_DENIED", details={"filename": filename, "reason": "invalid_wrapped_key"})
        raise HTTPException(400, "Invalid wrapped document key")
    content = await file.read(MAX_BYTES + 1)
    if len(content) < 28:
        audit(db, u.id, "UPLOAD_DENIED", details={"filename": filename, "reason": "invalid_encrypted_payload"})
        raise HTTPException(400, "Invalid encrypted payload")
    if len(content) > MAX_BYTES:
        audit(db, u.id, "UPLOAD_DENIED", details={"filename": filename, "reason": "size_limit"})
        raise HTTPException(413, "Maximum upload size is 20 MB")
    did = str(uuid.uuid4()); stored = did + ".enc"
    (STORE / stored).write_bytes(content)
    now = datetime.now(timezone.utc)
    d = Document(id=did, owner_id=u.id, filename=filename, mime_type=(file.content_type or "application/octet-stream")[:150],
                 stored_name=stored, category=(category.strip() or "General")[:80], created_at=now, updated_at=now)
    db.add(d); db.commit()
    db.add(Permission(document_id=did, user_id=u.id, wrapped_key=wrapped_key, permission="owner")); db.commit()
    audit(db, u.id, "DOCUMENT_UPLOADED", did, {"filename": filename, "category": d.category, "ciphertext_bytes": len(content)})
    return {"id": did, "filename": d.filename, "category": d.category}


@app.get("/api/documents")
def documents(name: Optional[str] = None, owner: Optional[str] = None, category: Optional[str] = None,
              date_from: Optional[str] = None, date_to: Optional[str] = None,
              u: User = Depends(auth), db: Session = Depends(db_dep)):

    is_admin = getattr(u, "role", None) == "admin"

    if is_admin:
        stmt = select(Document)
    else:
        stmt = (
            select(Document, Permission)
            .join(Permission, Permission.document_id == Document.id)
            .where(Permission.user_id == u.id)
        )

    if name:
        stmt = stmt.where(Document.filename.ilike(f"%{name[:100]}%"))

    if category:
        stmt = stmt.where(Document.category.ilike(f"%{category[:80]}%"))

    if owner:
        owner_user = db.scalar(select(User).where(User.email == owner.lower()))
        if not owner_user:
            return []
        stmt = stmt.where(Document.owner_id == owner_user.id)

    try:
        if date_from:
            stmt = stmt.where(Document.created_at >= datetime.fromisoformat(date_from))
        if date_to:
            stmt = stmt.where(
                Document.created_at < datetime.fromisoformat(date_to) + timedelta(days=1)
            )
    except ValueError:
        raise HTTPException(400, "Dates must use YYYY-MM-DD format")

    if is_admin:
        rows = db.scalars(stmt.order_by(Document.created_at.desc())).all()

        return [
            {
                "id": d.id,
                "filename": d.filename,
                "mime_type": d.mime_type,
                "category": d.category,
                "owner": d.owner_id == u.id,
                "owner_id": d.owner_id,
                "permission": "admin",
                "created_at": d.created_at.isoformat(),
                "updated_at": d.updated_at.isoformat() if d.updated_at else None
            }
            for d in rows
        ]

    rows = db.execute(stmt.order_by(Document.created_at.desc())).all()

    return [
        {
            "id": d.id,
            "filename": d.filename,
            "mime_type": d.mime_type,
            "category": d.category,
            "owner": d.owner_id == u.id,
            "owner_id": d.owner_id,
            "permission": p.permission,
            "created_at": d.created_at.isoformat(),
            "updated_at": d.updated_at.isoformat() if d.updated_at else None
        }
        for d, p in rows
    ]

@app.get("/api/documents/{did}/key")
def get_key(did: str, u: User = Depends(auth), db: Session = Depends(db_dep)):
    d, p = require_document_access(db, did, u)
    audit(db, u.id, "DOCUMENT_KEY_GRANTED", did, {
    "filename": d.filename,
    "permission": p.permission
})
    return {"wrapped_key": p.wrapped_key, "filename": d.filename, "mime_type": d.mime_type}

@app.get("/api/documents/{did}/ciphertext")
def ciphertext(did: str, u: User = Depends(auth), db: Session = Depends(db_dep)):
    d, p = require_document_access(db, did, u)
    path = (STORE / d.stored_name).resolve()
    if not path.is_relative_to(STORE.resolve()) or not path.is_file():
        audit(db, u.id, "DOWNLOAD_FAILED", did, {"reason": "stored_file_missing"})
        raise HTTPException(404, "Document content not found")
    audit(db, u.id, "CIPHERTEXT_DOWNLOADED", did, {"filename": d.filename})
    return FileResponse(path, media_type="application/octet-stream", filename="encrypted-document.bin")

@app.post("/api/documents/{did}/share")
def share(did: str, x: Share, u: User = Depends(auth), db: Session = Depends(db_dep)):
    d = require_owner_or_admin(db, did, u)
    if x.permission not in {"read", "edit"}:
        audit(db, u.id, "PERMISSION_GRANT_DENIED", did, {"reason": "invalid_permission"})
        raise HTTPException(400, "Permission must be read or edit")
    r = db.scalar(select(User).where(User.email == x.email.lower()))
    if not r:
        audit(db, u.id, "PERMISSION_GRANT_DENIED", did, {"recipient_email": x.email.lower(), "reason": "recipient_not_registered"})
        raise HTTPException(404, "Recipient must register first")
    if r.id == d.owner_id: raise HTTPException(400, "Document owner already has full access")
    p = permission(db, did, r.id)
    if p:
        p.wrapped_key = x.wrapped_key; p.permission = x.permission
    else:
        db.add(Permission(document_id=did, user_id=r.id, wrapped_key=x.wrapped_key, permission=x.permission))
    db.commit(); audit(db, u.id, "PERMISSION_GRANTED", did, {"recipient_id": r.id, "permission": x.permission})
    return {"message": f"{x.permission.title()} access granted to {r.email}"}

@app.delete("/api/documents/{did}/permissions/{user_id}")
def revoke(did: str, user_id: int, u: User = Depends(auth), db: Session = Depends(db_dep)):
    require_owner_or_admin(db, did, u)
    p = permission(db, did, user_id)

    if not p or p.permission == "owner":
        audit(db, u.id, "PERMISSION_REVOKE_DENIED", did, {
            "recipient_id": user_id,
            "reason": "grant_not_found_or_owner"
        })
        raise HTTPException(404, "Active recipient permission not found")

    # Save the permission type before deleting it
    revoked_permission = p.permission

    db.delete(p)
    db.commit()

    audit(db, u.id, "PERMISSION_REVOKED", did, {
        "recipient_id": user_id,
        "permission": revoked_permission
    })

    return {"message": "Access revoked"}

@app.get("/api/documents/{did}/permissions")
def list_permissions(did: str, u: User = Depends(auth), db: Session = Depends(db_dep)):
    require_owner_or_admin(db, did, u)
    rows = db.execute(select(Permission, User).join(User, User.id == Permission.user_id).where(Permission.document_id == did)).all()
    return [{"user_id": user.id, "email": user.email, "name": user.name, "permission": p.permission} for p, user in rows]

@app.patch("/api/documents/{did}")
def update_document(did: str, x: DocumentUpdate, u: User = Depends(auth), db: Session = Depends(db_dep)):
    d, p = require_document_access(db, did, u, allowed=("owner", "edit"))
    if x.filename is not None: d.filename = Path(x.filename).name[:255]
    if x.category is not None: d.category = x.category.strip()[:80] or "General"
    d.updated_at = datetime.now(timezone.utc); db.commit()
    audit(db, u.id, "DOCUMENT_UPDATED", did, {"filename": d.filename, "category": d.category})
    return {"id": d.id, "filename": d.filename, "category": d.category}

@app.put("/api/documents/{did}/content")
async def replace_content(did: str, file: UploadFile = File(...), wrapped_key: Optional[str] = Form(None),
                         u: User = Depends(auth), db: Session = Depends(db_dep)):
    d, p = require_document_access(db, did, u, allowed=("owner", "edit"))
    content = await file.read(MAX_BYTES + 1)
    if len(content) < 28:
        audit(db, u.id, "DOCUMENT_UPDATE_DENIED", did, {"reason": "invalid_encrypted_payload"})
        raise HTTPException(400, "Invalid encrypted payload")
    if len(content) > MAX_BYTES:
        audit(db, u.id, "DOCUMENT_UPDATE_DENIED", did, {"reason": "size_limit"})
        raise HTTPException(413, "Maximum upload size is 20 MB")
    (STORE / d.stored_name).write_bytes(content)
    if wrapped_key and p.permission == "owner": p.wrapped_key = wrapped_key
    d.updated_at = datetime.now(timezone.utc); db.commit()
    audit(db, u.id, "DOCUMENT_CONTENT_REPLACED", did, {"ciphertext_bytes": len(content)})
    return {"message": "Encrypted document content updated"}

@app.delete("/api/documents/{did}")
def delete_document(did: str, u: User = Depends(auth), db: Session = Depends(db_dep)):
    d = require_owner_or_admin(db, did, u)
    filename = d.filename
    path = STORE / d.stored_name
    if path.exists(): path.unlink()
    db.query(Permission).filter(Permission.document_id == did).delete(synchronize_session=False)
    db.delete(d); db.commit()
    audit(db, u.id, "DOCUMENT_DELETED", did, {"filename": filename})
    return {"message": "Document deleted"}

@app.get("/api/audit")
def audit_list(u: User = Depends(auth), db: Session = Depends(db_dep)):
    if u.role == "admin":
        rows = db.scalars(select(Audit).order_by(Audit.id.desc()).limit(500)).all()
    else:
        permitted = select(Permission.document_id).where(Permission.user_id == u.id)
        rows = db.scalars(select(Audit).where((Audit.document_id.in_(permitted)) | ((Audit.document_id.is_(None)) & (Audit.actor_id == u.id))).order_by(Audit.id.desc()).limit(250)).all()
    return {"events": [{"id": e.id, "document_id": e.document_id, "actor_id": e.actor_id, "action": e.action,
                        "details": json.loads(e.details), "timestamp": e.timestamp.isoformat(), "event_hash": e.event_hash} for e in rows]}

@app.get("/api/admin/activity")
def admin_activity(u: User = Depends(require_admin), db: Session = Depends(db_dep)):
    rows = db.scalars(select(Audit).order_by(Audit.id.desc()).limit(500)).all()
    return {"events": [{"id": e.id, "document_id": e.document_id, "actor_id": e.actor_id, "action": e.action,
                        "details": json.loads(e.details), "timestamp": e.timestamp.isoformat()} for e in rows]}

@app.get("/api/admin/users")
def admin_users(u: User = Depends(require_admin), db: Session = Depends(db_dep)):
    rows = db.scalars(select(User).order_by(User.id)).all()
    return [{"id": x.id, "name": x.name, "email": x.email, "role": x.role} for x in rows]

@app.patch("/api/admin/users/{user_id}/role")
def set_role(
    user_id: int,
    x: RoleUpdate,
    u: User = Depends(require_admin),
    db: Session = Depends(db_dep)
):
    if x.role not in {"admin", "owner", "viewer"}:
        raise HTTPException(
            400,
            "Role must be admin, owner or viewer"
        )

    target = db.get(User, user_id)

    if not target:
        raise HTTPException(404, "User not found")

    # Protect the last remaining administrator
    if target.role == "admin" and x.role != "admin":
        admins = db.scalars(
            select(User).where(User.role == "admin")
        ).all()

        if len(admins) <= 1:
            raise HTTPException(
                400,
                "Cannot remove the last administrator. Promote another user to admin first."
            )

    old = target.role
    target.role = x.role
    db.commit()

    audit(
        db,
        u.id,
        "USER_ROLE_CHANGED",
        details={
            "target_user_id": user_id,
            "old_role": old,
            "new_role": x.role
        }
    )

    return {
        "message": "Role updated",
        "user_id": user_id,
        "role": x.role
    }
    if x.role not in {"admin", "owner", "viewer"}: raise HTTPException(400, "Role must be admin, owner or viewer")
    target = db.get(User, user_id)
    if not target: raise HTTPException(404, "User not found")
    old = target.role; target.role = x.role; db.commit()
    audit(db, u.id, "USER_ROLE_CHANGED", details={"target_user_id": user_id, "old_role": old, "new_role": x.role})
    return {"message": "Role updated", "user_id": user_id, "role": x.role}

@app.get("/api/audit/verify")
def verify(u: User = Depends(require_admin), db: Session = Depends(db_dep)):
    rows = db.scalars(select(Audit).order_by(Audit.id.asc())).all(); prev = "0" * 64
    for e in rows:
        ts = e.timestamp
        if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
        payload = {"document_id": e.document_id, "actor_id": e.actor_id, "action": e.action,
                   "details": json.loads(e.details), "timestamp": ts.isoformat(), "previous_hash": e.previous_hash}
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        if e.previous_hash != prev or digest != e.event_hash:
            return {"valid": False, "checked": e.id - 1, "failed_event": e.id}
        try: signer.public_key().verify(base64.b64decode(e.signature), digest.encode())
        except (InvalidSignature, ValueError): return {"valid": False, "checked": e.id - 1, "failed_event": e.id}
        prev = digest
    return {"valid": True, "checked": len(rows), "chain_head": prev}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)