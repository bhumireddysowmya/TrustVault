-- TrustVault fresh-install SQLite schema.
-- The application also creates these tables through SQLAlchemy on first startup.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    private_key_bundle TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'owner'
);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

CREATE TABLE IF NOT EXISTS documents (
    id VARCHAR(36) PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(150) NOT NULL,
    stored_name VARCHAR(100) NOT NULL UNIQUE,
    category VARCHAR(80) NOT NULL DEFAULT 'General',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_documents_owner_id ON documents(owner_id);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY,
    document_id VARCHAR(36) NOT NULL REFERENCES documents(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    wrapped_key TEXT NOT NULL,
    permission VARCHAR(20) NOT NULL DEFAULT 'read'
);
CREATE INDEX IF NOT EXISTS ix_permissions_document_id ON permissions(document_id);
CREATE INDEX IF NOT EXISTS ix_permissions_user_id ON permissions(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_permission_document_user ON permissions(document_id, user_id);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    document_id VARCHAR(36),
    actor_id INTEGER,
    action VARCHAR(60) NOT NULL,
    details TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    event_hash VARCHAR(64) NOT NULL UNIQUE,
    signature TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_document_id ON audit(document_id);
