# TrustVault

**Secure document sharing with per-document permissions and a tamper-evident audit trail.**

TrustVault is a FastAPI + SQLite document-sharing prototype. The browser encrypts file contents before upload; the server stores encrypted bytes and enforces authorization on every document API operation. The project is intended for evaluation and learning, not for storing real confidential company documents until the deployment hardening items in this README and `THREATS.md` are completed.

## Current feature set

- Registration and login with bcrypt password hashing and expiring JWT bearer tokens.
- Three account roles: `admin`, `owner`, and `viewer`.
- Browser-side AES-256-GCM file encryption, RSA-OAEP key wrapping, and password-derived protection for the user's private-key bundle.
- Per-document `owner`, `read`, and `edit` permission records.
- Grant and revoke named-user access; each key and ciphertext request re-checks the current permission record.
- Upload, metadata editing, encrypted-content replacement API, delete, and search by filename, owner email, category, and date.
- Admin-only global activity view, user-role management, and audit-chain verification.
- Hash-linked audit events signed with Ed25519.
- Pytest security tests for cross-user isolation, revocation, viewer restrictions, admin-only endpoints, and audit verification.

## Role and permission model

| Account role | Capabilities |
|---|---|
| `admin` | View global activity, verify the audit chain, manage account roles, and administer grants/revocations or delete documents. Admin status does not automatically grant document decryption keys or general edit access. |
| `owner` | Register and upload documents; manage documents they own; grant read/edit access and revoke recipients. |
| `viewer` | Cannot upload, share, edit or delete. Can read only documents for which an owner has granted a `read` permission. |

Document-level permissions are separate from account roles. The owner has the `owner` grant; recipients receive `read` or `edit`. `edit` permits metadata/content updates but not sharing, revocation, or deletion. The backend checks these grants; hiding a button in the browser is not treated as security.

### First administrator

Set `TRUSTVAULT_ADMIN_EMAIL` before registering the intended administrator account. Registration of that exact email assigns the `admin` role. Do not allow public self-service registration to assign arbitrary roles. If that email already has an account in an upgraded database, run `python scripts/promote_admin.py` from a trusted local shell with `TRUSTVAULT_ADMIN_EMAIL` set. After the admin signs in, use `PATCH /api/admin/users/{user_id}/role` to set other registered users to `owner` or `viewer`.

## Technology

- Frontend: HTML, CSS, JavaScript, Web Crypto API
- Backend: Python, FastAPI, Uvicorn
- Database: SQLite, SQLAlchemy
- Authentication: bcrypt password hashes, JWT (HS256)
- File encryption: AES-256-GCM in the browser
- Key wrapping: RSA-OAEP in the browser
- Audit integrity: SHA-256 hash chain and Ed25519 signatures

## Project structure

```text
TrustVault_Submission/
├── main.py
├── requirements.txt
├── README.md
├── API_DOCUMENTATION.md
├── THREATS.md
├── PROMPTS.md
├── SUBMISSION_NOTES.md
├── static/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── tests/
│   ├── README.md
│   └── test_security.py
├── database/
│   ├── README.md
│   └── schema.sql
├── scripts/
│   ├── init_db.py
│   └── promote_admin.py
├── .env.example
├── presentation/
└── data/                 # created automatically; do not commit
    ├── trustvault.db
    ├── encrypted/
    └── audit-signing-key.pem
```

## Run locally on Windows

Open Command Prompt in the project directory.

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

Set a local development JWT secret for the current terminal session (use a different, random value for each deployment):

```bat
set TRUSTVAULT_JWT_SECRET=replace-with-a-long-random-secret-for-local-testing
```

For the first administrator account, set its email before registering:

```bat
set TRUSTVAULT_ADMIN_EMAIL=admin@example.com
```

Start the application:

```bat
uvicorn main:app --reload
```

Open:

- Website: http://127.0.0.1:8000
- Interactive API documentation: http://127.0.0.1:8000/docs

The SQLite database, encrypted files, and local audit signing key are created under `data/` on first run. You can also run `python scripts/init_db.py` to create/upgrade the database explicitly; see `database/` for the schema reference. The app includes a small SQLite migration for the earlier SecureVault database schema. Back up the database, encrypted directory, and signing key together; losing the signing key prevents verification of signatures made by that key.

## Clean-clone setup and deployment notes

1. Clone the repository and create/activate a virtual environment.
2. Install `requirements.txt`.
3. Configure a strong `TRUSTVAULT_JWT_SECRET` in the host's secret manager/environment.
4. Configure `TRUSTVAULT_ADMIN_EMAIL` before registering the initial administrator.
5. Set `APP_ENV=production` and `TRUSTVAULT_DATA_DIR` to a persistent writable volume.
6. Set `TRUSTVAULT_AUDIT_PRIVATE_KEY` to a PEM signing-key file stored outside the web root and protected with restrictive filesystem permissions. Production startup refuses to run without this existing key file; a local key is generated under the data directory only in development.
7. Run `uvicorn main:app --host 0.0.0.0 --port $PORT` (adapt the port syntax to the host).
8. Put the app behind HTTPS. Do not expose the SQLite file, `data/`, `.env`, private keys, or encrypted storage as static web paths.
9. Create seed accounts through registration. Register the admin using the configured admin email, register owner/viewer accounts, and have the admin assign the viewer role.
10. Verify the live URL, all role credentials, seeded data and tests before submitting. Do not put real user passwords or private keys in a public README.

**Production warning:** The application still needs deployment-specific hardening such as HTTPS enforcement, rate limiting, MFA, secure cookie/session strategy, database concurrency planning, backups, monitoring, and external audit anchoring. The development fallback secret and local signing-key generation must not be relied on for a public production deployment.

## Automated tests

```bash
python -m pip install -r requirements.txt
pytest -q
```

The tests use an isolated in-memory SQLite database. They verify that an ungranted user cannot list/open/download another user's document, that revocation immediately blocks subsequent key and ciphertext requests, that viewers cannot upload/share, that ordinary users cannot access global admin audit endpoints, and that the audit chain verifies. Passing these tests is not equivalent to a penetration test of the deployed service.

## Security architecture and limitations

- File contents are encrypted in the browser before upload. The server can still see metadata such as filename, category, user IDs, file size and timestamps.
- The server validates the filename extension, encrypted payload minimum size and upload size. Because content is encrypted before it reaches the server, the server cannot reliably inspect the original file signature or scan plaintext for malware. A production design needs a safe client-side scanning workflow or a carefully designed quarantine/decryption boundary.
- Revocation deletes the recipient's permission record. Subsequent requests to the server fail immediately. It cannot erase plaintext or keys a recipient downloaded or copied before revocation.
- Audit events are hash-linked and signed. This is tamper-evident against database-only modification when the signing key remains secret. A full server compromise that also obtains the signing key can undermine the evidence; use external key management and remote append-only anchoring for stronger assurance.
- The browser's decrypted content and private key are exposed to the user's endpoint while in use. Endpoint compromise is outside the protection provided by server-side access checks.
- Do not use this prototype for real confidential documents without independent security review.

## Required submission evidence still to complete

- Public repository with meaningful commits over the development period.
- Deployed live URL and safe demo credentials for all three roles.
- Genuine `PROMPTS.md` entries with dated prompts, specific AI errors, fixes, and actual commit URLs.
- Five-minute demo video.
- Final review of `THREATS.md`, database setup, deployment, and live-system negative tests.

See `API_DOCUMENTATION.md`, `THREATS.md`, `PROMPTS.md`, and `SUBMISSION_NOTES.md` for details.
