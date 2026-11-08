# TrustVault – Secure Document Sharing with a Real Audit Trail

## 1. Project Overview

TrustVault is a secure document-sharing application that allows users to upload, access, share, and manage documents with permission-based access control.

It uses encryption to protect documents and maintains an audit trail to record important user activities.

## 2. Technologies Used

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, FastAPI
- **Database:** SQLite
- **ORM:** SQLAlchemy
- **Security:** AES-256-GCM, RSA-OAEP, PBKDF2
- **Testing:** Pytest, HTTPX

## 3. Main Features

- User registration and login.
- Secure document upload and access.
- Browser-side document encryption.
- Permission-based document sharing.
- View, edit, and revoke document permissions.
- Document deletion.
- Audit trail for tracking user activities.
- Audit integrity verification using hash chains and digital signatures.
- Admin panel for user and activity management.
- Protection against removing the last administrator.


## 4. Installation and Setup

### Prerequisites

- Python installed on your system.
- Visual Studio Code or another code editor.

### Step 1: Open the project folder

Open the TrustVault project folder in VS Code and open its terminal.

### Step 2: Create a virtual environment

```bash
python -m venv venv
```

### Step 3: Activate the virtual environment

For Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### Step 4: Install dependencies

```bash
pip install -r requirements.txt
```

## 5. Database Setup

TrustVault uses SQLite. On first application startup, SQLAlchemy creates the schema automatically.

To initialize or upgrade the database explicitly from the repository root:

```bash
python scripts/init_db.py
```

`schema.sql` is the fresh-install schema reference. The application keeps the earlier prototype database filename `data/securevault.db` and adds the `users.role`, `documents.category`, and `documents.updated_at` columns when upgrading that earlier schema.

The migration also adds a unique document/user permission index. If an old database contains duplicate grants, reconcile those rows before applying the unique index.

Keep the SQLite database, encrypted document directory, and audit signing key private. Back them up together. Never commit `data/` to the public repository.

To promote an already-registered first administrator during a local upgrade, set `TRUSTVAULT_ADMIN_EMAIL` and run:

```bash
python scripts/promote_admin.py
```

This is an operator bootstrap script, not a public API.

## 6. Run the Application

From the project root, with the virtual environment activated, run:

```bash
python main.py
```

Open the application in your browser:

```text
http://127.0.0.1:8000
```

## 7. Run Security Tests

To execute the automated tests, run:

```bash
pytest -q
```

## 8. Security Overview

- AES-256-GCM is used for document encryption.
- RSA-OAEP is used for encryption key wrapping.
- PBKDF2 is used to derive the key protecting the private-key bundle.
- Passwords are securely hashed.
- Access to documents is controlled through user permissions.
- Audit records support integrity verification through hash chaining and signatures.

## 9. Important Notes

- Do not share passwords, private keys, or signing keys.
- Do not expose the database or encrypted document storage publicly.
- Keep backups of the database, encrypted documents, and audit signing key together.
- Use a trusted environment when managing administrator accounts.
