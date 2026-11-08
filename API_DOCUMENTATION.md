# TrustVault API Documentation

Base URL (local): `http://127.0.0.1:8000`. All protected routes require `Authorization: Bearer <JWT>` unless stated otherwise. The API docs are also available at `/docs`.

## Roles

- **admin**: global audit/activity, audit verification and role administration; can perform owner-level administrative document operations. Admin status alone does not provide a document decryption key.
- **owner**: owns uploaded documents and can manage their grants and documents.
- **viewer**: cannot upload, share, edit or delete; can read only explicitly granted documents.

Document permissions are `owner`, `read`, and `edit`. `edit` allows metadata/content changes. Only the owner or admin can grant/revoke access or delete a document.

## Authentication

| Method | Endpoint | Allowed caller | Purpose |
|---|---|---|---|
| POST | `/api/register` | Public | Register; assigns `owner`, except configured `TRUSTVAULT_ADMIN_EMAIL` receives `admin`. |
| POST | `/api/login` | Public | Authenticate and receive JWT + own key bundle. |
| GET | `/api/me` | Any authenticated user | Return own profile and role. |

Register body: `{ "name": "Example", "email": "user@example.com", "password": "at-least-10-characters", "public_key": "PEM public key", "private_key_bundle": "encrypted bundle" }`.

Login body: `{ "email": "user@example.com", "password": "..." }`.

## Recipients and documents

| Method | Endpoint | Allowed caller | Purpose |
|---|---|---|---|
| GET | `/api/lookup?email=...` | Authenticated | Look up a registered recipient's public key. |
| POST | `/api/documents` | Owner or admin | Upload encrypted file, wrapped key and optional category. Viewer is denied. |
| GET | `/api/documents` | Authenticated | List only documents for which the caller has a permission record. |
| GET | `/api/documents/{id}/key` | Granted user (`owner`, `read`, `edit`) | Retrieve caller's wrapped key. Permission is checked on every request. |
| GET | `/api/documents/{id}/ciphertext` | Granted user (`owner`, `read`, `edit`) | Download encrypted bytes. Permission is checked on every request. |
| POST | `/api/documents/{id}/share` | Document owner or admin | Grant/update a named user's `read` or `edit` access. Body: `{ "email": "recipient@example.com", "wrapped_key": "...", "permission": "read" }`. |
| GET | `/api/documents/{id}/permissions` | Document owner or admin | List current grants. |
| DELETE | `/api/documents/{id}/permissions/{user_id}` | Document owner or admin | Revoke a recipient's grant. Subsequent key and ciphertext requests are denied. |
| PATCH | `/api/documents/{id}` | Document owner, admin, or recipient with `edit` | Update filename/category metadata. |
| PUT | `/api/documents/{id}/content` | Document owner, admin, or recipient with `edit` | Replace encrypted content. Multipart fields: `file`; optional `wrapped_key`. |
| DELETE | `/api/documents/{id}` | Document owner or admin | Delete encrypted server copy, document metadata and grants. Audit event is retained. |

Upload uses multipart form data: `file`, `wrapped_key`, and optional `category`. Maximum size is 20 MB. The backend checks allowed filename extensions and minimum encrypted-payload length; it cannot inspect plaintext file signatures because the file is encrypted in the browser.

### Document search

`GET /api/documents` accepts optional query parameters:

- `name`: filename substring
- `owner`: owner email
- `category`: category substring
- `date_from`: inclusive `YYYY-MM-DD`
- `date_to`: inclusive `YYYY-MM-DD`

Search results are restricted to the caller's existing document grants; search is not a way to discover unshared documents.

## Audit and administration

| Method | Endpoint | Allowed caller | Purpose |
|---|---|---|---|
| GET | `/api/audit` | Authenticated | Own account events and events for currently accessible documents; admin receives global events. |
| GET | `/api/audit/verify` | Admin only | Verify event hash chain and Ed25519 signatures. |
| GET | `/api/admin/activity` | Admin only | View recent global audit activity. |
| GET | `/api/admin/users` | Admin only | List account IDs, names, emails and roles (no password/key material). |
| PATCH | `/api/admin/users/{user_id}/role` | Admin only | Set role to `admin`, `owner` or `viewer`. Body: `{ "role": "viewer" }`. |

Security-relevant actions are written to the audit log, including denied document access, denied admin actions, failed login, upload denial, grant/revoke, document changes/deletion and role changes. Audit coverage should be rechecked whenever new endpoints are added.

## Status codes

- `200`: request succeeded
- `400`: invalid input or unsupported upload
- `401`: missing/invalid/expired token or failed login
- `403`: authenticated user lacks the required role/document grant
- `404`: target user/document/grant not found
- `409`: email already registered
- `413`: upload exceeds 20 MB

## Security notes

The server enforces permission checks for document key and ciphertext retrieval on every request. Revocation removes the permission row, so future requests are denied even when the recipient still holds a valid JWT. Revocation cannot erase plaintext or key material already copied by the recipient. Do not expose the encrypted storage directory as a public static path.
