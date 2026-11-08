# TrustVault — Threat Model

**Scope:** This document describes the current project code and known residual risks. It is not a certification or a substitute for a deployed-system penetration test. Re-run `pytest -q` and manually test the deployed system before submission.

## Architecture and security boundary

The browser encrypts file bytes with AES-256-GCM and wraps the random document key for each recipient using RSA-OAEP. The FastAPI server stores ciphertext and metadata. SQLite stores users, document ownership, per-document grants and audit events. Every key/ciphertext request checks the current permission record on the server.

## Roles and permission model

- `admin`: can inspect global activity, verify the audit chain and administer account roles. Admin does not automatically receive every document's wrapped key.
- `owner`: owns uploaded documents; can edit/delete their documents, grant read/edit access and revoke recipients.
- `viewer`: cannot upload, share, edit or delete; can read documents only when explicitly granted.
- Document grants: `owner`, `read`, `edit`. `edit` permits metadata/content updates but not sharing, revocation or deletion.

The first administrator is bootstrapped by setting `TRUSTVAULT_ADMIN_EMAIL` before registering that email. Other role changes require an authenticated administrator.

## Threat register

| ID | Threat / attack path | Current mitigation | Residual risk / accepted limitation | Test evidence |
|---|---|---|---|---|
| T1 | User changes a document ID to access another user's file (IDOR). | Listing, key and ciphertext routes require a matching document permission. | Every new endpoint must repeat the same server-side check; do not rely on UI hiding. | `test_ungranted_user_cannot_list_open_or_download_document` |
| T2 | Recipient keeps using a link/token after owner revokes access. | Permission is queried from the database for each key and ciphertext request; revoke deletes the grant. | Cannot claw back plaintext or keys copied before revocation. | `test_grant_then_revoke_removes_access_immediately` |
| T3 | Viewer attempts upload, share, edit or delete. | Role and document permission checks are performed by backend routes. | Role assignment/bootstrap credentials must be protected. | `test_viewer_cannot_upload_or_share`; `test_viewer_cannot_edit_or_delete_another_users_document` |
| T4 | Ordinary user attempts to read global audit activity or verify all events. | Global activity and verification endpoints require `admin`; denied attempts are recorded as `ADMIN_ACTION_DENIED`. | Admin account compromise exposes global metadata. | `test_non_admin_cannot_read_global_audit_or_verify_chain` |
| T5 | Database-only attacker edits/deletes audit records. | Events include previous hash, SHA-256 event hash and Ed25519 signature. | The local fallback signing key is stored under the data directory. A full host compromise including the signing key can undermine trust. Use an external secrets manager/HSM and remote append-only log for stronger assurance. | `test_admin_can_review_activity_and_verify_audit` checks a valid chain; `test_audit_tampering_is_detected` checks that altered event details fail verification. |
| T6 | Attacker guesses passwords or performs credential stuffing. | bcrypt password hashing and JWT expiry. | No MFA, rate limiting, lockout or breached-password screening is implemented. | Manual security review required. |
| T7 | Attacker steals or forges a bearer token. | HS256 signature validation and token expiration. | JWT secret must be strong and private; no token revocation/refresh mechanism or secure cookie mode is implemented. XSS or endpoint compromise can steal a browser-held token. | Add token expiry/secret-rotation integration tests. |
| T8 | Attacker downloads encrypted files directly from the storage folder or uses path traversal. | Storage uses generated UUID filenames; there is no public static mount for `data/`; API access requires permission. | Host filesystem permissions and deployment configuration remain critical. | Inspect deployed static mounts and filesystem permissions. |
| T9 | User uploads oversized or misleading files. | 20 MB cap, allowed filename extensions, minimum encrypted-payload length and generated storage name. | Server cannot inspect original magic bytes or scan plaintext because encryption happens in the browser. No malware scanner, quota or decompression-bomb protection. | Add boundary tests for max size and invalid payload. |
| T10 | Recipient changes a read grant into edit or owner. | Only owner/admin can call grant/revoke routes; permission value is validated. | Admin credentials are high impact; no approval workflow for role elevation. | Add tests for recipient grant escalation. |
| T11 | Attacker enumerates registered emails/public keys. | Lookup requires authentication. | Any authenticated user can currently query an email; add privacy-preserving invitations or rate limiting if required. | Manual review. |
| T12 | Concurrent writes produce inconsistent audit-chain ordering. | Each event links to the last stored event and is signed. | The simple SQLite implementation does not use a dedicated serialized append service or external anchoring; concurrent production writes need stronger transaction/locking design. | Load/concurrency tests not yet included. |
| T13 | Attacker changes document filename/category or replaces content without permission. | Metadata and content update routes require owner/edit permission. | Content replacement and metadata editing need full role/permission integration tests. | Add endpoint-specific negative tests. |
| T14 | Revoked user has already saved a plaintext copy. | Server blocks all future key/ciphertext requests after revocation. | This cannot technically delete a copy already downloaded to an endpoint. This is an explicit product limitation, not a control we claim to solve. | Demonstrate post-revocation API denial and disclose cached-copy limitation. |

## Audit evidence model

The audit record includes actor, action, document ID where relevant, details, timestamp, previous event hash, event hash and Ed25519 signature. A verifier recomputes the chain and verifies signatures. This detects ordinary database-only alteration while the signing key remains secret. It does not prove that a compromised server did not omit an event before writing it, nor protect against a host attacker who controls the signing key. Stronger evidence requires an independently controlled append-only sink or periodic external anchoring.

Denied document key/ciphertext requests and failed logins are logged. Continue to add audit events for new denied operations and verify them in tests. Do not log passwords, bearer tokens, plaintext documents or encryption keys.

## File validation boundary

The server sees ciphertext, not the original file. It can enforce size, extension and basic encrypted-payload shape, but cannot honestly claim server-side MIME sniffing, malware scanning or plaintext content validation. A production system should use a quarantine process and carefully designed client-side or trusted scanning workflow without silently weakening end-to-end confidentiality.

## Deployment assumptions and accepted gaps

- HTTPS is terminated correctly by the deployment platform.
- JWT secret and audit signing key are protected outside source control.
- Data volume and SQLite file are private and backed up.
- Browser and user endpoint are not compromised.
- No real confidential corporate data is used in this prototype.
- Revocation prevents future server access but cannot erase previously downloaded copies.
- MFA, rate limiting, remote audit anchoring, malware scanning, concurrency hardening and independent penetration testing remain future work.
