# TrustVault submission notes

## Current package state

This package has been updated from the earlier SecureVault-named prototype to use the TrustVault project name. The backend now includes account roles, document-level read/edit permissions, permission revocation, document metadata search/update/delete, admin activity endpoints and a pytest security suite.

## Before submission — mandatory checks

- [ ] Install dependencies in a clean virtual environment and run `pytest -q`.
- [ ] Run the application from a clean clone and verify `/`, `/docs`, registration, login, upload, share, revoke, search, edit and delete.
- [ ] Configure `TRUSTVAULT_JWT_SECRET`, `TRUSTVAULT_ADMIN_EMAIL`, persistent `TRUSTVAULT_DATA_DIR`, and an externally protected `TRUSTVAULT_AUDIT_PRIVATE_KEY` for deployment.
- [ ] Create separate demo accounts for admin, owner and viewer. Never publish personal credentials or private keys.
- [ ] Verify all routes against the live deployment, especially after revocation.
- [ ] Add the real public Git repository URL, live URL and demo video link.
- [ ] Add genuine commit history across the work period.
- [ ] Update `PROMPTS.md` with actual prompts, specific incorrect AI outputs, human corrections and real commit links. Do not invent commit IDs or claim AI output was tested unless it was.
- [ ] Review the presentation and record a five-minute demo.

## Known limitations to disclose

- Browser-side encryption means the server cannot inspect original file content for magic-byte validation or malware scanning.
- Revocation blocks future server requests but cannot erase a previously downloaded plaintext copy.
- Audit signing-key protection and external append-only anchoring need production-grade infrastructure.
- MFA, rate limiting, token revocation, malware scanning, load/concurrency testing and independent penetration testing are not complete.
- The automated tests are API-level tests on an isolated in-memory SQLite database, not a substitute for testing the deployed service.

Do not describe the project as production-ready or claim all company requirements have been independently verified until the checklist above has been completed.
