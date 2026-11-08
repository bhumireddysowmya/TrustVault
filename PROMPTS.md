# TrustVault — AI Assistance Log

> Keep this file honest and project-specific. The entries below are draft summaries based on the AI-assisted work in this project conversation. Edit them to match the assistance you actually used, add the tool/model name if required by your programme, and do not claim AI-generated code was independently tested unless you tested it.

## Entry 1 — 2026-11-02 — Project setup and troubleshooting
**Purpose:** Resolve local Windows/Python setup issues and run the FastAPI project.

**AI assistance:** Guidance on creating a Python virtual environment, installing requirements, activating the environment in PowerShell and starting the application with Uvicorn.

**Human verification:** The application was started locally and the user checked the local website and API documentation.

## Entry 2 — 2026-11-02 — README and project documentation
**Purpose:** Prepare project documentation for handover and submission.

**AI assistance:** Helped structure a README with the project overview, technology stack, architecture, setup instructions, API overview, testing notes and limitations.

**Human verification:** The project owner should compare every statement with the final source and correct any feature descriptions that are not implemented.

## Entry 3 — 2026-11-02 — Security and access-control review
**Purpose:** Identify gaps between the current implementation and the stated document-security requirements.

**AI assistance:** Reviewed the supplied FastAPI source and discussed authentication, document permissions, denied access, audit logging, revocation and the need for automated negative tests.

**Human verification:** The project owner should run the documented tests against the final code and retain test output as evidence.

## Entry 4 — 2026-11-02 — Threat modelling and audit integrity
**Purpose:** Document likely attacks and the controls used by the prototype.

**AI assistance:** Helped organise a threat model covering unauthorised access, password attacks, encrypted-file exposure, key compromise, JWT theft, audit tampering, malicious uploads and denial of service.

**Human verification:** Confirm the mitigations and limitations against the final code and deployment configuration. Do not represent a design recommendation as an implemented control.

## Entry 5 — 2026-11-02 — Submission planning and API documentation
**Purpose:** Organise the Snovasys submission materials.

**AI assistance:** Helped outline the project folder, documentation deliverables, API endpoint reference and demo sequence.

**Human verification:** The project owner must verify the final API behaviour, role permissions, test results, repository contents and deployed URL before submission.

## Security-related AI use disclosure

AI assistance was used to help review the implementation and organise security documentation. AI suggestions are not proof of security. The project owner is responsible for validating the code, running tests, checking the deployed configuration and accurately disclosing unfinished work.

---

## Additional entries — 2026-11-05 code review and requirement alignment

> These entries describe work performed while revising the uploaded source snapshot. The ZIP did not contain a Git repository, so there are no genuine commit URLs available in this working copy. Create commits in your own repository and replace each `COMMIT LINK PENDING` note with the actual commit URL. Do not invent links.

### Entry 6 — 2026-11-05 — Role-based authorisation and document permission lifecycle
**Prompt / request summary:** Review the uploaded FastAPI project against the TrustVault company brief. Add distinct admin, owner and viewer account roles; per-document read/edit grants; owner-controlled grant and revoke; and enforce permissions on the backend rather than relying on hidden frontend buttons.

**AI output:** Updated the FastAPI models and routes to add role assignment, owner/read/edit permission values, owner/admin-only grant and revoke operations, server checks for document key/ciphertext access, and tests for cross-user access and revocation.

**Specific issue found and correction:** The first implementation direction risked treating an administrator role as automatic permission to decrypt every document. That would mix administrative visibility with document confidentiality. The revised design keeps admin activity/role administration separate from possession of a document's wrapped key; an admin does not automatically receive the key needed to decrypt every document. The local database filename was also kept as `securevault.db` so an existing prototype database can be upgraded instead of silently starting a new empty database.

**Human verification still required:** Run `pytest -q`; test grant and revoke against two real browser accounts; verify key and ciphertext routes both return 403 immediately after revocation; and test the deployed system. The current tool environment could not install dependencies because package network access was unavailable, so test execution is not claimed here.

**Fix commit:** COMMIT LINK PENDING — add the real commit URL after committing this change.

### Entry 7 — 2026-11-05 — Audit trail and administrator visibility
**Prompt / request summary:** Review audit requirements in the company brief. Make global audit activity and audit-chain verification administrator-only, preserve user-scoped audit visibility, and record denied security-sensitive operations without recording secrets.

**AI output:** Added admin-only activity and verification routes, role-change audit events, denied upload/access/share events, and documentation explaining the SHA-256 chain and Ed25519 signature model.

**Specific issue found and correction:** A hash chain and signature do not make a log absolutely immutable if an attacker compromises the application host and obtains the signing key. The documentation was corrected to describe the actual guarantee as tamper-evidence against database-only modification while the signing key remains secret. It now identifies external key management and independently controlled append-only anchoring as production improvements. The audit verifier is restricted to admins rather than being exposed to every authenticated user.

**Human verification still required:** Run the audit tests, alter a test audit row and confirm verification fails, inspect denied-event coverage for every protected route, and verify the deployed signing-key configuration. These checks have not yet been run in this environment.

**Fix commit:** COMMIT LINK PENDING — add the real commit URL after committing this change.

### Entry 8 — 2026-11-05 — Upload validation and honest security boundaries
**Prompt / request summary:** Compare upload validation and encryption claims with the actual browser-encrypted upload flow. Improve server-side checks without claiming the server can inspect plaintext that it never receives.

**AI output:** Added extension allowlisting, a minimum encrypted-payload size check, the existing 20 MB size limit, and clearer documentation of the limits of encrypted-file validation.

**Specific issue found and correction:** The server cannot verify the original file's magic bytes or scan the original plaintext for malware after the browser has encrypted it. The documentation was changed so it does not claim full MIME/content validation or malware scanning. A secure quarantine/scanning design remains a future improvement.

**Human verification still required:** Test allowed and rejected extensions, empty/short payloads, and the 20 MB boundary in a working local environment.

**Fix commit:** COMMIT LINK PENDING — add the real commit URL after committing this change.

## Reusable project context

The reusable context for this work is the company's TrustVault brief: server-side authorisation on every route; per-document named-user read/edit grants; immediate server-side revocation; audit evidence including refused attempts; three roles; executable negative tests; and honest disclosure of residual risks. Treat the company brief and actual source code as authoritative; do not use generated documentation as proof that a feature works.
