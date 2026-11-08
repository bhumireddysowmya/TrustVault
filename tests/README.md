# TrustVault automated security tests

Run from the repository root:

```bash
pip install -r requirements.txt
pytest -q
```

`test_security.py` exercises cross-user document isolation, denied-access audit events,
permission grant and immediate revocation, viewer restrictions, admin-only audit access,
and audit-chain verification. These are API-level tests using an isolated in-memory
SQLite database; they do not replace a deployed-system penetration test.
