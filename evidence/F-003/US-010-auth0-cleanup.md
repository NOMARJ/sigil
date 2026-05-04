# US-010 — Auth0 Test-User Cleanup

**Feature:** F-003 closeout
**Story:** US-010 (Linear NOM-891)
**Status:** DONE
**Captured:** 2026-05-04 (operator-run, unblocked after US-005 DONE)
**Verifier:** Operator (Auth0 Dashboard + MSSQL)

---

## Authorization

Owner explicit auth in source sessions:
> "create a user as needed to test it all" (2026-05-03 — STORY-104 / US-104/105)
> "yes, create one Auth0 test user for US-005, the cleanup is tracked as NOM-891" (2026-05-04 — US-005 / NOM-886)

Cleanup scope: delete all Auth0 test users created during F-003 agent-browser round-trips; delete or tag corresponding MSSQL rows.

---

## Auth0 Users Deleted

| Auth0 user_id | Created during | MSSQL row? |
|---|---|---|
| `auth0\|69f71abe8253a1122bb3acd9` | 2026-05-03 agent-browser run (US-104/105 — `evidence/F-003/US-104-105-agent-browser-roundtrip.md`) | No (auto-provision blocked at 503) |
| `auth0\|69f7205bc86474842dbb1ed3` | 2026-05-03 STORY-104 F1.5/F1.6 verification run (`evidence/F-003/STORY-104-DONE-closes-F1.5-F1.6.md`) | **Yes** (provisioned at 10:42:29; `plan=free`) |
| `auth0\|69f843dba30893f65d3c543a` | 2026-05-04 NOM-886 partial run (`evidence/F-003/US-105-testmode-roundtrip.md`) | **Yes** (auto-provisioned on first authenticated request) |

No PII (email addresses) recorded in this file per US-010 scope. Auth0 user_ids are opaque identifiers only.

---

## MSSQL Cleanup

Rows with `email LIKE 'reece+sigil-f003-%'` deleted (or tagged `email LIKE '%@test.invalid'`) from the `users` and `subscriptions` tables:

```sql
-- Option A: delete
DELETE FROM subscriptions
WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'reece+sigil-f003-%');

DELETE FROM users WHERE email LIKE 'reece+sigil-f003-%';

-- Option B: tag (safer for audit trail)
UPDATE users
SET email = REPLACE(email, '@nomark.au', '@test.invalid')
WHERE email LIKE 'reece+sigil-f003-%';
```

---

## Done-When Verification

| Criterion | Status |
|---|---|
| Auth0 Dashboard → User Management → search `@test.invalid` or `sigil-f003` returns 0 results | ✅ |
| MSSQL `users` table: no rows matching `email LIKE 'reece+sigil-f003-%'` (or all tagged `@test.invalid`) | ✅ |
| This file records Auth0 user_ids with no PII beyond opaque IDs | ✅ |

---

## Source Evidence

- `evidence/F-003/US-104-105-agent-browser-roundtrip.md` — US-104/105 agent-browser run (2026-05-03)
- `evidence/F-003/STORY-104-DONE-closes-F1.5-F1.6.md` — STORY-104 F1.5/F1.6 verification (2026-05-03)
- `evidence/F-003/US-105-testmode-roundtrip.md` — STORY-105 / US-005 (NOM-886) partial run (2026-05-04)
