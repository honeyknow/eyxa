# Eyxa - Accepted Scope Limitations

This document records design decisions that were deliberately scoped out for
the current release. They are not bugs or oversights; they are accepted
limitations with the rationale noted.

---

## 1. Enrollment token has no expiry or rotation

**Decision date:** 2026-07-27  
**Approved by:** Project lead (Phase 4 approval)

The `users.enroll_token` value is generated once when a user account is
created. It has no expiry date and there is no automatic rotation mechanism.

**Accepted because:**
- Eyxa targets a maximum of 3 enrolled endpoints per user (locked capacity
  decision). The token is used only once per endpoint (on first run). It is
  not presented on every ingest request; that uses the per-endpoint
  `agent_token` instead.
- The enroll_token is transmitted over HTTPS only (TLS enforced except the
  explicit `SkipTlsVerify` development registry flag).
- The threat model for Phase 1 does not include a compromised enrollment
  token scenario.

**Future hardening (outside current scope):**
- Add an `enroll_token_expires_at` column to `users`.
- Add a dashboard action to regenerate the token (invalidating the old one).
- Log enrollment attempts (success and failure) to an `audit_log` table.

---

## 2. SkipTlsVerify must be disabled before Phase 9

See `.agents/AGENTS.md` Rule 8 hardening note.


#ignore 
REG DELETE "HKLM\SOFTWARE\Eyxa" /v EnrollToken   /f
REG DELETE "HKLM\SOFTWARE\Eyxa" /v SkipTlsVerify /f
REM Keep BackendUrl - Phase 5 will need it
DEL /F "C:\ProgramData\Eyxa\agent-token.bin" 2>nul
