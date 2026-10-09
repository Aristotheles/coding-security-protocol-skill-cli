# Coding Security Protocol — M2 dependency blocker

Date: 2026-10-09 · Reviewer: Codex · Status: approved by user's subsequent “devam”; MVP §26/§28 updated

## Observed evidence

- MVP.md §26 requires OPEN → duplicate same ID → verified CLOSED → REOPENED
  before permitting M3.
- SECURITY_AGENT.md §6 permits closure only after tests, successful relevant
  rescan, runtime verification where applicable, applicable policy checks and
  required secret rotation confirmation.
- M3 implements policy evaluation; M4 implements deterministic verification.
- Actual `security verify --json` and `security gate --json` both returned
  CONTRACT_ERROR, exit 50, `command not implemented in M1`.
- Git status could not run: the folder has no Git repository.

M2 cannot honestly pass its complete acceptance scenario in isolation under this
ordering. Producing fake verification or treating an unimplemented gate as PASS
would violate the security invariants. Implementing M3/M4 in this turn would exceed
the active milestone. No M2 production code or protected contract was changed.

## Smallest proposed edit — MVP.md only

This is a milestone-dependency correction, not a component or storage redesign.
Human approval is required by AGENTS.md §25 before editing the frozen plan.

1. Replace M2 acceptance with these foundation checks:
   - Real scanner evidence normalizes and creates SEC-0001 OPEN.
   - Repeated unchanged evidence retains SEC-0001 without duplicate SEC-0002.
   - Canonical JSON validates; SQLite can rebuild from it, with JSON precedence.
   - A test-only seeded CLOSED canonical record returns as REOPENED with its
     existing SEC ID, regression=true and appended history when its fingerprint
     reappears. This fixture does not claim a real production closure occurred.
   - Without actual deterministic verification and applicable policy evaluation,
     production closure fails closed; absence on a scan alone cannot close a finding.
2. Replace M2 stop condition with: do not start M3 until the above foundation tests
   pass. M2 must not mark any live finding CLOSED.
3. Add the existing full OPEN → dedup → verified CLOSED → REOPENED scenario to
   M4 acceptance, after real M3 policy and M4 verification exist. Retain its status
   as a release-blocking MVP acceptance test; M5 cannot start until it passes.

## Impact

- Proposed contract edit: MVP.md §26 and §28 only.
- SECURITY_AGENT.md, policy definitions, lifecycle states, schema, CLI names,
  canonical JSON/SQLite source-of-truth order and architecture remain unchanged.
- No dependency, migration, data rewrite, tool installation or scope expansion.
- M0/M1 remain complete; M2 remains unchecked.
- Only this proposal and automatic local memory/handoff records were written.

Resolution: the user replied “devam” after receiving this exact proposal. Only the
proposed milestone acceptance correction was applied; M2 foundation implementation
is authorized. Earlier observations above are retained as historical context.
