# Coding Security Protocol — M3 verification

2026-10-09 13:29 Europe/Istanbul · Codex · Mode: FEATURE · Overall: VERIFIED WITH WARNINGS

## Scope and result

Only M3 — Policy Engine. User's “devam” after milestone status authorized the first
unchecked milestone M3. POL-001..007 are evaluated from the existing unchanged policy
YAML. security gate emits decisions and writes durable local audit/outbox reports;
SQLite derives gate_runs/escalation_state from those reports with FK/transactions.
No schema migration, new package, policy weakening, AI adapter, CI or M4 collector.

## Commands and actual results

- New policy unit suite: 22 tests OK after first fixes (8.777 seconds).
- Final python -m unittest discover -s tests -v: **107 tests OK**, exit 0,
  **86.215 seconds**. Includes 27 policy unit and 4 gate CLI acceptance tests,
  existing real Semgrep/Trivy acceptance and M2 integration.
- Real security gate --event release --json: **BLOCK/10**, POL-005 triggered by
  deliberate fake-secret fixture findings SEC-0001/SEC-0003. Missing input/evidence
  is also explicitly reported; BLOCK precedence is fail-closed, not verification PASS.
- Real security doctor --json: **PASS/0**, Python 3.14.5.
- Real security verify --json: **CONTRACT_ERROR/50**, still unimplemented M4.
- Exact output: `.agent/m3-command-results.json`.
- compileall: exit 0. AST/whitespace/no-shell: 23 Python files PASS.
- git diff --check: PASS. High-confidence credential/private-key signatures in
  reviewed Python files: no matches, not a comprehensive secret/security audit.
- Actual SQLite: one BLOCK gate_run, foreign_keys ON, integrity ok, FK check empty.
- Protected policy/config/schema/DB-schema/invariants and canonical finding diff:
  empty. Canonical finding states were not changed by gate.

## M3 acceptance

- [x] Open CRITICAL + release BLOCK; merge scope tested; VERIFYING not a bypass.
- [x] Lockfile change + new dependency REVIEW_REQUIRED; enabled SBOM diff required.
- [x] AI finding still present on validated rescan BLOCK (POL-002).
- [x] Configured AI coverage drop BLOCK (POL-004); invalid metrics rejected.
- [x] Open hardcoded secret BLOCK on merge/release; required rotation confirmation
  checked for seeded historical CLOSED secrets; playbook reference emitted.
- [x] Root/nested/custom security-critical path REVIEW_REQUIRED.
- [x] HIGH 29/30/59/60/89/90-day boundaries tested; 30 warning/report target,
  60 owner/team, 90 owner/team/security_lead. Warning alone does not hard-block.
- [x] Target status QUEUED, not attempted/delivered. Same stage/target is not queued
  repeatedly, across concurrent actual CLI gates and index rebuilds.
- [x] Invalid/missing policy, invalid fields/filters/timing fail closed.
- [x] Missing evidence, bare/fake PASS, failed/incomplete/timeout receipt, hash mismatch,
  path escape, inconsistent rescan and malformed waiver cannot PASS.
- [x] Human runtime waiver contract and justified NOT_APPLICABLE tested using fixtures;
  no actual human waiver/approval was created. Unapproved accepted risk rejected.
- [x] PASS/BLOCK/REVIEW_REQUIRED machine and human CLI output tested in isolated
  TEST_ONLY producer contexts. Gate evaluates receipts; it does not fabricate them.
- [x] Report/index failures return nonzero. Persisted report permits index recovery;
  subsequent canonical updates/rebuilds preserve audit and notification dedup state.

## Fixes observed during testing

First new unit run exposed test DB connections not closing on Windows and historical
boundary fixture last_seen later than simulated clock; corrected explicit close and
historical fixture timestamps. Fake scan PASS now explicitly requires a valid run ID
before loading scanner evidence. First CLI acceptance helper assumed parser argument
errors returned JSON; existing CLI contract prints error to stderr/30, so assertion
checks that actual contract. Final full suite passed; no test was removed or weakened.

## Files

New: security-cli/lib/policy.py, gate_audit.py; tests/m3_support.py,
tests/unit/test_policy.py, tests/integration/test_gate_acceptance.py;
docs/gate-input.md; .security/playbooks/secret-leak.md.
Modified: doctor.py dispatch, store.py audit replay, tests/support.py fixture copies,
test_doctor_acceptance.py removes gate from unimplemented commands, README.md,
MVP.md progress/current action. .agent evidence/handoff and Obsidian records updated.

## Validation areas and limits

Repository/toolchain, static/format, Windows compile, tests, canonical data integrity,
SQLite persistence/concurrency, policy boundaries and failure handling PASS. UI,
payment, remote AI, authentication application changes N/A. Receipt file hashes and
contracts do not independently authenticate producer execution; inputs must originate
from trusted deterministic/human records. M4 collector remains unimplemented. Actual
review approval/secret rotation/verified closure, notification delivery, other OS/Python
versions NOT VERIFIED. No comprehensive security or release-readiness claim.

M0–M3 complete; M4–M6 unchecked. Current M3 changes are local and **not committed or
pushed**. Previous GitHub HEAD remains fc0b201. No additional agent/process/deploy.
Next allowed step: M4 — Verification Layer, only on a new user task. Stop here.
