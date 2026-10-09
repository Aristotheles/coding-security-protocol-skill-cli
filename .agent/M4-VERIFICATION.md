# Coding Security Protocol — M4 verification

2026-10-09 · Codex · FEATURE · VERIFIED WITH WARNINGS

## Scope and implementation

Only M4 — Verification Layer, authorized by user's “devamke”. Fixed configured
argv test/runtime adapters, real static scan and relevant rescan, ordered immutable
receipts, policy evaluation and explicit core-only closure. Canonical JSON precedes
the derived SQLite index; every connection enables FK, updates use writer locks.
No new package, schema/policy/invariant change, AI adapter, CI, notification delivery,
architecture redesign, commit or push. M3 local work remains preserved.

## Commands and evidence

- Final `python -m unittest discover -s tests -v`: **132 tests OK**, exit 0,
  **203.566 seconds**. 24 new M4 unit tests and one full real-scanner integration
  acceptance test; all 107 prior tests retained.
- Real acceptance: vulnerable source → SEC-0001 OPEN → unchanged same SEC-0001 →
  fix plus actual test/rescan/runtime/policy → CLOSED → restore → same SEC-0001
  REOPENED, regression=true. Runtime failure first returned VERIFY_ERROR/60 and
  left OPEN; corrected runtime returned PASS/0. Empty AI registry throughout.
  Acceptance fixtures are isolated temporary directories, cleaned after testing.
- Actual repository `security verify --target tests/fixtures/scanner-project --json`
  returned **VERIFY_ERROR/60**, 95.237 seconds: static_scan PASS, tests PASS,
  security_rescan FAIL (SEC-0001/SEC-0002 still found), runtime NOT_APPLICABLE.
  Policy gate BLOCK/10. closed_ids empty; SEC-0001/2/3 remain OPEN. This is the
  expected negative result for deliberately vulnerable TEST_ONLY fixtures.
- Actual doctor JSON and literal `security doctor`: **PASS/0**, Python 3.14.5.
- Actual `security gate --event release --json`: **BLOCK/10**.
- Actual `security ai-patch --json`: **CONTRACT_ERROR/50**, still unimplemented.
- Exact actual command reports: `.agent/m4-command-results.json`; referenced raw
  outputs, receipts and reports are preserved in gitignored runtime directories.
- `python -m compileall -q security-cli tests`: exit 0.
- AST/whitespace/no-shell=True check: **28 Python files OK**.
- High-confidence private-key/token signatures: **29 files, no matches**; this is
  a targeted check, not a comprehensive security audit.
- `git diff --check`: exit 0 (Git LF/CRLF normalization notices only).
- Actual SQLite: foreign_keys=1, integrity=ok, foreign_key_check empty; three
  OPEN canonical/index findings and three audited gate runs after actual commands.
- Protected policy/schema/DB schema/AGENTS/SECURITY_AGENT diff empty. Config only
  gains the required stack.tests adapter. Canonical SEC-0001/2 observations updated
  by actual successful rescan; no artificial closure or fixture removal.

## Acceptance criteria

- [x] Test failure creates FAIL evidence; timeout preserves raw output.
- [x] Scanner failure/missing executable cannot mean finding gone or PASS.
- [x] Remaining original fingerprint produces security_rescan FAIL.
- [x] Runtime waiver requires existing human approver, reason and UTC timestamp.
- [x] Missing required evidence prevents successful gate.
- [x] PASS requires actual completed commands and validated preserved evidence.
- [x] Full actual verified-closure/regression lifecycle passes without AI.
- [x] Runtime NOT_APPLICABLE/WAIVED remains explicit, never fake PASS.
- [x] New rescan risks persist before policy; critical/secret risks block closure.
- [x] Original scanner/version/rules/ignore scope evidence must match.
- [x] Drift/tampered proof or receipt, review-required dependency change, direct
  closure without proof, and missing secret rotation confirmation prevent closure.
- [x] Canonical closure/index failure returns nonzero and rebuild recovers audit.

## Bug found and corrected

An index-failure regression test exposed a prospective policy view being written
to SQLite before actual canonical closure. Policy now audits using canonical OPEN
findings; only core closure writes verified CLOSED JSON, then rebuilds the index.
The failure and recovery tests pass. Final full suite rerun includes this correction
and later ignore configuration/tool-version drift hardening; no test was weakened.

## Files changed for M4

New: security-cli/lib/verify.py; tests/m4_support.py; tests/unit/test_verify.py;
tests/integration/test_verification_acceptance.py; docs/verification-contract.md;
.agent/M4-VERIFICATION.md; .agent/m4-command-results.json.
Modified: doctor.py CLI/config schema; scan.py provenance/timestamps;
store.py verified closure/regression and guarded update; policy.py proof gate;
security.config.yml stack.tests; tests/support.py; test_doctor_acceptance.py;
docs/gate-input.md; README.md; MVP.md; SEC-0001/2 observations; HANDOFF and Obsidian.
Prior M3 changes are also uncommitted and are preserved, not attributed to M4.

## FEATURE verification report

Repository/toolchain: PASS (Windows, Python 3.14.5, Semgrep 1.180.0, Trivy 0.75.0)
Format/static analysis: PASS (diff, AST, compileall, whitespace)
Tests/build platform: PASS (132 tests, actual Windows CLI/native adapters)
Architecture/data/backend/persistence: PASS (frozen contracts, canonical JSON,
proof validation, SQLite integrity/FK, locking, rebuild and index failure recovery)
Secrets/privacy/reliability/diff: PASS within targeted scope (local minimal inputs,
failure/timeout/tamper/drift tests; no live credential or remote AI use)
AI/cost, payments, GUI accessibility, mobile builds: N/A (CLI-only M4)
Overall: VERIFIED WITH WARNINGS

Warnings: Local trusted producer/waiver files are not cryptographic authentication.
Pre-M4 baselines lacking provenance cannot close; collect a fresh baseline before
fixing. Preserve runtime evidence for audit/recovery. Fixture findings remain OPEN.
Actual credential rotation, approval, notification delivery, other OS/Python versions
NOT VERIFIED. No release-readiness or comprehensive security audit claim.

M0–M4 complete, M5/M6 unchecked. M3+M4 changes local; HEAD remains fc0b201.
Next allowed step: M5 — AI Adapter, only on a new user task. Stop here.
