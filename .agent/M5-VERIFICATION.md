# Coding Security Protocol — M5 final verification

2026-10-09 14:41 Europe/Istanbul · Codex · FEATURE · Overall: VERIFIED WITH WARNINGS

## Result and boundary

M0–M5 acceptance complete. Only M5 was continued. M6 is not started. No dependency,
architecture, policy weakening, automatic apply/closure, commit, push or deploy.
Default provider registry remains empty; deterministic core is AI-independent.

## Root cause and correction

Previous live failures are preserved below as historical evidence. Diagnosis
reproduced HTTP/WebSocket failures only with the old case-sensitive environment
allowlist: Windows os.environ uses SYSTEMROOT, while the allowlist used SystemRoot.
Case-insensitive matching preserves the same allowed key, restoring DNS/native
networking. Arbitrary secret environment variables remain excluded. No login reset,
TLS bypass, proxy change, model change or extra dependency was needed. The effective
saved model gpt-6.1-sol now appears in attempt/canonical metadata.
Evidence: `.agent/m5-connectivity-diagnosis.json`; regression assertion in
`tests/unit/test_ai_patch.py`.

## Final tests and actual commands

- Full `python -m unittest discover -s tests -v`: **145 OK**, **218.233 seconds**,
  after the final environment/model-audit fixes, including all prior real scanner
  lifecycle, 11 M5 unit tests and 2 M5 native CLI acceptance tests.
- Targeted 13 M5 tests: OK, 23.340 seconds (before final model-audit change).
- Live Codex adapter: valid contract/diff dry-run; `.agent/m5-live-codex.json`.
- Actual isolated `security ai-patch SEC-0001 --provider codex --json` with real
  Codex: **REVIEW_REQUIRED/20**, **PATCH_PROPOSED**, response **VALIDATED**,
  source_unchanged=true, canonical_status=PATCH_PROPOSED,
  patch_applied=false, finding_closed=false; model gpt-6.1-sol.
  Run: 20261009T113429Z-ed58c93a8c3b4341a417525bd09a9d01.
  Record: `.agent/m5-live-cli.json`. Preserved raw/request/response/diff/audit:
  `.security/evidence/m5-live-cli-e90e75fff372427ba77a1e2b1143ed10`.
  Temporary acceptance project is cleaned; evidence_copy maps its original relative
  report references. Runtime copies are gitignored. This used a safe small fixture.
- Actual root `security doctor` with documented session PATH: **PASS/0**.
  A fresh shell without that documented PATH initially could not resolve security;
  rerunning with README session PATH succeeded. No permanent machine PATH changed.
- Root findings SEC-0001/2/3 remain OPEN; no root source patch or closure.
  Previous root sensitive-context refusal/20 and release gate BLOCK/10 are historical
  valid results in `.agent/m5-command-results.json`, not repeated gate checks today.
- Compileall, AST/whitespace/no-shell (30 .py modules plus CLI entrypoint), SQLite
  integrity/foreign_keys ON/foreign_key_check and git diff --check passed.
  Final machine-readable snapshot: `.agent/m5-final-checks.json`.

## Acceptance

- [x] One actual live provider validates JSON contract, finding/source identity,
  allowed/protected paths, unified diff and isolated Git dry-run.
- [x] Invalid/quota/timeout/schema/ID/diff/path/tool/dry-run failures use bounded
  fallback; exhausted providers produce human_review, never fake security PASS.
- [x] Requests are bounded; conservative sensitive context is refused before invoke.
- [x] Fixed native argv/timeout/raw audit, isolated source copy and environment filter.
- [x] Canonical PATCH_PROPOSED/history then derived index; nonzero failure/recovery.
- [x] No patch apply or finding closure; restricted trust cannot be downgraded.
- [x] Empty providers preserve deterministic core and verified M4 lifecycle.

## Files and verification scope

M5 files: ai_patch.py, AI request/response schemas, AI contract, doctor.py dispatch/
provider config, scan.py stdin/env support, policy.py provenance, test support,
11 unit/2 acceptance tests, README/MVP and local verification/handoff records.
This continuation corrected only environment filtering/model audit and regression
assertion, then completed evidence/docs. M3/M4 uncommitted work is preserved.

FEATURE: toolchain/static/build/tests/Windows native CLI/persistence/contracts/
fail-closed/diff review PASS. Live authenticated Codex operation verified. Targeted
privacy checks are bounded, not a comprehensive security audit. GUI/accessibility,
payments/mobile, notification delivery and independent AI review N/A to M5.
Other OS/Python versions and actual human approval/credential rotation NOT VERIFIED.
Local bridge trust, conservative secret screening and noncryptographic provenance
limitations remain as described in the contract. This is not release readiness.

Next allowed step: M6 — Provider Fallback / Review, only on a new human instruction.
STOP. M3–M5 changes remain local/uncommitted.

---

## Historical pending verification — superseded by final evidence above

# Coding Security Protocol — M5 verification

2026-10-09 · Codex · FEATURE · Overall: NOT VERIFIED (live provider pending)

## Result and boundary

User's “devam” authorized only first unchecked M5. Proposal-only ai-patch CLI,
strict request/response schemas, native command/Codex adapters, bounded context,
protected/allowed paths, unified diff parsing, isolated Git dry-run, attempt audit,
canonical PATCH_PROPOSED and trust propagation are implemented. No new dependency,
policy weakening, architecture change, AI review/M6, automatic apply/closure or push.
The default registry stays empty. M3/M4 local changes were preserved.

M5 is **not marked complete**. TEST_ONLY adapter subprocesses pass contract tests;
they are not real AI. Two actual Codex CLI calls failed before a response with
workspace routing discovery/connection errors. Neither made a valid proposal.

## Tests and actual commands

- New 11 unit + 2 native CLI acceptance tests: 13 OK, 18.134 seconds.
- Full `python -m unittest discover -s tests -v`: **145 OK**, **188.267 seconds**.
  All prior 132 tests remain, including real Semgrep/Trivy lifecycle without AI.
- After SQLite-error classification hardening, M5 unit tests were rerun separately;
  11 tests OK, 14.801 seconds; also recorded in HANDOFF. Full suite above precedes that
  narrow error classification change; do not misstate its coverage.
- Actual isolated live Codex first and second attempts: REVIEW_REQUIRED/20,
  terminal human_review, fallback_reason tool_error, source_unchanged=true.
  `codex login status` reports logged in using ChatGPT; this is not connectivity
  proof. Second attempt preserved desktop routing origin and selected user model
  while retaining isolated tool/hook configuration; still failed.
- Live records: `.agent/m5-live-codex-initial.json`, `.agent/m5-live-codex.json`.
  Raw attempt/request/stdout/stderr copies are under each evidence_copy directory
  recorded there. They are gitignored. Temporary acceptance projects are cleaned;
  original relative references refer to those projects, mapped by evidence_copy.
- Actual root `ai-patch SEC-0002 --json`: REVIEW_REQUIRED/20,
  sensitive_context_human_review, no invocation. Fixture contains a TEST_ONLY
  secret assignment; canonical finding bytes unchanged.
- Actual doctor PASS/0 and release gate BLOCK/10. Exact root outputs:
  `.agent/m5-command-results.json`.
- compileall exit 0, 31 Python files AST/whitespace/no-shell PASS, targeted
  high-confidence credential signatures no matches. Diff check exit 0.
  These are targeted checks, not a comprehensive security audit.

## Acceptance

- [x] Native JSON protocol and exact request/response schema contract.
- [x] Quota, timeout, malformed JSON, schema violation/missing ID, wrong ID/source,
  empty/invalid diff, protected/outside paths, dry-run failure, unavailable/tool
  error all trigger bounded fallback; all fail → human_review.
- [x] Fixed argv, shell=False, timeout/descendant termination, unique preserved raw.
- [x] Existing file only; no rename/create/delete/binary/mode/symlink/traversal or
  dependency manifest change; changed file list and hunks must agree.
- [x] Minimal line context, request bounds, likely sensitive context refusal before
  invocation, environment allowlist, source/control/canonical drift rejection.
- [x] Propose only: no source edit, no test execution inferred from AI suggestion,
  no CLOSED/no human approval. Real M4 evidence is still required.
- [x] Restricted proposal always human review; caller human/standard metadata
  cannot downgrade stored canonical trust during verification/policy.
- [x] Canonical proposal/history before derived DB; failure nonzero/rebuild recovery.
- [x] Empty providers preserve core operation; original deterministic lifecycle passes.
- [ ] One **live AI provider** valid response + validated dry-run proposal proven.

## Changes

New: security-cli/lib/ai_patch.py; schemas/ai-patch-request.schema.json;
schemas/ai-patch-response.schema.json; docs/ai-adapter-contract.md;
tests/unit/test_ai_patch.py; tests/integration/test_ai_patch_acceptance.py;
.agent/M5-VERIFICATION.md and three actual command/live JSON records.
Modified for M5: doctor.py provider config fields/CLI dispatch; scan.py optional
stdin/environment parameters (existing scanner calls retain prior defaults);
policy.py canonical AI provenance; tests/support.py; README/MVP/HANDOFF/Obsidian.
Existing M3/M4 config/schema/canonical changes are prior work, not new M5 changes.
No existing finding schema, SQL schema, policy YAML, AGENTS or SECURITY_AGENT edits.

## Test fixes and limitations

FEATURE control areas: repository/toolchain PASS; format/static/compile PASS;
automated tests PASS; Windows CLI/native adapter build/platform PASS; architecture
and JSON/SQLite persistence PASS; targeted secrets/privacy and reliability PASS
within documented scope; diff review PASS. Live AI/authenticated provider operation
NOT VERIFIED (connection failed). GUI/accessibility, payment, mobile release,
independent AI review and notification delivery N/A for this task. Other supported
OS/Python versions NOT VERIFIED. No comprehensive security or release-readiness claim.

First unit run failed because repeated test fixtures changed canonical status but
kept PATCH_PROPOSED history and because drift test source was reused for a later
dry-run. Reset complete test fixture snapshots/source; no control/test was weakened.
Later tests include OSError and sqlite OperationalError after canonical proposal.

Local contracts/proofs do not cryptographically authenticate a human or provider.
Trusted native bridge executables are operator-controlled; temporary working root
and read-only Codex configuration are not a general containment guarantee. Secret
screening is conservative, not comprehensive. Semantic new dependencies still need
accurate change metadata/human review. Other OS/Python versions, real credential
rotation/approval and notification delivery NOT VERIFIED. GUI/payments/mobile/AI
review are N/A in M5. Live AI completion NOT VERIFIED; no fabricated PASS.

Next allowed step: restore/diagnose live Codex connectivity and rerun the same M5
contract acceptance. M6 NOT READY. M0–M4 [x], M5/M6 [ ]. Changes remain local.
