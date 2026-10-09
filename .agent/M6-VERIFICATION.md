# Coding Security Protocol — M6 verification

2026-10-09 14:55 Europe/Istanbul · Codex · FEATURE · Overall: VERIFIED WITH WARNINGS

## Scope and implementation

Only first unchecked M6 — Provider Fallback & Independent Review. Preserved M3–M5
local work. No dependency, framework, architecture change, scanner addition, CI,
policy weakening, auto apply/closure, human approval, commit, push or deploy.

Config registry order remains authoritative; optional roles patch/review/both.
Review uses existing native command/Codex transport and separate strict schemas.
Author exclusion and native Codex alias exclusion; bounded input, diff SHA/SEC/
author/reviewer binding; one attempt per eligible provider per role. Contract errors
cause fallback even at process exit 0. Valid REJECT/CONCERNS stops without hunting
for an approval. All exhausted providers route explicitly to human_review.

Review is advisory only. No reviewer can replace tests/rescan/runtime/policy.
Restricted author's trust survives standard review and provider removal. Required
human review is persisted in canonical proposal/history and cannot be downgraded
by caller change metadata in the policy gate. POL-001..007 YAML is unchanged;
AI_REVIEW is an invariant control report label, not an extra policy. No new approval
workflow is introduced. Sensitive paths still follow POL-006. Ordinary standard
paths with no independent reviewer explicitly record REDUCED confidence.

## Acceptance criteria

- [x] Provider removal preserves scanner/gate operation (native CLI tests).
- [x] Empty provider list permits actual manual tests/rescan/runtime/policy closure.
- [x] Fallback is based on validated contract, including exit-0 invalid output.
- [x] Restricted patch cannot inherit standard trust, including standard APPROVE.
- [x] Explicit human_review terminal for exhausted patch/review providers.
- [x] Independent advisory review with binding and reviewer separation.
- [x] Source remains unchanged; approved proposal alone never closes finding.
- [x] Final full regression suite: 162 tests OK/0 (250.324 seconds).

## Tests and actual commands

Targeted 16 tests passed (29.378 seconds); this preceded the final mixed-trust
configuration-order test. Final `python -m unittest discover -s tests -v`: **162 OK**, **250.324 seconds**,
after all final code/test changes. Includes real Semgrep/Trivy acceptance and actual
verified closure/regression without any AI provider.
New M6 tests: 14 unit + 3 native CLI acceptance. TEST_ONLY adapters are explicitly
simulated opinions; they are not real independent AI providers.

Actual root commands: doctor PASS/0, release gate BLOCK/10 due to deliberate open
fixtures, ai-patch SEC-0002 REVIEW_REQUIRED/20 before provider invocation for
sensitive fixture context; canonical bytes unchanged. All root SEC1/2/3 stay OPEN.
Machine-readable root command evidence: `.agent/m6-command-results.json`.

Actual isolated CLI with TEST_ONLY bridges: invalid review hash fallback then
validated APPROVE; restricted author remains restricted and requires human review;
source unchanged, PATCH_PROPOSED/20, no apply/closure. Removing providers routes
human_review and deterministic verified closure still requires review.
Evidence: `.agent/m6-native-cli.json`; raw copied evidence path recorded there.
Original temporary project was cleaned; evidence_copy maps its original relative
proposal/review response/audit references. Runtime copies are gitignored.

Static/format: 34 Python modules/entrypoints AST/whitespace/no-shell PASS,
compileall PASS, targeted high-confidence credential signatures no matches,
SQLite integrity/foreign_keys ON/foreign_key_check PASS, git diff --check PASS.
Requirements, policy YAML, finding/SQLite schemas, AGENTS and SECURITY_AGENT unchanged.

## Initial failure and repair

First targeted test run failed (23 cases: 15 errors and 1 failure) because test
bridge used a multiline inline argv value, prohibited by the existing config TEXT
contract. It returned CONFIG_ERROR before providers. Moved that TEST_ONLY script
to an isolated absolute file and kept argv single-line; no validator was weakened.
Subsequent 10-test run passed (17.765 seconds); then 14 passed (27.963 seconds),
then final targeted 16 passed (29.378 seconds). No canonical provenance is erased
to simulate provider removal; independent manual acceptance uses a fresh fixture.

## FEATURE verification and limits

Repository/toolchain: PASS (Windows/Python 3.14.5, existing dependencies)
Format: PASS
Static analysis: PASS (AST/compile, no separate type/lint tool added)
Tests: PASS (162 final unit/integration cases)
Build/platforms: PASS (native Windows CLI/compile); other OS/Python NOT VERIFIED
Architecture: PASS (CLI logic, existing adapter/store/policy boundaries)
Data/content: PASS (exact schemas/IDs/hash binding, JSON first/derived SQLite)
Auth/backend: PASS within existing local trusted bridge/policy scope; human auth not implemented
AI/cost: PASS contract, timeout, bounded input, one attempt per role; live independent AI NOT VERIFIED
Offline/persistence: PASS (empty providers/manual core and index rebuild)
Accessibility/UX: N/A (no GUI added)
Secrets/privacy: PASS targeted refusal/allowlist; conservative, not comprehensive audit
Reliability: PASS (malformed/timeout/tool/quota/drift/fallback/no fake closure)
Diff review: PASS (only M6 plus authorized records)

Warnings: two real independent AI providers were not invoked. M6 acceptance requires
replaceability/contract tests, not new branded agents. Native bridge provider IDs are
operator-managed; independence/provenance/human authority are not cryptographically
authenticated. Semantic dependency metadata and conservative secret screening retain
previous limits. No actual human approval/credential rotation/notification delivery.
The default registry remains empty. This is not a production release-readiness claim.

## Files

New: security-cli/lib/ai_review.py; schemas/ai-review-request.schema.json;
schemas/ai-review-response.schema.json; tests/unit/test_ai_review.py;
tests/integration/test_ai_review_acceptance.py; M6 proof/actual CLI records.
Modified: ai_patch.py task transport/review/provenance; doctor.py optional roles;
policy.py canonical review requirement; tests/support.py copying new contracts;
docs/ai-adapter-contract.md; README; MVP progress and HANDOFF/Obsidian on completion.

Next allowed step: user-directed final diff/commit preparation. M0–M6 implementation
and acceptance complete; STOP. No new milestone, commit/push or release was started.
