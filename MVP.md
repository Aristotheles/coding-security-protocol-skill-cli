# Coding Security Protocol — MVP v1.0

> Provider-independent, CI-independent, stack-adaptable AI-assisted DevSecOps layer.

## 0. Purpose

Coding Security Protocol is a small, portable security control layer for software projects.

Its job is to:

- run deterministic security scanners;
- normalize and deduplicate their findings;
- keep a persistent finding history;
- detect regressions;
- apply machine-readable security policies;
- allow AI agents to propose patches through a strict adapter contract;
- verify every patch with tests, rescan and runtime evidence;
- preserve human authority for sensitive decisions;
- keep working even if Codex, Claude Code, Antigravity, GitHub or another commercial service is unavailable.

The system must degrade gracefully when AI is unavailable. It must never depend on an AI provider in order to scan, store, verify or block a release.

---

# 1. Architecture Freeze

The architecture in this document is approved for MVP v1.

Do not redesign it during implementation.

Do not:

- replace SQLite;
- move business logic into GitHub Actions;
- make the system depend on Codex, Claude Code, Antigravity or any other AI provider;
- add new scanners before the MVP acceptance tests pass;
- add frameworks merely for convenience;
- introduce a hosted database;
- make JSON findings secondary to the database;
- allow AI to edit security policies;
- allow AI to close findings directly;
- allow AI output to bypass deterministic verification;
- implement multiple milestones in one uncontrolled pass.

If an implementation detail is unclear, choose the smallest solution that preserves this architecture.

---

# 2. Core Principle

The decision chain is:

**Evidence → Memory → Deduplication → Risk → AI Remediation → Deterministic Verification → Policy → Human Authority**

AI is not the source of security truth.

AI may:

- explain a finding;
- propose a patch;
- review another provider's patch;
- suggest tests.

AI may not:

- declare a vulnerability closed;
- change security policy;
- bypass a policy;
- merge security-sensitive code by itself;
- fabricate evidence;
- mark a failed verification as passed.

---

# 3. Four-Evidence Gate

A patch reaches the policy gate only after evidence has been collected for:

1. `static_scan`
2. `tests`
3. `security_rescan`
4. `runtime_verify`

Allowed evidence states:

- `PASS`
- `FAIL`
- `WAIVED`
- `NOT_APPLICABLE`

`runtime_verify` may be waived only with explicit human approval containing:

- approver identity;
- reason;
- timestamp.

A waiver is evidence, not a pass.

---

# 4. Independent Core

The MVP core is independent from AI vendors and CI providers.

Core components:

- Git
- Python security CLI
- Semgrep
- Trivy
- SARIF
- JSON finding store
- SQLite query index
- machine-readable policy engine
- test runner adapter
- playbooks
- audit records

Optional integrations:

- CodeQL
- GitHub Actions
- GitLab CI
- Jenkins
- MobSF
- OWASP ZAP
- SBOM tooling
- fuzzing
- dashboards
- notification providers

Optional integrations must never become required for basic operation.

---

# 5. AI Layer

AI providers are replaceable adapters.

Initial provider preference:

1. Codex — primary remediation agent
2. Claude Code — second reviewer / fallback
3. Antigravity — runtime/browser verification and fallback agent
4. local model — restricted trust
5. human — terminal fallback

The provider order is configuration, not architecture.

All providers must use the same adapter contract.

If every AI provider is unavailable, the system remains operational and routes remediation to human review.

---

# 6. Repository Layout

Target layout:

```text
/
├── AGENTS.md
├── MVP.md
├── SECURITY_AGENT.md
├── security.config.yml
│
├── schemas/
│   ├── finding.schema.json
│   ├── ai-patch-request.schema.json
│   ├── ai-patch-response.schema.json
│   └── ai-review-response.schema.json
│
├── docs/
│   └── ai-adapter-contract.md
│
├── security-cli/
│   ├── security
│   ├── security-store.schema.sql
│   └── lib/
│
├── .security/
│   ├── policies/
│   │   └── security-policy.yml
│   ├── findings/
│   ├── raw/
│   │   ├── semgrep/
│   │   └── trivy/
│   ├── sarif/
│   ├── evidence/
│   ├── reports/
│   ├── playbooks/
│   │   └── secret-leak.md
│   └── security.db
│
└── tests/
    ├── fixtures/
    ├── unit/
    └── integration/
```

Generated runtime files under `.security/` may be ignored selectively, but canonical finding JSON files must remain versionable unless a project explicitly chooses another audit strategy.

---

# 7. Source of Truth

Canonical security finding records are JSON files:

```text
.security/findings/SEC-0001.json
.security/findings/SEC-0002.json
...
```

SQLite is a queryable index/cache for:

- CLI queries;
- policy evaluation;
- dashboard queries;
- AI lookup;
- audit acceleration.

If JSON and SQLite disagree, JSON wins and SQLite must be rebuilt.

The CLI must support rebuilding the SQLite index from canonical JSON.

---

# 8. Finding Identity

Every finding receives a permanent ID:

```text
SEC-0001
SEC-0002
SEC-0042
```

IDs are never reused.

Deduplication and regression use a stable fingerprint containing at least:

- vulnerability category;
- normalized location;
- relevant code/context identity.

The fingerprint algorithm must be versioned:

```text
fingerprint_version: 1
```

Changing the fingerprint algorithm must not silently create a new security history.

Expected lifecycle:

```text
new finding
→ OPEN

same finding next scan
→ same SEC ID
→ last_seen updated

verified fix
→ CLOSED

same fingerprint later reappears
→ same SEC ID
→ REOPENED
→ regression = true
```

A previously closed vulnerability returning must not receive a new SEC ID.

---

# 9. Finding Ownership

Findings should support:

```text
owner
responsible_team
```

Global roles such as:

```text
security_lead
```

belong in configuration, not inside every finding.

---

# 10. Secret Remediation State

A `hardcoded-secret` finding cannot become `CLOSED` merely because the string was removed from code.

When rotation is required, the finding must carry remediation state such as:

```json
{
  "rotation_required": true,
  "rotation_confirmed": false,
  "confirmed_at": null,
  "confirmed_by": null
}
```

Closure requires deterministic confirmation that the required response was completed.

---

# 11. Policy Set

MVP policies:

## POL-001 — No open critical on release

If at least one `CRITICAL` finding is open, release is blocked.

## POL-002 — AI patch must close the finding

If an AI-generated patch is proposed and the relevant scanner still reports the finding after rescan, merge is blocked and the finding remains/re-enters open state.

## POL-003 — Dependency change review

If a lockfile changes and one or more new dependencies are added:

- human review is required;
- SBOM diff is required when SBOM support is enabled.

## POL-004 — No coverage regression

If an AI-generated patch reduces configured test coverage, merge is blocked.

## POL-005 — Secret zero tolerance

Open secret findings block merge and release.

The secret leak playbook is triggered.

A finding cannot close until required secret rotation is confirmed.

## POL-006 — Security-critical code requires human review

Changes matching configurable security-sensitive paths require human review.

Initial examples:

```text
**/auth/**
**/middleware/**
**/permissions/**
**/session/**
**/crypto/**
```

Paths are project-tunable.

## POL-007 — Stale high-risk finding escalation

Applies to `HIGH` and `CRITICAL` findings in `OPEN` or `REOPENED` state.

Stages:

```text
30 days → WARNING → security report
60 days → ESCALATED WARNING → owner + responsible team
90 days → OVERDUE → owner + responsible team + security lead
```

POL-007 is not a hard release block in MVP.

Notifications must have delivery/audit state so an escalation is not considered complete merely because it was written to a dashboard.

---

# 12. Exit Codes

The CLI must use stable exit codes.

```text
0   PASS
10  BLOCK
20  REVIEW_REQUIRED
30  CONFIG_ERROR
40  TOOL_ERROR
50  CONTRACT_ERROR
60  VERIFY_ERROR
```

Commands must not return `0` for an unimplemented security control.

Unimplemented or invalid security logic is fail-closed.

---

# 13. Security CLI

Required commands:

```bash
security doctor
security scan
security normalize
security findings update
security findings show SEC-0042
security findings rebuild-index
security verify
security gate
security ai-patch SEC-0042
```

Optional later commands:

```bash
security ai-review SEC-0042
security report
security notify
security sbom
```

---

# 14. CLI Safety Requirements

The CLI must:

- use argument arrays for scanner invocation;
- avoid `shell=True`;
- enforce execution timeouts;
- record scanner exit status;
- distinguish "scanner found vulnerabilities" from "scanner failed to execute";
- avoid overwriting multiple scans from the same day;
- generate a unique `run_id`;
- use timestamped raw output;
- validate configuration before running;
- fail closed when required configuration cannot be parsed;
- enable SQLite foreign keys;
- use SQLite transactions;
- protect concurrent store updates;
- validate JSON schemas;
- validate SARIF before normalization;
- reject missing evidence;
- reject fake PASS states;
- emit machine-readable reports.

Recommended run identifier:

```text
20261009T093015Z-a1b2c3
```

---

# 15. Protected Paths

AI-generated patches may never modify these by default:

```text
.security/policies/**
schemas/**
docs/ai-adapter-contract.md
SECURITY_AGENT.md
AGENTS.md
security.config.yml
```

The implementation may add other protected paths.

If a proposed diff touches a protected path:

```text
→ reject patch
→ CONTRACT_ERROR or REVIEW_REQUIRED
→ log attempt
```

A human may edit protected files outside the AI patch flow.

---

# 16. AI Adapter Contract

All AI providers receive normalized requests and must return schema-valid responses.

## Patch request

Contains:

- full finding JSON;
- minimum relevant files/context;
- applicable constraints;
- applicable policy IDs;
- prior remediation history.

Recommended constraints:

```text
allowed_paths
forbidden_paths
max_files_changed
no_new_dependencies
no_policy_edits
```

Only the minimum necessary source context should be sent to a remote AI provider.

## Patch response

Must contain at least:

- status;
- finding ID;
- unified diff;
- short remediation summary;
- changed files;
- suggested tests;
- patch source.

Valid statuses:

```text
PATCH_PROPOSED
CANNOT_FIX
NEEDS_HUMAN
```

Free-text responses are invalid.

A reasoning summary is informational only and is never security evidence.

---

# 17. AI Fallback Rules

Fallback is triggered by:

- quota/rate limit;
- provider unavailable;
- timeout;
- malformed JSON;
- schema violation;
- empty patch;
- invalid unified diff;
- missing finding ID;
- patch that cannot apply in dry-run;
- protected-path violation;
- tool execution failure;
- output contract violation.

A provider returning HTTP 200 with invalid content still counts as failure.

Maximum retries per provider in MVP:

```text
1
```

After all providers fail:

```text
human_review
```

---

# 18. AI Trust

Trust belongs to a capability profile, not a brand name.

Initial profiles:

```text
standard
restricted
```

`restricted` patches always require human review.

Example:

```text
provider: ollama
model: <model>
trust: restricted
```

A stronger future local model may receive another trust profile without changing the architecture.

Two AIs agreeing does not prove a patch is safe.

Agreement is a confidence signal only.

---

# 19. Reviewer Separation

When available, the patch reviewer should be a different provider from the patch author.

Example:

```text
Codex patch
→ Claude review
```

If no independent reviewer is available:

```text
human_review: REQUIRED
```

or the system must explicitly mark review confidence as reduced.

Deterministic verification remains mandatory regardless of reviewer agreement.

---

# 20. Runtime Verification

Runtime verification occurs before the policy gate.

Correct order:

```text
patch
→ tests
→ security rescan
→ runtime/browser verify
→ policy gate
→ merge/release decision
```

Antigravity may initially serve as the preferred runtime/browser verification agent, but runtime verification is an adapter role, not an Antigravity dependency.

Runtime verification must target staging/test environments unless a project explicitly defines a safe production verification policy.

---

# 21. CI Independence

Business logic lives in the CLI.

CI files contain orchestration only.

Good:

```yaml
- run: security doctor
- run: security scan
- run: security normalize
- run: security findings update
- run: security verify
- run: security gate
```

Bad:

```text
hundreds of lines of scanner, deduplication, policy and AI logic inside CI YAML
```

The same CLI commands must work:

- locally;
- in GitHub Actions;
- in GitLab CI;
- in Jenkins;
- in another CI runner.

---

# 22. MVP Scope

MVP includes:

- CLI foundation;
- configuration validation;
- SQLite store;
- canonical finding JSON;
- Semgrep adapter;
- Trivy adapter;
- SARIF normalization;
- deduplication;
- persistent finding identity;
- regression detection;
- policy engine;
- four-evidence model;
- secret leak playbook;
- AI adapter contract;
- one working AI patch adapter after deterministic core is stable;
- provider fallback skeleton;
- unit and integration tests.

---

# 23. Out of Scope for Initial MVP

Do not implement until core acceptance tests pass:

- full dashboard;
- Kubernetes deployment;
- hosted service;
- multi-tenant support;
- PostgreSQL;
- distributed queues;
- complex RBAC;
- MobSF;
- ZAP active scanning;
- full CodeQL integration;
- fuzzing;
- automatic PR creation;
- automatic merge;
- Slack/email integrations;
- advanced SBOM management;
- enterprise SIEM integrations.

Hooks/interfaces may be reserved, but these features must not delay v1.

---

# 24. Milestone M0 — Bootstrap & Doctor

## Goal

Create a safe, runnable project foundation.

## Implement

```bash
security doctor
```

Checks:

- supported Python version;
- expected directory structure;
- finding JSON schema exists and validates;
- policy file exists and parses;
- security config exists and parses;
- SQLite database can initialize;
- foreign keys are enabled;
- Semgrep availability;
- Trivy availability;
- write access to runtime directories;
- configured AI provider registry is syntactically valid;
- runtime verifier configuration is syntactically valid.

## Rules

Missing required config must not silently become `{}`.

Invalid YAML/JSON must be `CONFIG_ERROR`.

Missing optional scanner may be warning only if explicitly disabled.

## Acceptance Criteria

- `security doctor` returns `0` only when mandatory MVP requirements are valid.
- Broken policy YAML returns `30`.
- Missing required schema returns `30`.
- DB initialization is repeatable/idempotent.
- Doctor output has human-readable and machine-readable modes.

## Stop Condition

Do not start M1 until M0 tests pass.

---

# 25. Milestone M1 — Scanner Layer

## Goal

Run Semgrep and Trivy for real and preserve raw evidence.

## Implement

```bash
security scan
```

Initial scanners:

```text
Semgrep
Trivy
```

## Requirements

Each scanner profile uses:

- executable;
- argv list;
- timeout;
- enabled flag;
- output format;
- severity mapping;
- optional changed-file strategy.

Raw output:

```text
.security/raw/semgrep/<run_id>.sarif
.security/raw/trivy/<run_id>.sarif
```

If Trivy requires an intermediate JSON format for a feature, preserve the raw file and normalize later.

## Acceptance Criteria

- scanner binary actually runs;
- output is not overwritten by later runs;
- execution error is different from vulnerability detection;
- timeout is handled;
- missing scanner is handled according to config;
- scan metadata records command profile, timestamps and tool version where available;
- no `shell=True`.

## Stop Condition

Do not start M2 until test fixtures produce real raw scanner output.

---

# 26. Milestone M2 — Normalize, Dedup & Finding Store

## Goal

Turn scanner results into persistent normalized findings.

## Implement

```bash
security normalize
security findings update
security findings show SEC-0001
security findings rebuild-index
```

## Normalize

Convert tool output into a common model containing at least:

- tool;
- rule ID;
- category;
- severity;
- location;
- message;
- raw reference;
- context used for fingerprinting.

Merged SARIF:

```text
.security/sarif/<run_id>-merged.sarif
```

Do not emit a fake empty "successful" SARIF when required scanner output is missing.

## Dedup

Multiple tools reporting the same vulnerability should become one finding when fingerprint rules determine they represent the same issue.

Example:

```text
Semgrep SQL injection
+ another scanner SQL injection
→ SEC-0007
```

## Store

Write canonical JSON first.

Then update SQLite in a transaction.

If SQLite update fails after JSON write, report error and allow index rebuild.

## Acceptance Criteria

Foundation integration tests must demonstrate:

- real scanner evidence normalizes and creates SEC-0001 OPEN;
- unchanged evidence retains SEC-0001 without a duplicate SEC-0002;
- canonical JSON validates and can rebuild SQLite, with JSON precedence;
- a test-only seeded CLOSED canonical record returns as REOPENED with its
  existing SEC ID, regression=true and appended history when its fingerprint reappears;
- no actual production closure is claimed by that test fixture;
- without real deterministic verification and applicable policy evaluation,
  production closure fails closed; absence on a scan cannot close a finding.

Human-approved milestone dependency correction: the complete verified-closure
lifecycle scenario remains release-blocking and is accepted in M4 after M3/M4 exist.

## Stop Condition

Do not start M3 until the M2 foundation tests pass. M2 must not mark a live finding CLOSED.

---

# 27. Milestone M3 — Policy Engine

## Goal

Make security decisions independently of AI.

## Implement

```bash
security gate
```

Inputs include:

- canonical findings;
- evidence state;
- changed files;
- lockfile/dependency diff;
- patch metadata;
- coverage delta when configured;
- secret remediation state;
- waiver data;
- event (`merge` or `release`).

Outputs:

```text
PASS
BLOCK
REVIEW_REQUIRED
```

Write:

```text
.security/reports/<run_id>-gate-report.json
```

and audit the decision in SQLite.

## Required Policies

Implement POL-001 through POL-007.

Policies must remain data-driven from `security-policy.yml`.

Do not hardcode policy results into CI.

## Acceptance Criteria

Tests must prove at least:

- CRITICAL open + release → `BLOCK`;
- new dependency + lockfile change → `REVIEW_REQUIRED`;
- open hardcoded secret → `BLOCK`;
- auth path changed → `REVIEW_REQUIRED`;
- stale HIGH at 30 days → warning;
- 60-day escalation creates notification target state;
- 90-day escalation includes security lead;
- same escalation stage is not re-notified indefinitely;
- invalid/unreadable policy config → fail closed.

## Stop Condition

Do not start M4 until all policies have automated tests.

---

# 28. Milestone M4 — Verification Layer

## Goal

Collect deterministic evidence before policy evaluation.

## Implement

```bash
security verify
```

## Evidence

### static_scan

Scanner execution relevant to the change.

### tests

Stack adapter test command.

Examples later:

```text
npm test
pytest
gradle test
```

The core must not assume one stack.

### security_rescan

The scanner that originally reported the finding must run again.

The relevant finding must no longer be reported before closure is considered.

### runtime_verify

Runtime/browser verification adapter.

Initial state may be:

- real adapter;
- `NOT_APPLICABLE`;
- human-approved `WAIVED`.

It may not be falsely marked `PASS`.

## Evidence Record

Store evidence with:

- run ID;
- type;
- state;
- timestamp;
- source/tool;
- raw reference;
- approver for waivers;
- reason for waivers.

## Acceptance Criteria

- test failure → evidence `FAIL`;
- scanner execution failure → not equivalent to "finding gone";
- rescan still finds issue → `FAIL`;
- runtime waiver requires approver + reason + timestamp;
- missing required evidence prevents successful gate;
- verify command never prints "all passed" without checking.

The release-blocking full lifecycle integration test must also demonstrate:

```text
vulnerable fixture → SEC-0001 OPEN
unchanged fixture → same SEC-0001, no duplicate
fix + real tests/rescan/runtime/policy verification → SEC-0001 CLOSED
restore same vulnerability → SEC-0001 REOPENED, regression=true
```

All closure requirements in SECURITY_AGENT.md remain mandatory.

## Stop Condition

Do not start M5 until evidence gate tests and the full verified-closure lifecycle test pass.

---

# 29. Milestone M5 — AI Adapter

## Goal

Allow AI remediation without making the system AI-dependent.

## Implement

```bash
security ai-patch SEC-0001
security ai-patch SEC-0001 --provider <name>
```

First working adapter may be Codex.

The CLI itself must remain provider-neutral.

## Flow

```text
load finding
→ determine applicable policies
→ select minimum relevant context
→ build schema-valid request
→ invoke provider
→ parse response
→ validate response schema
→ validate finding ID
→ validate unified diff
→ enforce protected paths
→ enforce allowed paths
→ enforce max files changed
→ dry-run patch
→ record attempt
→ propose patch
```

Do not mark finding CLOSED.

## Patch Attempt Audit

Record:

- finding ID;
- provider;
- model when known;
- trust profile;
- start/end timestamp;
- result;
- fallback reason;
- response validation status;
- patch reference.

Example:

```text
Codex → invalid_diff
Claude → timeout
Antigravity → PATCH_PROPOSED
```

## Acceptance Criteria

Tests must prove fallback on:

- quota;
- timeout;
- malformed JSON;
- schema violation;
- missing finding ID;
- invalid diff;
- protected path touch;
- tool error.

Restricted trust patch must cause human review requirement.

## Stop Condition

Do not start M6 until one provider passes contract tests.

---

# 30. Milestone M6 — Provider Fallback & Independent Review

## Goal

Make AI providers replaceable.

## Default Chain

```text
Codex
→ Claude Code
→ Antigravity
→ local model
→ human review
```

The actual chain comes from configuration.

## Review

When possible:

```text
patch_source != reviewer_source
```

AI review output:

```text
APPROVE
REJECT
CONCERNS
```

Review output is advisory evidence, not deterministic closure evidence.

If no independent AI reviewer is available, require human review for security-sensitive changes as configured.

## Acceptance Criteria

- provider removal does not break scanner/gate operation;
- empty provider list still allows manual remediation;
- fallback is driven by contract validity, not just HTTP errors;
- restricted provider patch cannot silently inherit standard trust;
- system reaches explicit `human_review` terminal state.

---

# 31. Secret Leak Playbook

Create:

```text
.security/playbooks/secret-leak.md
```

Minimum process:

```text
DETECT
→ REVOKE / ROTATE
→ DETERMINE EXPOSURE
→ CLEAN HISTORY IF REQUIRED
→ CHECK LOGS / ABUSE
→ NOTIFY RESPONSIBLE OWNER
→ DOCUMENT INCIDENT
→ VERIFY NEW SECRET HANDLING
→ CLOSE FINDING ONLY AFTER REQUIRED CONFIRMATION
```

The playbook must state that deleting a secret from the current source tree does not invalidate a credential already exposed in Git history or remote systems.

---

# 32. Test Fixture Project

Create a deliberately vulnerable fixture only for automated testing.

It must never contain a real credential.

Fixture cases:

- fake hardcoded secret matching test scanner rules;
- simple injectable code pattern detectable by Semgrep;
- dependency/lockfile change case;
- security-sensitive path change;
- closed/reopened regression case.

Test data must use obvious non-production values such as:

```text
TEST_ONLY_DO_NOT_USE
```

Never commit live API keys to test the secret scanner.

---

# 33. Security Tests

Minimum test groups:

## Unit

- config parser;
- schema validation;
- fingerprint generation;
- severity mapping;
- policy condition evaluation;
- exit code mapping;
- diff validation;
- protected path validation;
- trust profile evaluation.

## Integration

- Semgrep execution;
- Trivy execution;
- raw → normalized;
- normalized → finding;
- duplicate → same finding;
- closed → reopened;
- SQLite rebuild from JSON;
- gate block/review/pass;
- evidence missing → fail closed;
- AI contract invalid → fallback.

## Regression

Every security bug fixed in Coding Security Protocol itself should receive a test where practical.

---

# 34. Finding Store Requirements

SQLite must include/audit at least:

- findings;
- finding sources;
- finding history;
- gate runs;
- escalation state.

Add as implementation matures:

- patch attempts;
- evidence records;
- notification delivery state.

Use:

```sql
PRAGMA foreign_keys = ON;
```

Use transactions for coordinated updates.

Use UTC ISO-8601 timestamps for events.

Prefer full timestamps over date-only fields for operational records.

---

# 35. Notification Model

POL-007 notification targets are logical roles, not hardcoded email addresses.

Examples:

```text
finding_owner
responsible_team
security_lead
security_report
```

Notification providers are adapters.

MVP may write notifications to an outbox/report instead of sending email/Slack.

However it must record:

- target;
- stage;
- attempted timestamp;
- status;
- delivered timestamp when applicable;
- error when applicable.

"Displayed on dashboard" is not equivalent to "notified."

---

# 36. Security Configuration

`security.config.yml` should eventually contain sections for:

```text
stack
scanners
ai
roles
runtime_verify
notifications
protected_paths
```

Do not put secrets directly in this file.

Credentials must come from environment variables or external secret management.

---

# 37. Stack Adapter

The core is stack-independent.

Project-specific behavior is injected via config/adapter.

Examples:

## Node / TypeScript

```text
test command → npm test
Semgrep profile → JS/TS
optional CodeQL language → javascript-typescript
```

## Python

```text
test command → pytest
Semgrep profile → Python
optional CodeQL language → python
```

## Android

```text
test/build → Gradle
artifact → APK/AAB
later scanner → MobSF
```

## Web/API

```text
staging target
later runtime scanner → ZAP
browser verification adapter
```

Do not choose the project stack inside the core implementation.

---

# 38. GitHub Actions — Later Orchestration

After local CLI behavior is proven, add a minimal workflow.

Expected conceptual flow:

```text
checkout
→ install dependencies
→ security doctor
→ security scan
→ security normalize
→ security findings update
→ security verify
→ security gate
```

No dedup/policy/AI business logic belongs in the workflow file.

---

# 39. Definition of MVP Success

The Coding Security Protocol MVP is successful when the following scenario works end-to-end:

```text
1. Run Semgrep + Trivy against vulnerable test fixture.
2. Create SEC-0001 as OPEN.
3. Re-run unchanged fixture.
4. Do not create a duplicate SEC ID.
5. Fix vulnerability.
6. Run tests and relevant security rescan.
7. Close SEC-0001 only after deterministic verification.
8. Restore the same vulnerability.
9. Re-run scan.
10. Reopen SEC-0001.
11. Set regression = true.
12. Policy gate returns the expected exit code.
13. All of the above works without any AI provider configured.
```

This scenario is the heart of v1.

AI integration is not allowed to hide failure of this scenario.

---

# 40. Definition of Done

MVP v1 is done when:

- M0–M6 acceptance tests pass;
- deterministic core works with no AI configured;
- Semgrep + Trivy work locally;
- findings persist across runs;
- regression detection is proven;
- policies POL-001–007 are tested;
- evidence gate is fail-closed;
- AI adapter rejects invalid outputs;
- restricted trust forces human review;
- CI logic remains in CLI;
- source-of-truth JSON can rebuild SQLite;
- secret leak playbook exists;
- documentation matches implementation.

---

# 41. Codex Execution Discipline

Codex is the primary implementation agent but not the architect.

For each milestone:

```text
1. Read MVP.md, AGENTS.md and SECURITY_AGENT.md.
2. Identify the active milestone only.
3. Inspect only files relevant to that milestone.
4. State the smallest implementation needed.
5. Implement it.
6. Add/update tests.
7. Run tests.
8. Run the relevant CLI command.
9. Report actual results.
10. Update the milestone progress section.
11. STOP.
```

Do not automatically continue to the next milestone.

Do not opportunistically refactor unrelated code.

Do not add "nice to have" features.

Do not change architecture because another design appears cleaner.

If an architecture change is genuinely necessary, stop and report:

```text
ARCHITECTURE_CHANGE_REQUIRED
```

with:

- exact blocker;
- smallest proposed change;
- impacted files;
- security impact.

Wait for human decision.

---

# 42. Progress

## Architecture

- [x] Architecture defined
- [x] Finding model drafted
- [x] Policy set drafted
- [x] AI adapter contract drafted
- [x] CLI skeleton drafted
- [x] SQLite schema drafted
- [x] MVP implementation plan frozen

## Implementation

- [x] M0 — Bootstrap & Doctor
- [x] M1 — Scanner Layer
- [x] M2 — Normalize / Dedup / Finding Store
- [ ] M3 — Policy Engine
- [ ] M4 — Verification Layer
- [ ] M5 — AI Adapter
- [ ] M6 — Provider Fallback / Review

---

# 43. Current Next Action

**M2 foundation complete. Stop here. M3 is the next milestone and requires a new human task.**

M2 verification:

> 76 unit/integration tests passed; two real scanner acceptance tests were rerun after excluding generated bytecode caches. Real scan/normalize/update/show/rebuild-index/doctor commands returned 0. Cross-tool dedup, stable IDs, canonical JSON precedence, crash-safe ID allocation, concurrent writes, index recovery and test-only seeded CLOSED → REOPENED regression passed. M2 production closure remains unavailable; the full verified-closure lifecycle acceptance remains release-blocking in M4 under the human-approved plan correction. M3 has not started.
