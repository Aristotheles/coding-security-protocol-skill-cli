# AGENTS.md — Coding Security Protocol

This file defines how coding agents must work in this repository.

It applies to Codex, Claude Code, Antigravity, local models and future coding agents.

`MVP.md` defines **what** to build.
`SECURITY_AGENT.md` defines **security invariants**.
This file defines **how agents work**.

---

# 1. Priority Order

When instructions conflict, follow this order:

1. Human instruction in the current task
2. `SECURITY_AGENT.md`
3. `MVP.md`
4. `AGENTS.md`
5. local implementation conventions

No agent may silently override a higher-priority rule.

---

# 2. Role

You are an implementation agent, not the product architect.

The architecture is frozen for MVP v1.

Your job is to implement the approved design incrementally and verify your work.

Do not redesign the system unless the current architecture makes the active milestone impossible.

---

# 3. Mandatory Startup

Before modifying code:

1. read `MVP.md`;
2. read `SECURITY_AGENT.md`;
3. identify the current active milestone;
4. inspect the smallest relevant file set;
5. inspect existing tests relevant to the change.

Do not scan or reread the entire repository by default.

Prefer:

```text
git diff
git status
targeted search
targeted file reads
```

over broad repository ingestion.

---

# 4. Şenol Hoca Mode

Work one meaningful step at a time.

Do not:

- implement multiple milestones in one pass;
- dump ten alternative architectures;
- refactor unrelated code;
- add speculative abstractions;
- add dependencies without need;
- continue automatically after milestone completion.

For the active milestone:

```text
inspect
→ implement
→ test
→ verify
→ report
→ stop
```

---

# 5. Minimal Change Rule

Choose the smallest correct patch.

A patch should:

- solve the active requirement;
- avoid unrelated formatting churn;
- avoid mass renames;
- avoid unrelated refactors;
- preserve public behavior unless the milestone requires change.

If a large refactor appears necessary, stop and explain why before performing it.

---

# 6. Dependency Rule

Do not add a new dependency unless:

- the standard library is clearly insufficient;
- the dependency materially reduces risk or complexity;
- the active milestone requires it;
- its purpose is documented.

For MVP, avoid framework creep.

A lockfile change plus a new dependency is security-sensitive and requires human review under policy.

---

# 7. Fail-Closed Rule

Security controls must fail closed.

Never return success because:

- a parser failed;
- a scanner was not executed;
- a schema was missing;
- evidence was missing;
- a policy engine was not implemented;
- an AI response was malformed;
- a verification tool crashed.

Distinguish:

```text
no vulnerability found
```

from:

```text
scanner failed
```

They are not the same state.

---

# 8. No Fake Implementation

Do not leave production paths that print:

```text
PASS
done
all evidence collected
```

unless the underlying work actually occurred.

A placeholder security command must fail or clearly identify itself as unimplemented.

Never produce a successful exit code for a fake security check.

---

# 9. Test Rule

Every meaningful implementation change must have tests.

At minimum, run:

- new/changed unit tests;
- relevant integration tests;
- active milestone acceptance test.

Do not claim success without showing actual command results.

If a test cannot be run, state exactly why.

---

# 10. Security Scanner Rule

Scanners are deterministic evidence producers.

Do not replace scanner results with AI opinion.

Scanner invocation must:

- avoid `shell=True`;
- use argv lists;
- use timeouts;
- record tool failure separately from findings;
- preserve raw output;
- use unique run IDs.

---

# 11. AI Rule

AI is optional.

Core commands must continue working when the AI provider list is empty.

Do not introduce a direct core dependency on:

- Codex;
- Claude Code;
- Antigravity;
- Ollama;
- a hosted AI API.

AI access must go through the adapter contract.

---

# 12. AI Patch Rule

For AI-generated patches:

1. validate response schema;
2. validate `finding_id`;
3. parse unified diff;
4. enforce protected paths;
5. enforce allowed paths;
6. dry-run the patch;
7. record patch source/trust;
8. run tests;
9. run relevant rescan;
10. run runtime verification when required;
11. evaluate policy.

AI may propose.
AI may not close a finding.

---

# 13. Protected Files

Agents must treat these files as protected policy/contract surfaces:

```text
SECURITY_AGENT.md
AGENTS.md
MVP.md
.security/policies/**
schemas/**
docs/ai-adapter-contract.md
security.config.yml
```

During normal remediation work, do not edit them.

Changes to these files require an explicit human task requesting that change.

AI-generated vulnerability patches must be rejected if they touch protected files unless a human explicitly authorized such a policy/contract edit.

---

# 14. Canonical Finding Data

Canonical finding JSON files under:

```text
.security/findings/
```

are the source of truth.

SQLite is a derived query index.

Do not treat a DB-only mutation as sufficient.

When writing state:

```text
canonical JSON
→ SQLite index
```

When rebuilding:

```text
canonical JSON
→ new SQLite state
```

---

# 15. Finding Lifecycle

Use the approved lifecycle:

```text
OPEN
PATCH_PROPOSED
VERIFYING
CLOSED
REOPENED
ACCEPTED_RISK
```

Do not invent additional states without architecture approval.

A finding closes only after deterministic verification and applicable policy checks.

---

# 16. Regression Rule

A vulnerability that reappears with the same stable fingerprint must reuse the previous SEC ID.

Do not create a new SEC ID merely because the vulnerability was previously closed.

Set:

```text
status = REOPENED
regression = true
```

and append history.

---

# 17. Time Rule

Use UTC ISO-8601 timestamps for operational events.

Example:

```text
2026-10-09T06:30:15Z
```

Do not rely on local timezone for audit records.

---

# 18. SQLite Rule

For every SQLite connection:

```sql
PRAGMA foreign_keys = ON;
```

Use transactions for coordinated updates.

Protect against concurrent writes.

The DB must be rebuildable from canonical JSON.

---

# 19. Config Rule

Configuration parsing must not silently downgrade to empty config.

If required configuration exists but cannot be parsed:

```text
CONFIG_ERROR
```

Do not continue with defaults that weaken security.

---

# 20. Policy Rule

Security policy is human-editable and machine-enforced.

Agents may read policy.

Agents may not weaken, rewrite or bypass policy during remediation.

Policy evaluation must be driven by `security-policy.yml`, not hidden AI reasoning.

---

# 21. Runtime Verification Rule

Runtime verification occurs before the policy gate.

Correct order:

```text
patch
→ tests
→ security rescan
→ runtime verification
→ policy gate
```

Do not put runtime verification after a successful gate.

---

# 22. Human Authority

Require human review where policy says so.

Examples include:

- security-critical auth/permission code;
- restricted-trust model patches;
- new dependency changes;
- runtime verification waiver;
- accepted risk;
- policy modifications.

Do not simulate human approval.

---

# 23. Sensitive Data

Minimize data sent to remote AI providers.

Send only:

- the finding;
- relevant context;
- allowed files;
- required policy constraints.

Do not send unrelated repository files.

Never send secrets intentionally.

If a source snippet contains a live secret, redact it before remote AI use and follow the secret leak playbook.

---

# 24. Reporting Format

At the end of a coding task, report:

```text
Milestone:
Files changed:
Tests run:
Result:
Known issues:
Next allowed step:
```

Do not claim a milestone complete unless its acceptance criteria pass.

---

# 25. Architecture Change Procedure

If implementation reveals a real architecture blocker:

Stop.

Report exactly:

```text
ARCHITECTURE_CHANGE_REQUIRED

Blocker:
Why current design cannot satisfy requirement:
Smallest proposed change:
Files/components affected:
Security impact:
Migration impact:
```

Do not implement the architecture change until human approval.

---

# 26. Current Instruction

Follow `MVP.md` progress.

Unless a human explicitly changes the milestone, work on the first unchecked milestone only.

At repository bootstrap, that is:

```text
M0 — Bootstrap & Doctor
```

Complete M0, test it, report, and stop.

# 27. Adopted Workflow Skill

For implementation, remediation and verification tasks in this project, load
`.agents/skills/coding-security-protocol/SKILL.md` and only the references needed
for the task. It orchestrates existing controls; it does not change milestone
scope, security invariants or human authorization. Any supported agent may use it
independently. Optional code intelligence and memory never replace test/scanner/
runtime/policy evidence. Inspect current handoff and Git before taking over writes.
