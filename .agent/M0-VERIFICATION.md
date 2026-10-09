# Coding Security Protocol — M0 verification

Date: 2026-10-09 · Agent: Codex · Mode: FEATURE

## Evidence

- `python -m unittest discover -s tests -v`: 40 tests, OK, exit 0 (16.754 seconds).
- `python -m unittest tests.unit.test_doctor.ConfigTests.test_invalid_config_fields -v`: OK after correcting the executable control-character validator.
- `security doctor`: PASS, exit 0 on the real project root, Python 3.14.5.
- `security doctor --json`: PASS, exit 0; machine-readable report saved beside this note.
- `python -m compileall -q security-cli tests`: exit 0.
- AST parsing and read-only whitespace check: 9 Python files passed.
- Old project-name search: no matches in project text files (rg exit 1).

## Acceptance criteria

- [x] Valid mandatory requirements return 0; config, DB and required-tool errors cannot PASS.
- [x] Broken policy YAML returns 30 (real CLI subprocess test).
- [x] Missing required finding schema returns 30 (real CLI subprocess test).
- [x] Repeatable initialization preserves existing data; concurrent initialization tested.
- [x] Human-readable and machine-readable doctor modes work; Windows launcher tested.

Additional tests cover malformed/empty/duplicate/unsafe YAML, invalid and missing JSON
Schema, non-standard JSON constants, broken/remote schema references, AI registry and
runtime syntax, unsupported Python, missing directories, write-access failures, DB
corruption, schema mismatch rollback, DB locking and actual foreign-key enforcement.
Later commands return CONTRACT_ERROR rather than fabricated security success.

## Verification areas

| Area | Result | Evidence / limit |
| --- | --- | --- |
| Repository/toolchain | WARN | Folder has no `.git`; git status/diff unavailable. Original 3 docs compared to pre-edit temporary snapshot. Python and both parser dependencies present. |
| Format | PASS | Read-only whitespace checks; no formatter rewrite. |
| Static analysis | PASS | AST and compileall; no separate linter configured. |
| Tests | PASS | All 40 relevant unit/integration/acceptance tests. |
| Build/platforms | PASS | Python CLI compiles; actual Windows launcher invoked. Other OS and Python versions NOT VERIFIED. |
| Architecture | PASS | M0 only; no scanning, AI invocation, policy evaluation or CI. |
| Data/content | PASS | Typed config, JSON Schema validation, SQL contract and FK checks. |
| Auth/backend | PASS / N/A | SQLite initialization/FK/concurrency tested; auth/network backend absent. |
| AI/cost | N/A | Only config syntax validated; no provider calls. |
| Offline/persistence | PASS | Local operation, idempotency, rollback and DB failures tested. |
| Accessibility/UX | PASS / N/A | Human-readable CLI and JSON checked; no graphical UI. |
| Secrets/privacy | PASS | Changed text reviewed; no credentials, no remote data transfer, no config value echo. |
| Reliability | PASS | Negative paths, bounded SQLite lock timeout, concurrent bootstrap. |
| Diff review | PASS / WARN | Snapshot diff preserves existing docs except rename and M0 status; Git diff unavailable. |

Overall: VERIFIED WITH WARNINGS.

## Known limits and next allowed step

Semgrep and Trivy are not installed; both are explicitly disabled and optional in
the bootstrap config, so availability is WARN. No scan was run or reported PASS.
M1 must enable/install its scanner profiles before real scanning. Missing enabled
or mandatory binaries produce TOOL_ERROR. AI schemas, adapter contract and secret
playbook contents are not implemented in M0. Git initialization was not performed.
The initial MVP architecture checklist said those drafts existed, but only the
three top-level documents were present at startup.

M0 is complete. Next allowed milestone: M1 — Scanner Layer, only on a new user task.
Stop; do not implement M1 in this turn.
