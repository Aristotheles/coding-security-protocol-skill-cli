# Coding Security Protocol — M1 verification

2026-10-09 · Codex · Mode: FEATURE · Result: VERIFIED WITH WARNINGS

## Commands and observed results

- `python -m unittest discover -s tests -v`: 56 tests, OK, exit 0, 35.637 seconds.
- Real acceptance test invoked Semgrep 1.180.0 and Trivy 0.75.0 twice against the
  vulnerable fixture. Each tool reported its expected rule and at least one finding;
  distinct run IDs and unchanged raw-file hashes proved preservation.
- `security scan --target tests/fixtures/scanner-project --json`: exit 0;
  Semgrep FINDINGS=1, Trivy FINDINGS=1. Full report: `.agent/m1-scan.json`.
- `security doctor --json`: PASS, exit 0, both executables available.
  Report: `.agent/m1-doctor.json`.
- `python -m compileall -q security-cli tests`: exit 0.
- AST, read-only whitespace and no-shell execution checks: PASS.
- Trivy archive SHA-256 verified against the official release checksum file:
  `4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f`.

## M1 acceptance

- [x] Both scanner binaries actually run and produce raw SARIF.
- [x] Repeated runs preserve existing stdout/stderr and have distinct run IDs.
- [x] Findings are separate from execution failure.
- [x] Timeout stops the scanner process tree and preserves partial streams.
- [x] Missing enabled/mandatory scanners fail closed; optional disabled scanners skip.
- [x] Metadata contains command/profile, UTC timestamps, exit code and available version.
- [x] Argument arrays used; no shell=True; Windows batch scanner launchers rejected.

Negative tests include malformed config, invalid profile types, missing target
placeholder, no enabled scanners, disabled mandatory scanner, missing executable,
zero exit with invalid/empty evidence, SARIF unsuccessful execution, process exit 2,
timeout, project-root boundary and literal shell metacharacters.

## Changed files

`.gitignore`, `security.config.yml`, `security-cli/lib/doctor.py`, new
`security-cli/lib/scan.py`, new `.security/rules/python-security.yml`, new
`.security/rules/trivy-secret.yml`, new `tests/fixtures/scanner-project/dangerous.py`,
`tests/support.py`, `tests/integration/test_doctor_acceptance.py`, new
`tests/unit/test_scan.py`, new `tests/integration/test_scanner_acceptance.py`,
`README.md`, `MVP.md`, `.agent` reports/handoff. `.tools/trivy` is generated/ignored;
Semgrep was installed in uv's isolated tool environment. Core requirements and
lockfiles were not changed. Policy, schema, DB schema and finding state were not edited.

## Verification areas and limits

Repository/toolchain WARN: no `.git`, so Git status/diff unavailable. Targeted source
review used; no init/commit/push/deploy. Format/static analysis/tests/Windows CLI,
raw evidence integrity, config boundaries, privacy and persistence checks PASS.
No graphical UI/auth/payment/AI/network application changes: N/A. Other OS/Python
versions NOT VERIFIED. Scans use local rules and disable scanner telemetry/version
checks; raw output is retained locally. No AI calls, policy decisions or closure.

The initial Trivy fixture in a `.txt` file was excluded by the scanner; moving the
clearly fake marker into the scanned Python fixture produced the required finding.
The first scan report remains as historical evidence, not a completed acceptance.

The M1 Trivy profile enables secret scanning only. Dependency/CVE/container/IaC
scanning is not claimed. Full SARIF schema validation and normalization are M2;
M1 validates its evidence envelope and execution notifications. Coverage is a
bootstrap Python eval rule plus Trivy secret rules, not a comprehensive security audit.

M0 and M1 are marked complete. Next allowed step: M2 — Normalize / Dedup / Finding Store,
only when the user requests the next milestone. M2 has not started.
