# Deterministic verification — M4

`security verify --target <project-relative-path> --json` executes the configured
test and runtime adapters and real Semgrep/Trivy scans. It does not close findings
by default. To request core closure of an explicitly fixed finding:

```text
security verify SEC-0001 --target app --input .security/evidence/change.json --close --json
```

The input uses [gate context version 1](gate-input.md), declares accurate changed
files/dependency/patch/coverage metadata, and starts with `evidence: {}`. Injected
PASS records are rejected. The fix path must be declared and inside the scan target.
Without `--close`, PASS only means verification/gate succeeded; findings stay open.

The test adapter is `stack.tests` in security.config.yml:

```yaml
stack:
  tests:
    argv: [python, -m, unittest, discover, -s, tests/unit, -v]
    timeout_seconds: 120
```

The core does not assume Python, npm, pytest or Gradle. It executes the configured
native executable plus argv, with shell=False, timeout and descendant termination.
Windows .cmd/.bat shell launchers are rejected. A missing test command is CONFIG_ERROR.
Configure an actual test suite: exit 0 is the project's test adapter contract, not
independent proof of coverage or test quality.

Order: static scan → tests → relevant security rescan → runtime → policy → optional
core closure. Every step has a unique run/UTC record and raw reference/hash. Actual
stdout/stderr and command exit/timeout/completion receipts are preserved under
`.security/evidence/<run_id>/`. Runtime command mode permits test/staging only.
Explicit not_applicable config produces NOT_APPLICABLE with a reason, never PASS.

`--waiver .security/evidence/human-waiver.json` consumes an existing human waiver
with `actor_type: human`, approved_by, approved_at (UTC), reason. The collector never
creates human approval; missing fields, future timestamp or AI actor fail closed.
Waived evidence remains WAIVED. Local evidence/waiver files must come from trusted
operators; hashes detect drift but are not cryptographic human authentication.

Scanner error/timeout is not finding absence. Original scanners must be enabled and
the original finding location must be inside the target. Successful rescan findings,
including new risks, are stored as canonical JSON before policy evaluation. An
original fingerprint still present sets security_rescan FAIL. New critical/secret
risks remain visible to policy and can block closure.

Closure requires preserved original raw/report/normalized evidence. Original and
rescan tool versions, scanner profiles, local rule files, ignore configurations and
Git-root state must agree. If old pre-M4 evidence lacks these inputs, collect a fresh
baseline before fixing; the core does not invent missing provenance. Source/control
or evidence drift during verification or between gate and closure prevents closure.
Snapshots exclude generated tools/evidence/cache/build folders but always include
explicit changed files and targeted finding paths.

An immutable verification proof binds source/config/policy/canonical snapshots,
ordered evidence receipts, original scanner evidence and gate context. Policy first
evaluates a read-only prospective CLOSED view; it does not write that view into the
DB or JSON. Only a matching audited PASS allows core to atomically write CLOSED
canonical records, append proof/gate history and rebuild SQLite with FK/transactions.
No AI/direct DB mutation, standalone gate PASS or forged/missing proof can close.
Review-required changes stay open. Secret closure still requires human rotation
confirmation; secret regression clears the old confirmation and reuses the SEC ID.

Reports: `.security/reports/<run_id>-verify-report.json`. Test/rescan/runtime failure
returns VERIFY_ERROR/60, tool failures TOOL_ERROR/40, invalid contracts 50, config
errors 30. Completed evidence can still produce policy BLOCK/10 or REVIEW_REQUIRED/20.
Runtime failures are passed to the gate as failing evidence. An index failure after
valid canonical closure returns nonzero with canonical_written/closed_ids and can
recover through findings rebuild-index; it never reports overall PASS.

Keep runtime raw, normalized, verification and gate reports for closure/audit
recovery; they are gitignored and are not re-created as fake evidence after loss.
The full real-scanner acceptance test proves OPEN → same ID → actual test/runtime/
rescan/policy verified CLOSED → same ID REOPENED, with zero AI providers configured.
