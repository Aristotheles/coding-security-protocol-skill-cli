# Gate input contract — version 1

`security gate --input .security/evidence/gate-context.json --event release --json`
evaluates existing records. M3 does not execute tests/runtime tools, approve reviews,
rotate secrets or close findings. M4 now provides the separate
[security verify collector and guarded core closure](verification-contract.md).

The input is a project-relative UTF-8 JSON file with exactly these fields:

```json
{
  "version": 1,
  "event": "release",
  "changed_files": [],
  "dependencies": {
    "lockfiles_changed": [], "added": [],
    "sbom_enabled": false, "sbom_diff": null
  },
  "patch": {
    "source": "none", "trust": "standard",
    "finding_ids": [], "rescan_run_id": null
  },
  "coverage": {"enabled": false, "before": null, "after": null},
  "evidence": {}
}
```

This intentionally empty evidence example **cannot PASS**. All four classes are
required: `static_scan`, `tests`, `security_rescan`, `runtime_verify`. Each record
has `type`, `state`, UTC `timestamp`, `source`, project `.security/`-contained
`raw_reference` and the file's SHA-256 `sha256`.

- Scanner PASS references its real `*-scan-report.json`. The gate reloads and
  validates the M1/M2 normalized/raw evidence and requires the completion timestamp
  to match. An arbitrary JSON object saying PASS is rejected. For AI patches,
  `security_rescan` must match `patch.rescan_run_id`; POL-002 checks actual normalized
  rescan fingerprints against canonical target IDs.
- Test/runtime PASS references a producer JSON receipt with matching `type`,
  `state`, `timestamp`, `source`, integer `exit_code: 0`, `timed_out: false`, and
  `completed: true`. The receipt must come from an actual deterministic execution;
  metadata alone cannot prove execution. M3 validates the local producer contract
  and file hash, not cryptographic authenticity. M4 collects actual execution receipts.
  Unit/CLI acceptance fixtures explicitly label simulated receipts TEST_ONLY.
- FAIL is failing evidence. Tool failure, missing records, timeout and incomplete
  receipts cannot yield success.
- Only runtime can be NOT_APPLICABLE, with a reason and matching
  `runtime_verify.mode: not_applicable` config.
- Only runtime can be WAIVED, with `approved_by`, `approved_at`, `reason`, and a
  matching referenced human waiver record (`actor_type: human`). The gate never
  creates or approves a waiver. AI-produced waiver records are rejected.

Changed files are portable relative paths (also valid for deleted files). Declared
lockfile changes must be in that list. The human/deterministic caller is responsible
for accurate diff/patch/coverage metadata; arbitrary remote AI output is not trusted
gate input. When coverage is enabled, finite before/after percentages are required.
AI patches require known SEC IDs and a validated rescan. Restricted trust requires
human review. M3 returns REVIEW_REQUIRED without manufacturing approval; it does
not implement a review-approval workflow or accepted-risk mutation.

Policies and selectors/actions/targets come from `security-policy.yml`; the gate
validates all seven condition structures. Missing/unreadable/malformed required
configuration returns CONFIG_ERROR/30. Invalid contracts return CONTRACT_ERROR/50;
I/O/index failure returns TOOL_ERROR/40. A deterministic BLOCK/10 takes precedence
over other missing evidence; otherwise incomplete evidence returns VERIFY_ERROR/60,
then review conditions return REVIEW_REQUIRED/20, otherwise PASS/0. Reports expose
both policy matches and evidence issues. No-input gate evaluates current canonical
blocks but never returns PASS or substitutes an empty successful evidence record.

POL-005 points to `.security/playbooks/secret-leak.md`. Open secrets or CLOSED
secrets lacking required human rotation confirmation block both merge and release.
Removing the value or getting a policy PASS does not close a finding.

POL-007 uses first_seen for HIGH/CRITICAL in configured OPEN/REOPENED states. The
highest reached 30/60/90 stage produces WARNING, never a hard block. Logical target
records have `QUEUED` status, `attempted_at: null`, `delivered_at: null`, `error: null`.
No email/Slack message was attempted or delivered. `(SEC ID, stage, target)` is
enqueued once, including across concurrent gates and index rebuilds; M3 has no sender
or automatic retry loop. The 90-day defaults include the security lead.

Reports are durable `.security/reports/<run_id>-gate-report.json` audit/outbox data;
the existing SQLite gate_runs and escalation_state tables are derived from them.
Canonical finding updates and index rebuilds preserve/replay those records. Keep
the reports when backing up runtime audit state; runtime reports are gitignored.
Error reports are retained but are not inserted into the decision-only gate_runs
schema as fake PASS/BLOCK. A report persisted before an index failure can rebuild
the index, while the failing invocation returns nonzero. Audit/index failures never
convert an incomplete check into PASS.
