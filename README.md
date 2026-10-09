# Coding Security Protocol v1.0

M0 implements environment validation through `security doctor`. M1 implements
Semgrep/Trivy execution and raw evidence with `security scan`. M2 implements
normalization, deduplication, canonical finding storage and index rebuild.
Policy evaluation, verified finding closure and AI adapters belong to later milestones.

## Run on Windows

Python 3.11 or newer within Python 3 is required. Install the parser/validator
dependencies with `python -m pip install -r requirements.txt`.

From the project root, in PowerShell:

```powershell
$env:PATH = "$PWD/security-cli;$env:PATH"
security doctor
security doctor --json
security scan --target tests/fixtures/scanner-project --json
python -m unittest discover -s tests -v
```

The PATH change applies only to the current session. On other platforms, invoke
`python security-cli/security doctor` from the project root. `--root <directory>`
selects a different project explicitly; the command never falls back to its own
repository when the selected project's configuration is missing.

## Doctor contract

Doctor checks Python, the M0 directory/file structure, JSON Schema draft 2020-12,
policy/config YAML, AI registry syntax, runtime verifier syntax, executable
availability, real runtime write/read/delete probes and SQLite initialization.
It enables foreign keys on every connection, initializes in a write transaction,
and checks the DB schema, integrity and foreign key consistency. Existing data is
preserved on repeated initialization; mismatched databases fail without migration.
Doctor validates schema definitions, not vulnerability findings or policy decisions.

Exit codes: `0 PASS`, `10 BLOCK`, `20 REVIEW_REQUIRED`, `30 CONFIG_ERROR`,
`40 TOOL_ERROR`, `50 CONTRACT_ERROR`, `60 VERIFY_ERROR`. Doctor uses 0, 30
and 40. Unimplemented milestone commands fail with 50; they cannot claim security success.
If config and tool checks both fail, config error takes precedence.

YAML uses a safe loader. Duplicate keys, merge keys, empty documents and unknown
config fields fail. JSON Schema references must be resolvable local JSON pointers;
doctor performs no remote schema fetches. Diagnostics do not echo config values.

## Bootstrap configuration

M0 used explicitly disabled/optional profiles. Both profiles are now enabled and
mandatory for M1. Missing disabled/optional binaries produce `WARN` in doctor.
Either `enabled: true` or `mandatory: true` makes a missing binary a TOOL_ERROR.
Doctor PASS alone never means a scan has completed.

AI `providers: []` is valid. A provider entry requires `id`, `adapter`, `enabled`
and `trust` (`standard` or `restricted`), with an optional `model`. IDs must be
unique. No provider is invoked in M0.

Runtime syntax accepts `mode: not_applicable`, or `mode: command` with a non-empty
`argv` array, positive `timeout_seconds` (maximum 3600) and `environment: test`
or `staging`. This validates configuration only; it produces no runtime evidence
and grants no waiver. Runtime execution is M4.

PyYAML safely parses YAML; jsonschema validates the JSON Schema standard and
typed config contract. These are the two dependencies; no framework is used.

The SQLite index is generated at `.security/security.db`. Canonical finding JSON
under `.security/findings/` remains versionable. AI schemas, adapter contract and
secret playbook contents are deferred to their corresponding milestones.

## M1 scanner contract

Install Semgrep in its isolated tool environment with
`uv tool install semgrep==1.180.0 --python 3.14`. The native Windows Trivy 0.75.0
binary is locally installed at `.tools/trivy/trivy.exe`; its release archive was
checked against the official SHA-256 list. `.tools/` is generated and ignored.
For another platform, configure its native Trivy executable path.

Each profile requires an executable, argv array with exactly one `{target}`,
positive timeout (maximum 3600 seconds), enabled/mandatory flags, SARIF output
and severity mapping. The target must exist within the project root. Commands use
argv lists and no shell. Windows batch launchers are rejected for scanner profiles.

Semgrep uses the local Python eval rule. Trivy uses built-in secret rules plus an
obviously fake fixture-secret rule. This profile enables secret scanning only;
dependency/CVE, container and IaC scanning are not claimed. Both scanners have
telemetry/version checks disabled in their profiles. No AI or hosted rule fetch
is required for these scans.

Raw stdout goes to `.security/raw/<tool>/<run_id>.sarif`, with separate stderr,
version stdout/stderr and a timestamped `.security/reports/<run_id>-scan-report.json`.
Every file is created exclusively and run IDs include UTC time and a UUID. Metadata
records the exact command, profile, version where available, timestamps, scanner
exit code, timeout and findings count. Timeouts stop the process tree and preserve
partial streams. Missing binaries, crashes, empty/malformed SARIF and failed SARIF
execution notifications produce TOOL_ERROR (40), even after a zero scanner exit.

Successful scanner execution returns 0 and `SCAN_COMPLETED`, with each scanner
marked `CLEAN` or `FINDINGS`. Findings are distinct from execution failure; exit 1
is accepted only with positive findings in valid SARIF. This is not a policy gate
decision or proof that a vulnerability was fixed. Disabled optional scanners are
`SKIPPED`; disabling every scanner or a mandatory scanner is CONFIG_ERROR (30).
M1 checks the evidence envelope and execution notifications without synthesizing
missing output. M2 now performs full SARIF schema validation and normalization.

Official references: [Semgrep CLI](https://docs.semgrep.dev/cli-reference),
[Trivy installation](https://www.trivy.dev/docs/latest/getting-started/installation/),
[Trivy custom secret rules](https://www.trivy.dev/docs/latest/guide/scanner/secret/).

## M2 normalize and finding store

Use the run ID returned by `security scan`:

```powershell
security normalize --run-id <run_id> --json
security findings update --run-id <run_id> --json
security findings show SEC-0001 --json
security findings rebuild-index --json
```

Normalization requires a successful scan report and raw evidence for every currently
enabled/mandatory scanner. Raw documents and merged SARIF are validated against the
bundled [OASIS SARIF 2.1.0 schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json).
Runtime schema retrieval is disabled. The unmodified schema is saved at
`security-cli/lib/sarif-2.1.0.schema.json`, SHA-256
`c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`.

Output is `.security/sarif/<run_id>-merged.sarif` and `<run_id>-normalized.json`.
Raw hashes, execution metadata, result counts and derived findings must agree;
update recomputes normalization and rejects altered artifacts. Missing/failed
scanners cannot produce an empty successful normalization. Repeating normalization
is idempotent and refuses conflicting existing output.

Fingerprint version 1 hashes category, portable project-relative location and code
context using canonical sorted JSON. It excludes tool, rule ID, line number,
severity, message and timestamps. Python code includes enclosing class/function
scope. If the source no longer matches the scanned snippet, rescan before normalizing.
Trivy secrets use scanner-masked context; the normalizer does not recover secrets
from source. Categories use explicit rule metadata, CWE tags and known bootstrap
rules. Unknown rules remain distinct rather than guessing equivalence. Cross-tool
matches merge only when this identity agrees, retaining all source references.

Canonical `.security/findings/SEC-XXXX.json` files are written atomically before
the SQLite index. `.security/findings/.sequence.json` preserves the ID high-water
mark and must remain versionable with canonical records. Interrupted writes can
leave ID gaps; IDs are never reused. An OS file lock coordinates normalization,
store writes, index rebuild and doctor DB initialization. Existing sightings are
idempotent by run ID; new observations append history and update last_seen.

SQLite is built from validated canonical JSON in a transaction with foreign keys
enabled, then replaced as a complete derived index. Invalid canonical data cannot
replace it. If index generation fails after JSON commit, the command returns 40
with `canonical_written: true`; use `findings rebuild-index` to recover. Show reads
canonical JSON, so a DB-only status mutation cannot override it.

M2 never closes findings or grants accepted risk. Absence on a later scan preserves
state. A prior historical CLOSED record reappearing after its closure timestamp
reuses the SEC ID, becomes REOPENED and sets regression=true. Out-of-order or
already-used evidence cannot masquerade as a new regression.

The user-approved plan correction puts the full, actually verified closure lifecycle
acceptance in M4, after M3/M4 controls exist. M2 regression tests seed explicitly
test-only historical CLOSED data; they do not claim real verification or closure.
Generated `__pycache__` directories are excluded from the local Trivy profile.
Real scans and examples target deliberately vulnerable, non-production fixtures.

## Repository scan exclusions

The root `.semgrepignore` keeps test fixtures scannable when the project is a Git
repository. It excludes generated runtime evidence, local tools, agent records and
Python bytecode caches. Semgrep otherwise applies its built-in exclusions when no
root ignore file exists; see [Semgrep targeting implementation](https://github.com/semgrep/semgrep/blob/develop/src/targeting/Semgrepignore.ml).
