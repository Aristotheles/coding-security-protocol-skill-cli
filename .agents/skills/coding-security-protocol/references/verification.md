# Evidence-based verification

## Resolve the project first

Use the adopted project's `security.config.yml`, `.security/policies/` and schemas.
The current CLI doctor requires the protocol's documented bootstrap structure;
copying a skill into an unrelated application does not make it adopted. If config
is absent/invalid or a tool is missing, retain the nonzero result, explain the
missing requirement and complete only authorized bootstrap. Never use `{}` fallback,
switch the target to a passing project or disable mandatory tools to get green.

Find existing tests and runtime adapters for the actual application stack. The
protocol repository's unittest command is not automatically appropriate for a
Flutter, Node, mobile or backend project. Do not overwrite application test config
or declare runtime not applicable purely because verification is inconvenient.

## Baseline and finding ingestion

Run `security doctor --root PROJECT --json`. Run `security scan --root PROJECT
--target TARGET --json`, retain its run ID and exit. TARGET must exist inside PROJECT.
Only if scanner execution succeeds, run `normalize` and `findings update` with that
same run ID, checking each exit. Normalize/store failure is not an empty clean scan.
Record raw paths and IDs without pasting all raw content into conversation.

Run-ID/SEC examples are placeholders to replace, not preexisting evidence. Never
seed historical CLOSED data in a real application to make acceptance appear valid.

## Verification by change type

| Change | Required handling |
| --- | --- |
| Documentation only | Check changed content, references, formatting and scope; runtime/tests may be N/A with a reason if project instructions permit |
| Implementation/fix | Run relevant tests, successful relevant rescan, applicable runtime, then policy |
| Auth/permissions/session/crypto or restricted AI provenance | Preserve human-review requirement in addition to deterministic checks |
| New dependency + lockfile | Human review; SBOM diff if configured; never silently weaken policy |
| Exposed secret | Revoke/rotate and incident requirements; removing the string alone cannot close |
| Release request | Complete project-wide mandatory release checks; a targeted scan cannot stand in for uncovered scope |

These are routing instructions, not new policies or waivers. Project requirements
win. FAST/FEATURE/RELEASE verification helpers may assist if installed, but their
labels do not substitute for required evidence.

## Fix and guard closure

Prepare the real project-relative gate context JSON, following the installed
`docs/gate-input.md`: event, changed files, dependency metadata, coverage if enabled,
patch source/trust, finding IDs and rescan references. Do not relabel restricted or
AI-origin patches human/standard. Caller-supplied prose is not a receipt.

After applying an authorized fix, `security verify SEC-ID --root PROJECT --target
TARGET --input .security/evidence/change.json --json` runs the configured collector.
Add `--close` only when guarded closure is intended and required human review is
satisfied. Without it verification does not close findings. Runtime runs before
policy, in test/staging. NOT_APPLICABLE and a valid human WAIVED record remain distinct
from runtime PASS; an AI must not manufacture approval fields.

The collector verifies evidence/source/control freshness. Retain provenance and
old attempts. A missing baseline, failed test/runtime, remaining finding, changed
source/tool/ignore configuration or mandatory scanner failure blocks closure.
No-input `gate --event release` evaluates current blocks but never yields PASS.

Canonical `.security/findings/SEC-XXXX.json` is authoritative; write through CLI.
SQLite enables FK on every connection and is derived. An index failure after JSON
commit remains TOOL_ERROR; if `canonical_written: true`, use `findings rebuild-index`
for recovery, not DB-only status editing. Reappearing fingerprints reuse SEC IDs.

## Failures and reporting

Keep original failing results. Correct the root cause within authorized scope and
rerun the failed check and affected dependent checks. Do not retry an unchanged
quota failure repeatedly or replace a crashed scanner with model opinion. Explain
NOT RUN/NOT VERIFIED precisely. Report the command, time, exit, evidence path,
remaining findings and human requirements. A successful scan means scanners ran;
a successful doctor means environment is valid; neither is release approval.
