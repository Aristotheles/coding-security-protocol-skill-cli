# Coding Security Protocol — AI adapter contract v1

M5 introduces proposal-only `security ai-patch SEC-0001 [--provider <id>]`.
JSON schemas: `schemas/ai-patch-request.schema.json` and
`schemas/ai-patch-response.schema.json`. Finding data is separately validated
against the canonical finding schema. No provider is required by doctor, scan,
findings, verify or gate. The default provider registry remains empty.

Requests contain the full canonical finding, up to 20 lines either side of its
location in one allowed existing file, original source hash, constraints, policy
IDs and remediation history. Total request/source size is bounded to 128 KiB.
Hardcoded-secret findings and likely credential/private-key context are refused
before invocation and routed to human review. Detection is conservative and not
a comprehensive secret classifier; operators must ensure the selected context is
safe to share. No unrelated repository contents are sent.

Responses require status (`PATCH_PROPOSED`, `CANNOT_FIX`, `NEEDS_HUMAN`), exact
finding_id, unified_diff, summary, changed_files, suggested_tests and patch_source
matching the configured provider ID. Extra fields, free text and JSON duplicate
keys/nonstandard constants are invalid. Nonproposals cannot contain a patch.
Suggested tests and prose are informational; the core never executes them.

Configure an optional provider in `security.config.yml`:

```yaml
ai:
  providers:
    - id: codex
      adapter: codex
      enabled: true
      trust: standard
      executable: codex
      timeout_seconds: 120
```

Model is optional: omit it to retain the locally selected Codex model. The native
Codex adapter uses saved CLI authentication, ignores user tools/hooks/rules, disables
shell/multi-agent/apps/web search, requests a read-only ephemeral run in an empty
temporary directory and structured JSON final output. The prompt instructs it to
use only supplied context. No project directory is supplied as its working root.
OS/process isolation is not a general security sandbox guarantee for arbitrary
trusted provider executables; native adapter programs are operator-controlled.
Custom Codex model-provider transport config is not silently substituted.
Only allowlisted environment keys are inherited; no arbitrary application secret
environment variables are forwarded. Environment key matching is case-insensitive
to retain Windows SYSTEMROOT, required by native networking. The effective selected
model is included in attempt/canonical proposal audit. CLI auth remains external,
never stored here.

Adapter `command` accepts executable, optional argv list and timeout_seconds. Its
native process receives request JSON on stdin and must emit a single response JSON
on stdout. Exit nonzero is tool_error (quota/rate-limit diagnostic is classified
as quota); timeout kills descendants. No shell scripts/interpolation. This protocol
allows externally maintained provider bridges and deterministic TEST_ONLY fixtures.

Enabled registry order drives patch and M6 independent review fallback. Each provider is called
once per role, no retries; --provider selects only the patch author. Reviewers still
come from the enabled registry, excluding the author. Optional roles: [patch],
[review] or [patch, review]; omitted roles support both for backward compatibility. Quota, unavailable binary,
timeout, malformed JSON/schema, wrong finding/source, empty/invalid diff, protected
or unauthorized paths, dry-run failure and tool errors advance to the next provider.
If none validates, terminal_state is human_review and exit is REVIEW_REQUIRED/20.
Review uses the same native command/Codex transport with a separate schema and
review prompt; native command bridges must distinguish task: review requests.

Only existing allowed files may be modified by a proposed diff. Creation, deletion,
rename, mode changes, binary patches, symlinks, path traversal, alternate streams,
ambiguous Windows paths, control files and dependency manifests are rejected.
Changed files must agree with parsed hunks; maximum one file. Git apply --check
with whitespace errors enforced runs on an isolated copy, never the source tree.
No package installer or dependency mutation is run. The adapter does not infer
semantic dependency safety from arbitrary new source code; review and configured
dependency/coverage metadata remain required at deterministic policy evaluation.

Validated proposals preserve diff/source hashes, provider/model when known, trust,
timestamps and attempt results/fallback reasons in unique `.security/evidence/`
folders and `*-ai-patch-report.json`. Canonical finding becomes PATCH_PROPOSED with
history, then the derived SQLite index is rebuilt. Restricted trust always requires
human review; canonical provenance cannot be relabeled human/standard in gate input.
An index failure returns TOOL_ERROR and permits findings rebuild-index recovery.

Every proposal returns REVIEW_REQUIRED/20: no security PASS is claimed before
application and M4 verification. Source is not patched, tests are not auto-executed,
finding is never closed, approval/accepted risk is not created. To proceed, review
and apply the stored diff, then run the configured M4 tests/rescan/runtime/policy
workflow with accurate dependency/coverage/change metadata. A valid standard
proposal can close only through that core verification; restricted remains review.

Official Codex interface references (local installed help also checked):
[Non-interactive execution](https://learn.chatgpt.com/docs/non-interactive-mode) and
[configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

## M6 independent advisory review

After a valid patch dry-run, the core sends its bounded original patch request plus
unified diff, SEC ID, author ID and SHA-256 to eligible reviewers in registry order.
Schemas: `schemas/ai-review-request.schema.json` and
`schemas/ai-review-response.schema.json`. The nested patch request has already
passed its patch/finding schemas. Review output contains exactly status (APPROVE,
REJECT or CONCERNS), finding_id, patch_source, reviewer_source, patch_sha256 and
summary. Identity and hash must bind to the actual proposal. Advisory text is never
executed or accepted as tests/rescan/runtime/policy evidence.

The author cannot review itself. Two native Codex entries are also excluded from
reviewing one another. Command bridges use operator-assigned provider IDs; operators
must ensure distinct IDs represent independent providers, not aliases to the same
model/service. Independence is not cryptographically authenticated. Different brands
or agreeing opinions do not upgrade trust.

Invalid contract, missing/wrong ID/hash/source, quota, timeout and tool failure try
the next eligible reviewer once. A valid REJECT or CONCERNS stops review and routes
to human_review; the core never hunts another provider for an APPROVE. A restricted
reviewer cannot supply final human approval. Attempts, effective model/trust/raw
response and binding references are preserved, with the review in canonical proposal
history before the derived index.

No independent valid reviewer yields explicit review terminal human_review and
REDUCED confidence. Human review is mandatory for a restricted author, sensitive
paths from POL-006, valid REJECT/CONCERNS, a restricted reviewer or unsafe/oversized
review context. On ordinary standard-trust paths reduced confidence is explicitly
recorded; it alone does not create a new mandatory approval rule. Sensitive-looking
secrets in the proposed diff are refused before forwarding to another provider.

Proposal trust remains the author's configured trust. Approval never upgrades a
restricted patch. Canonical human_review_required prevents caller metadata from
bypassing required review during M4 gate/closure; AI_REVIEW is a control report label,
not an additional YAML policy. POL-001..007 remain unchanged. The existing human
approval workflow is not implemented here, so no human approval is manufactured.
Every ai-patch still exits REVIEW_REQUIRED/20. Source is unchanged, no finding closes.
Even independently approved proposals require actual M4 deterministic verification.
Empty/removed providers preserve scanner/gate/manual remediation operation.
