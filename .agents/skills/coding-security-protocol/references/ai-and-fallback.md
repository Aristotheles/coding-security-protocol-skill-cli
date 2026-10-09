# AI proposals, review and fallback

Any interactive coding agent can use the deterministic CLI independently. That
does not make it a configured `security ai-patch` provider. These are separate
integrations: application skill discovery versus machine-readable AI transport.

## Registry and transport

Core commands must work with `ai.providers: []`. Read the installed
`docs/ai-adapter-contract.md` and schemas only when using AI proposals/review.
The shipped native Codex adapter has been live validated. Claude/Antigravity
interactive skill installation does not create a native proposal bridge.

Native `adapter: command` programs receive JSON on stdin and emit exactly one
schema-valid response on stdout. A free-text UI answer, stdout mixed with logs,
missing identity/hash or process exit zero alone is not a valid contract. External
bridges require real transport/auth/schema/diff acceptance; do not invent executable
names or label an untested registry entry connected. No credentials in versioned
config or memory. Respect selected model and trust without brand-based upgrades.

## Proposal and reviewer boundaries

`security ai-patch SEC-ID --root PROJECT --provider ID --json` is proposal-only.
The core bounds context, validates identities/schema/unified diff/paths, dry-runs
in an isolated copy and audits source/model/trust. Protected/config/policy files,
dependency manifests and unauthorized paths remain forbidden in remediation.
Sensitive secrets route to human review before sending; operators still minimize
and assess source context. Never upload unrelated source or secret-filled raw logs.

Every proposal exits REVIEW_REQUIRED/20. It does not apply the patch, execute
suggested tests or close a finding. Review/apply an authorized proposal separately,
then use the deterministic verification/policy flow. No AI-generated human approval.

Registry order/roles drive fallback. Each provider is called once per role. Quota,
timeout, invalid JSON/schema, wrong ID, malformed diff, protected paths or dry-run
failure advances to the next eligible provider. Exhaustion routes human_review.
Do not turn a failed chain into PASS or launch endless retries.

Independent advisory review binds finding, author/reviewer and exact SHA-256.
The author cannot review itself; duplicate native Codex aliases are not independent.
Operator IDs for command bridges are not cryptographic independence. Valid REJECT
or CONCERNS stops review and routes human review, without hunting for APPROVE.
An APPROVE cannot raise restricted trust or override required human review.
No reviewer produces explicit reduced confidence; applicable policy still governs.

The provider chain can fall back within one `ai-patch` request. It cannot transfer
an entire IDE conversation or automatically open Claude/Codex/Antigravity on quota.
Use the shared handoff procedure for interactive development sessions. Skill
discovery and native TEST_ONLY fixtures are not proof of live multi-provider review.
