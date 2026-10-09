# Shared memory and code intelligence

## Authority and minimum reading

Disk, Git and deterministic evidence determine current state. Memory records guide
navigation; they cannot declare current tests passed. Read current handoff, the
relevant durable project note/decisions and the active task, not every project diary.
Follow the user's actual memory location and live templates. No named vault, home
directory, plugin or commercial service is required by this portable skill.

If the user uses Obsidian: reread its current project/journal templates and guidance
before writes, update the existing main note/journal and applicable decision/index,
preserve other authors/history, then reread to verify links and content. Do not
silently create a replacement vault if the configured vault is inaccessible.
No secrets, live credentials or unrelated personal data in memories or handoff.

Keep one current handoff section, with previous snapshots clearly historical.
Record active writer and actual working tree. A stale handoff alone does not prove
another writer is stopped. Source/decision notes and task files may be versionable;
machine-specific configs, cache databases and credentials must remain local.

## Optional accelerators

| Available tool | Appropriate use | Failure fallback |
| --- | --- | --- |
| Serena | Initialize per tool manual, select correct project/language server, inspect symbols/references/diagnostics | Targeted local search/read |
| Zero-Waste MCP / AST index | Resolve symbol/paths, search a few candidates and read required line range | Targeted local search/read |
| GSD/intel/graphs | Consult existing scoped task plan or dependency map | Current source and task requirements |
| MemPalace/RAG | Retrieve relevant prior decisions/patterns when actually connected | Project notes and local handoff |
| Obsidian | Durable decisions and session history | Report unavailable memory; local handoff if authorized |

Installed skill files do not prove a live MCP server, working index, usable vault
or language server. Verify a real relevant query before saying connected. Serena
configuration "ready" is not enough: an empty language list can still fail symbol
extraction. After configuring Python, use a fresh/reloaded server and a real symbol
query. Do not claim an existing application's MCP session was hot-reloaded when
only a fresh standalone process was tested.

Indexes are potentially stale. Check resolved path, symbol signature and actual
source range against current files. Rebuild the affected source scope after edits.
Use per-project cache DB paths and limit indexing to source; avoid tools, vendor
trees, runtime evidence and unrelated repositories. An indexed file or symbol is
not security scan evidence. AST lookup does not establish vulnerability absence.

Optional external code tools inherit their client's permissions; this skill does
not provide a sandbox. Existing Zero-Waste read tools may accept arbitrary paths:
pass only allowed project source paths, do not describe CODEBASE_DIR as an access
control, and use client/OS permissions for enforcement. Do not execute its --setup
mode blindly: a generator that overwrites CLAUDE.md can destroy project instructions.

## Token-conscious operation

Read file/symbol overviews, then relevant function bodies and callers. Expand when
required to assess data flow or security behavior. Do not repeatedly read already
loaded unchanged files. Full-read startup contracts remain mandatory where required.
References are loaded on demand, not all at once. Save raw logs and show result,
run/SEC ID, severity/location and evidence paths; read details only for findings
being addressed. Never truncate away an error or delete original raw evidence.

One task should not invoke every available skill or create full codebase maps on
every edit. Reuse applicable up-to-date maps. Avoid unnecessary whole-repo rescans,
but run the entire required scope at release and whenever project policy demands it.

Token impact includes skill/context and tool output read by a model, plus AI
proposal/review calls. Scanner/test execution itself is not an LLM call. Cache hit
or byte reduction is not measured billed token savings. Use actual provider usage
when exposed; otherwise state usage unknown, without inventing a percentage.

## Quota and sequential handoff

At quota/timeout, record the completed work, failures, evidence paths, real Git
status, uncommitted changes, outstanding tests and the next action before stopping
when possible. Mark who is writing and what was not verified. Do not estimate quota
percentages if the client does not expose them.

Another agent may independently load the skill and continue the same project. It
checks the disk/Git/evidence and applicable instructions before writing, preserving
prior edits. This transfers recorded state, not hidden conversation or authentication.
Do not auto-start/message another agent or change its model without user authority.
No background quota watcher or automatic cross-app transition is provided.
