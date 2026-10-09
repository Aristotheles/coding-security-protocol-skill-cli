# Agent integration and installation

## One skill, independent clients

The canonical package is `.agents/skills/coding-security-protocol/` in this
repository. Copy the complete directory, including references, to the desired
client's skill location. Do not install only SKILL.md with broken references.

| Client | Project location | User location |
| --- | --- | --- |
| Codex | `.agents/skills/coding-security-protocol/` | `~/.agents/skills/coding-security-protocol/` |
| Claude Code | `.claude/skills/coding-security-protocol/` | `~/.claude/skills/coding-security-protocol/` |
| Antigravity | `.agents/skills/coding-security-protocol/` | `~/.gemini/config/skills/coding-security-protocol/`; legacy IDE also supports `~/.gemini/antigravity/skills/` |

Codex invocation: `$coding-security-protocol`. Claude Code invocation:
`/coding-security-protocol`. Antigravity supports skill-name requests and current
surfaces expose `/coding-security-protocol`; verify your installed client's
discovery rather than claiming every old version supports identical commands.
Each client can apply the skill independently. No forced author/reviewer pairing.

Automatic skill selection is normally relevance-based, not guaranteed execution
on every prompt. For always-on use in an adopted project, add a short explicit
instruction to that client's project rules to load this skill for implementation,
fix and release tasks. Respect existing instructions; do not overwrite them.
An instruction is not a technical commit/merge lock or background security service.

## Optional code tools

Configure existing Serena with the proper project language, and a native executable
and argv for each client's MCP interface. Start/reload a session after edits.
For this Python project the operative `.serena/project.yml` field is
`language_servers: [python]`; an empty list cannot supply Python symbols. This is
local development configuration, not a scanner/policy change. Other projects need
their own languages. A fresh server with `--project PROJECT` can test the corrected
configuration while an already-open client may still need MCP refresh/restart.
Zero-Waste MCP uses its existing separate environment; it is not added to the core
requirements.txt. Use CODEBASE_DIR for intended source scope and CODEBASE_DB_PATH
for an independent ignored cache; these select scope, not security isolation.

Client configuration shapes differ: Codex `[mcp_servers.NAME]` in TOML,
Claude local/project MCP definitions, Antigravity `mcpServers` JSON. Preserve other
servers and user settings; back up before mutation. Never publish full user config,
auth/env values, tokens or machine-only paths. Do not approve every MCP operation
globally just to avoid prompts. Failed optional lookup falls back to local search.

## Verify and state the actual level

1. Parse the saved config and check only intended entries changed.
2. Start its exact native stdio command/environment in a bounded test process.
3. Initialize MCP and make a real symbol query/read; a file existing is insufficient.
4. Confirm complete skill/reference files in each discovery location.
5. Observe discovery/actual invocation in each application when available; record
   NOT VERIFIED when only disk/config/standalone MCP was tested.
6. Test sequential handoff against real Git/evidence when authorized. Do not call
   file installation an automatic quota switch, live AI review or end-to-end GUI test.

For an unrelated application, adopt/configure the deterministic CLI separately:
scanner profiles, test command, runtime environment, required schema/policy/structure
and local tools. Run doctor against that application. Installing the skill does
not install protocol binaries or copy a passing application's evidence.

## Official client references

- [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Claude MCP](https://code.claude.com/docs/en/mcp)
- [Antigravity skills](https://antigravity.google/docs/skills)
- [Antigravity MCP](https://antigravity.google/docs/mcp)
