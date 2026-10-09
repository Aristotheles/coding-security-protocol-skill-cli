<a id="top"></a>
# Coding Security Protocol v1.0

> **Türkçe tam dokümantasyon: [README.tr.md](README.tr.md)** · [English documentation](#english)

**A security protocol and agent skill for use during software development with Claude Code, Codex and Antigravity.**
**Claude Code, Codex ve Antigravity ile kodlama sırasında kullanılan bir güvenlik protokolü ve ajan skill’i.**

[English](#english) · [Türkçe](#turkce) · [Support / Destek](#support) · [Social / Sosyal medya](#social)

Developed by **Aristotheles / Vibe Hoca**.
**Aristotheles / Vibe Hoca** tarafından geliştirilmektedir.

---

<a id="english"></a>
## English

### Contents

- [Overview and architecture](#en-overview)
- [Installation and doctor](#en-installation)
- [CLI workflows](#en-workflows)
- [Configuration and policies](#en-config)
- [Optional AI providers](#en-ai)
- [Storage and lifecycle](#en-storage)
- [Tests, milestones and limitations](#en-status)
- [Documentation and contributions](#en-docs)
- [Agent skill and token cost](#en-skill)
- [Support](#support)

<a id="en-overview"></a>
### Overview and architecture

Coding Security Protocol is a security protocol for use while developing applications. It includes an agent skill that Claude Code, Codex and Antigravity can each use independently, and a Python CLI that runs security controls. The workflow checks code changes through scanning, tests, verification and policy evaluation.

The CLI turns scanner output into traceable security findings, evaluates explicit policies and requires deterministic verification before findings can close. It remains usable with **no AI providers configured**. Installing the skill alone does not configure a project or guarantee security; the required setup and verification still apply.

It provides environment diagnostics, real Semgrep/Trivy execution, retained raw evidence, SARIF normalization, stable fingerprints, deduplication and persistent `SEC-XXXX` IDs. YAML policy gates, tests/rescans/runtime evidence and optional AI proposals share auditable finding history.

**Status:** all seven MVP milestones, M0–M6, have completed implementation and acceptance. This is an implemented MVP with the limitations documented below. Deliberately vulnerable **test fixtures with fake credentials** remain in the repository. Findings and blocked gates against them are expected; they are not clean security results.

The core uses Python, PyYAML, jsonschema and standard-library SQLite. Scanners and optional AI CLIs run as external processes. No web framework or hosted AI SDK is required.

```text
Configuration + policy + schemas
             |
     doctor / environment checks
             |
      Semgrep + Trivy scans
             |
   raw evidence + normalized SARIF
             |
canonical finding JSON -> SQLite index
             |
     optional AI proposal + review
             |
     human review / patch application
             |
tests -> security rescan -> runtime verification
             |
     policy gate -> guarded core closure
```

The operator reviews and applies patches; AI does not apply them. Closure is a separate explicit core operation.

- **Fail closed:** bad config, malformed output, missing evidence and tool failures never become successful security checks.
- **Evidence before closure:** AI opinion, absence on a later scan and database-only status changes cannot close findings.
- **Canonical JSON first:** JSON is authoritative; SQLite is rebuildable. Every connection enables `PRAGMA foreign_keys = ON`.
- **Controlled subprocesses:** argv lists, timeouts and separate tool-error reporting; no `shell=True` scanner execution.
- **Protected contracts:** AI remediation cannot rewrite policies, schemas, agent instructions or config.
- **Human authority:** advisory AI approval cannot replace required human review, secret rotation confirmation or deterministic verification.
- **UTC audit:** operational events use UTC ISO-8601 timestamps.

<a id="en-installation"></a>
### Installation and doctor

| Component | Requirement / verified environment |
| --- | --- |
| Python | Python 3.11+ within Python 3; tested on Windows/Python 3.14.5 |
| Packages | `PyYAML==6.0.3`, `jsonschema==4.26.0` in `requirements.txt` |
| Semgrep | Native executable; verified with 1.180.0 |
| Trivy | Native executable; verified with 0.75.0 |
| Git | Required for AI diff dry-run validation |
| AI | Optional; default provider list is empty |

Verified versions describe the recorded acceptance environment, not a guarantee for every platform/version.

#### Windows / PowerShell

1. Obtain the repository and open PowerShell in its root. GitHub access currently requires permission.
2. Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

3. Install Semgrep and native Windows Trivy. Config expects `semgrep` on PATH and Trivy at `.tools/trivy/trivy.exe`. Binaries are local, Git-ignored and not distributed in this repository. Use the official [Semgrep documentation](https://semgrep.dev/docs/getting-started/) and [Trivy installation guide](https://www.trivy.dev/docs/latest/getting-started/installation/); verify published checksums for release downloads.
4. Add the launcher to this session and run the actual checks:

```powershell
$env:PATH = "$PWD/security-cli;$env:PATH"
security doctor
security doctor --json
```

PATH changes only for this session. Equivalent invocation without adding the launcher:

```powershell
python security-cli/security doctor --json
```

The Python entry point is available on other platforms; their acceptance has not been verified here. Adjust executable paths. Scanner/test/runtime adapters require native executables; `.cmd`/`.bat` adapter programs are rejected.

`--root` explicitly selects a project and defaults to the current directory. Missing config elsewhere never triggers fallback to this repository.

Doctor checks Python, required structure, valid `finding.schema.json`, parseable/valid policy and config YAML, AI registry/runtime verifier structures, scanner availability, actual runtime write/read/delete probes and SQLite initialization with foreign keys enabled.

Missing mandatory tools fail; optional availability follows config. Empty AI lists are valid. Doctor **does not scan for vulnerabilities**: its PASS means environment checks passed.

<a id="en-workflows"></a>
### CLI workflows

| Command | Purpose |
| --- | --- |
| `security doctor --json` | Validate environment/config |
| `security scan --target tests/fixtures/scanner-project --json` | Execute scanners, retain raw evidence |
| `security normalize --run-id RUN_ID --json` | Validate/normalize completed scan |
| `security findings update --run-id RUN_ID --json` | Deduplicate, write canonical JSON, update index |
| `security findings show SEC-0001 --json` | Read a canonical finding |
| `security findings rebuild-index --json` | Rebuild SQLite from canonical records |
| `security gate --event release --json` | Evaluate release blocks; no-input execution never returns PASS |
| `security verify --target tests/fixtures/scanner-project --json` | Collect tests/rescan/runtime evidence |
| `security ai-patch SEC-0001 --json` | Request an optional validated proposal |

Use your actual scan run ID and finding ID instead of illustrative `RUN_ID`/`SEC-0001`.

#### Scan → normalize → store

This example intentionally scans vulnerable fixtures. Stop on failure:

```powershell
$scan = security scan --target tests/fixtures/scanner-project --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Scanner execution failed" }
security normalize --run-id $scan.run_id --json
if ($LASTEXITCODE -ne 0) { throw "Normalization failed" }
security findings update --run-id $scan.run_id --json
if ($LASTEXITCODE -ne 0) { throw "Finding storage failed" }
```

`SCAN_COMPLETED` / exit `0` means scanner execution succeeded, **not that no vulnerabilities exist**. Inspect normalized findings and gate decisions.

#### Verify a fix and request closure

Review/apply the fix, then prepare accurate metadata using the [gate input contract](docs/gate-input.md). For an actual project with source target `app` and existing context `.security/evidence/change.json`:

```powershell
security verify SEC-0001 --target app --input .security/evidence/change.json --close --json
```

Replace illustrative paths/IDs with real project data. Verification runs configured tests, relevant rescan and runtime verification, then policy. `--close` requests guarded core closure; without it, findings do not close automatically. Missing evidence, failed tests, remaining findings and source/control drift prevent closure. See the [verification contract](docs/verification-contract.md).

Runtime `not_applicable` records `NOT_APPLICABLE`, never runtime PASS. Waivers must already contain required human approval data; AI cannot create approval.

#### Exit codes

| Code | Result |
| --- | --- |
| `0` | `PASS` / successful execution, interpreted in command context |
| `10` | `BLOCK` |
| `20` | `REVIEW_REQUIRED` |
| `30` | `CONFIG_ERROR` |
| `40` | `TOOL_ERROR` |
| `50` | `CONTRACT_ERROR` |
| `60` | `VERIFY_ERROR` |

Read the result alongside the exit code. A completed scan is not a clean gate; a proposal is not a verified fix.

<a id="en-config"></a>
### Configuration and policies

[security.config.yml](security.config.yml) defines executables, argv, timeouts, severity mappings, providers, runtime and tests. Local profiles use Python Semgrep rules and Trivy **secret scanning**. Both scanners are enabled/mandatory with 120-second timeouts and SARIF output.

AI providers default to empty; runtime is explicitly `not_applicable`. The configured verification test is `python -m unittest discover -s tests/unit -v`; full acceptance separately includes integration tests.

The profile does not enable dependency CVE, container or IaC scanning. Trivy's other capabilities are not evidence those checks ran.

YAML errors never silently become `{}`. Duplicate/merge keys, wrong types, unknown config fields and malformed required data are rejected. Schemas are validated locally without remote reference retrieval.

[security-policy.yml](.security/policies/security-policy.yml) defines:

| Policy | Behavior |
| --- | --- |
| `POL-001` | Block release with open/reopened critical findings |
| `POL-002` | AI-targeted finding must be resolved by relevant rescan before merge |
| `POL-003` | Human review for new dependencies with lockfile changes; SBOM diff when enabled |
| `POL-004` | Block configured coverage regression |
| `POL-005` | Block open secrets; require rotation confirmation |
| `POL-006` | Human review for security-critical paths |
| `POL-007` | Queue stale HIGH/CRITICAL escalations at 30/60/90 days |

Decisions/escalations are durable and auditable. Notifications remain **QUEUED**; delivery is not implemented. Gate PASS does not close findings. An input-free gate cannot claim PASS even without current blocks.

<a id="en-ai"></a>
### Optional AI providers

Core commands work with `ai.providers: []`. Merge this **partial configuration** into the existing file to add native Codex; do not replace the entire config:

```yaml
ai:
  providers:
    - id: codex
      adapter: codex
      enabled: true
      trust: standard
      executable: codex
      timeout_seconds: 120
      roles: [patch, review]
```

Codex must be installed/authenticated locally. Omit `model` to retain the local selection. With this sole provider, no separate independent reviewer exists. External native JSON bridges may use `adapter: command`; see the [AI adapter contract](docs/ai-adapter-contract.md).

```powershell
security ai-patch SEC-0001 --provider codex --json
```

The command validates the finding/response, dry-runs the unified diff on an isolated copy, records the proposal and returns **REVIEW_REQUIRED / 20**. It does not apply patches, execute suggested commands or close findings.

- Context is bounded to one allowed existing file; sensitive secret context routes to human review before invocation.
- Finding/provider identity, paths, diff parsing and dry-run are checked. Protected files, dependency manifests, creation/deletion and path traversal are rejected.
- Config order/roles drive fallback; roles are `patch`, `review` or both, defaulting to both. Each provider runs once per role. Invalid output triggers fallback even after exit `0`.
- Review binds finding, author, reviewer and exact diff hash. Authors cannot review their own proposals.
- `APPROVE`, `REJECT`, `CONCERNS` are advisory. Valid rejection/concerns route to human review without seeking another approval.
- No independent reviewer means reduced confidence; restricted trust and applicable human review remain enforced.
- Empty/exhausted chains explicitly route to human review; deterministic/manual remediation remains available.

M5 validated a live Codex proposal. M6 review/fallback acceptance used native **TEST_ONLY** bridges; two independent live AI providers have not been verified. Operator-configured identities are not cryptographic proof of independence. Adapter isolation is not a general sandbox guarantee for arbitrary executables.

<a id="en-storage"></a>
### Storage and lifecycle

```text
OPEN -> PATCH_PROPOSED -> VERIFYING -> CLOSED
                                      |
                    same vulnerability returns
                                      v
                                  REOPENED
```

`ACCEPTED_RISK` is also an approved state; a human risk-acceptance workflow is not implemented and cannot be simulated.

Stable fingerprints reuse the previous `SEC-XXXX` for the same vulnerability. Reappearance after verified closure records `REOPENED`, `regression: true` and new history. Absence from a scan cannot close findings.

| Path | Contents |
| --- | --- |
| `.security/findings/` | Canonical SEC JSON and ID sequence |
| `.security/policies/`, `.security/playbooks/` | Policies and incident guidance |
| `.security/rules/` | Local scanner rules |
| `.security/raw/`, `.security/sarif/` | Raw/normalized scanner evidence |
| `.security/evidence/`, `.security/reports/` | Verification, proposal and decision evidence |
| `.security/security.db` | Derived SQLite query/audit index |
| `schemas/` | Finding/AI schemas |
| `security-cli/` | CLI/core and SQL schema |

Canonical JSON and the ID sequence are versionable. Tools, runtime evidence and SQLite are Git-ignored. Back up real evidence; the database is not a substitute.

Writes use atomic canonical-file updates, a store lock and SQLite transactions. Index failure after JSON commit returns TOOL_ERROR with `canonical_written: true`. Recover with `security findings rebuild-index --json`; never fabricate missing evidence.

<a id="en-status"></a>
### Tests, milestones and limitations

Run the full unit/integration suite from the root with scanners installed:

```powershell
python -m unittest discover -s tests -v
```

Latest recorded full implementation verification, **2026-10-09**: **162 tests passed in 217.410 seconds**, including real Semgrep/Trivy lifecycle checks. This dated evidence does not imply automatic CI on each checkout.

| Milestone | Implementation and acceptance |
| --- | --- |
| M0 — Bootstrap & Doctor | Verified |
| M1 — Scanner Layer | Verified |
| M2 — Normalize / Dedup / Finding Store | Verified |
| M3 — Policy Engine | Verified |
| M4 — Verification Layer | Verified |
| M5 — AI Adapter | Verified; live Codex proposal |
| M6 — Provider Fallback / Review | Verified; native TEST_ONLY bridges |

See [MVP progress](MVP.md#42-progress) and [final Git review evidence](.agent/FINAL-GIT-REVIEW.md) and [skill integration verification](.agent/SKILL-INTEGRATION-VERIFICATION.md).

Known boundaries:

- Deliberate fixture findings remain OPEN; recorded root release gate BLOCK/10 and unresolved verification VERIFY_ERROR/60.
- No automatic AI patch application, PR creation, merge or deploy.
- No human approval/risk-acceptance workflow, automated credential rotation or actual notification delivery.
- No GitHub Actions, full dashboard or CodeQL/ZAP/MobSF integration.
- Default profiles do not scan CVEs/containers/IaC or produce full SBOMs.
- Other OS/Python versions and two independent live reviewers are not acceptance-tested.
- MVP acceptance is not production release security approval.

<a id="en-docs"></a>
### Documentation and contributions

| Document | Purpose |
| --- | --- |
| [MVP.md](MVP.md) | Approved scope and acceptance |
| [SECURITY_AGENT.md](SECURITY_AGENT.md) | Security invariants |
| [AGENTS.md](AGENTS.md) | Agent rules |
| [Gate input contract](docs/gate-input.md) | Change context/policy evidence |
| [Verification contract](docs/verification-contract.md) | Verification, receipts, closure |
| [AI adapter contract](docs/ai-adapter-contract.md) | Proposal/review/fallback contracts |
| [Finding schema](schemas/finding.schema.json) | Canonical validation |
| [Secret leak playbook](.security/playbooks/secret-leak.md) | Response/rotation requirements |

Keep patches small/scoped, include meaningful implementation tests, preserve fail-closed behavior and use only fake credentials in fixtures. Protected contracts require an explicit human task. Avoid opportunistic dependencies/architecture changes.

**License:** no `LICENSE` file currently exists. This README does not assign a license.

---

<a id="en-skill"></a>
### Using the protocol as an agent skill

The detailed, portable [coding-security-protocol skill](.agents/skills/coding-security-protocol/SKILL.md) is included in this repository. Codex, Claude Code and Antigravity can each use it independently. It preserves the existing CLI and security contracts; another AI agent is never required for core operation.

| Client | Use in this checkout | Install for other projects |
| --- | --- | --- |
| Codex | `$coding-security-protocol` | Copy the complete skill folder to `~/.agents/skills/coding-security-protocol/` |
| Claude Code | `/coding-security-protocol` | Copy the complete folder to `~/.claude/skills/coding-security-protocol/` |
| Antigravity | Ask to use `coding-security-protocol`; current surfaces also support `/coding-security-protocol` | Copy the complete folder to `~/.gemini/config/skills/coding-security-protocol/`; legacy IDE supports `~/.gemini/antigravity/skills/` |

The canonical package lives in `.agents/skills/coding-security-protocol/`. A small `.claude/skills/` entry points Claude to it. User installations must contain the full package, including references. Project guidance connects the workflow through AGENTS.md, CLAUDE.md and GEMINI.md. Discovery/reload depends on the client version; file installation is not proof of a live application invocation.

Example request: **“Develop this feature using Coding Security Protocol; run applicable deterministic checks and leave a verified handoff.”** The agent runs the required commands and reports actual evidence. Skill selection is relevance-based; an adopted project's rules can explicitly require it. This is not an enforced commit hook or background service.

For another application, adopt the protocol structure, scanner/test/runtime configuration and policies separately, then run doctor against that application's root. Installing the skill alone does not bootstrap the CLI or make an unrelated application pass doctor. Do not run against this repository as a substitute.

#### Detailed guidance loaded when needed

- [Verification](.agents/skills/coding-security-protocol/references/verification.md): actual baseline, tests/rescan/runtime/policy, guarded closure and error handling.
- [Memory and tools](.agents/skills/coding-security-protocol/references/memory-and-tools.md): optional Serena/Zero-Waste/GSD/Obsidian, source freshness, bounded context and sequential handoff.
- [AI and fallback](.agents/skills/coding-security-protocol/references/ai-and-fallback.md): proposal-only transport, reviewer separation, quota failure and interactive-session distinctions.
- [Agent integration](.agents/skills/coding-security-protocol/references/agent-integration.md): complete installation, MCP configuration and verification levels.

#### Token cost and optional accelerators

Semgrep, Trivy and test processes are not LLM calls. Skill/context read by a model, tool outputs, AI proposal calls and independent AI review do consume model context/usage. The detailed references are read on demand; large raw outputs stay on disk with concise results shown in chat. Symbol lookup and bounded reads may reduce unnecessary input, but **no billed-token savings percentage has been measured**. Required evidence is never skipped to save tokens.

Serena's Python symbol lookup and the existing Zero-Waste MCP's real index/symbol/read tools were verified in fresh local stdio sessions. Per-client MCP settings and machine paths remain local; the core acquires no MCP dependency. These indexes help navigation, not security approval. They can be stale and their source-scope settings are not a sandbox. Optional lookup failure falls back to targeted local search.

Shared `.agent/HANDOFF.md` and authorized durable project memory let another agent resume recorded work after quota exhaustion. The receiving agent checks current Git and evidence. **No automatic cross-app launch, hidden conversation transfer or quota watcher is installed.** The installed interactive skills also do not create native Claude/Antigravity `ai-patch` providers: those require separately validated JSON command bridges. Live three-client UI invocation and automatic session switching are not claimed.

Official installation sources: [Codex](https://learn.chatgpt.com/docs/build-skills), [Claude Code](https://code.claude.com/docs/en/skills), [Antigravity](https://antigravity.google/docs/skills).

---

<a id="turkce"></a>
## Türkçe

### İçindekiler

- [Genel bakış ve mimari](#tr-overview)
- [Kurulum ve doctor](#tr-installation)
- [CLI akışları](#tr-workflows)
- [Yapılandırma ve politikalar](#tr-config)
- [İsteğe bağlı AI sağlayıcıları](#tr-ai)
- [Saklama ve yaşam döngüsü](#tr-storage)
- [Testler, aşamalar ve mevcut sınırlar](#tr-status)
- [Belgeler ve katkı](#tr-docs)
- [Ajan skill’i ve token maliyeti](#tr-skill)
- [Destek](#support)

<a id="tr-overview"></a>
### Genel bakış ve mimari

Coding Security Protocol, uygulama geliştirirken kullanılan bir güvenlik protokolüdür. Claude Code, Codex ve Antigravity’nin her birinin bağımsız kullanabileceği bir ajan skill’i ve güvenlik kontrollerini çalıştıran Python CLI aracı sunar. İş akışı, kod değişikliklerini tarama, test, doğrulama ve politika kontrolleriyle denetler.

CLI, tarayıcı çıktısını izlenebilir güvenlik bulgusuna dönüştürür, açık politikaları değerlendirir ve bulgu kapanışından önce deterministik doğrulama ister. **AI sağlayıcısı tanımlanmadan** kullanılabilir. Skill’i yüklemek tek başına projeyi yapılandırmaz veya güvenliği garanti etmez; gerekli kurulum ve doğrulamalar yine uygulanır.

Ortam tanılama, gerçek Semgrep/Trivy çalıştırma, ham kanıt saklama, SARIF normalizasyonu, kararlı parmak izi, tekrarları birleştirme ve kalıcı `SEC-XXXX` kimlikleri sunar. YAML kapıları, test/tekrar tarama/runtime kanıtları ve AI önerileri denetlenebilir bulgu geçmişine bağlanır.

**Durum:** yedi MVP aşamasının, M0–M6'nın, uygulama ve kabulü tamamlandı. Aşağıdaki sınırları olan uygulanmış bir MVP'dir. Depoda bilerek açık bırakılmış, **sahte kimlik bilgili test örnekleri** vardır. Bunların bulgu ve engelleme üretmesi beklenir; temiz güvenlik sonucu değildir.

Çekirdek Python, PyYAML, jsonschema ve standart SQLite kullanır. Tarayıcı ve AI CLI araçları dış süreçtir. Web framework veya barındırılan AI SDK bağımlılığı yoktur.

```text
Yapılandırma + politika + şemalar
             |
       doctor / ortam kontrolü
             |
      Semgrep + Trivy taraması
             |
    ham kanıt + normalize SARIF
             |
kanonik bulgu JSON -> SQLite indeksi
             |
     isteğe bağlı AI önerisi + inceleme
             |
     insan incelemesi / yama uygulaması
             |
testler -> tekrar tarama -> runtime doğrulaması
             |
   politika kapısı -> kontrollü çekirdek kapanışı
```

Yamayı operatör inceler ve uygular; AI uygulamaz. Kapanış ayrı ve açıkça istenen çekirdek işlemidir.

- **Fail-closed:** bozuk config, hatalı çıktı, eksik kanıt ve araç hatası başarılı güvenlik kontrolüne dönüştürülmez.
- **Kapanıştan önce kanıt:** AI görüşü, sonraki taramada görünmeme veya yalnız DB durumunu değiştirme bulguyu kapatamaz.
- **Önce kanonik JSON:** JSON esas kaynaktır; SQLite yeniden kurulabilir. Her bağlantıda `PRAGMA foreign_keys = ON` uygulanır.
- **Kontrollü süreç:** argv listesi, timeout ve ayrı araç hatası; tarayıcıda `shell=True` yoktur.
- **Korunan sözleşme:** AI politika, şema, ajan talimatı veya config'i değiştiremez.
- **İnsan yetkisi:** AI danışman onayı; zorunlu insan incelemesi, sır rotasyonu teyidi veya deterministik doğrulama yerine geçmez.
- **UTC denetim:** operasyon zamanları UTC ISO-8601 biçimindedir.

<a id="tr-installation"></a>
### Kurulum ve doctor

| Bileşen | Gereksinim / doğrulanan ortam |
| --- | --- |
| Python | Python 3 içinde 3.11+; Windows/Python 3.14.5 ile test edildi |
| Paketler | `requirements.txt`: `PyYAML==6.0.3`, `jsonschema==4.26.0` |
| Semgrep | Native executable; 1.180.0 ile doğrulandı |
| Trivy | Native executable; 0.75.0 ile doğrulandı |
| Git | AI diff dry-run doğrulaması için gerekli |
| AI | İsteğe bağlı; varsayılan liste boş |

Doğrulanan sürümler kayıtlı kabul ortamını gösterir; tüm platform/sürümler için garanti değildir.

#### Windows / PowerShell

1. Depoyu edinip kökünde PowerShell açın. GitHub erişimi şu anda yetki gerektirir.
2. Python bağımlılıklarını kurun:

```powershell
python -m pip install -r requirements.txt
```

3. Semgrep ve native Windows Trivy kurun. Config, PATH'te `semgrep` ve `.tools/trivy/trivy.exe` bekler. Binary'ler yereldir, Git dışındadır ve depoda dağıtılmaz. Resmî [Semgrep belgelerini](https://semgrep.dev/docs/getting-started/) ve [Trivy rehberini](https://www.trivy.dev/docs/latest/getting-started/installation/) kullanın; release indirmelerinin yayımlanan checksum değerlerini doğrulayın.
4. Başlatıcıyı oturuma ekleyip gerçek kontrolü çalıştırın:

```powershell
$env:PATH = "$PWD/security-cli;$env:PATH"
security doctor
security doctor --json
```

PATH yalnız bu oturumda değişir. Başlatıcıyı eklemeden eşdeğer çağrı:

```powershell
python security-cli/security doctor --json
```

Python giriş noktası diğer platformlarda da vardır; kabulü burada doğrulanmadı. Executable yollarını ayarlayın. Tarayıcı/test/runtime adapter'ları native executable ister; `.cmd`/`.bat` adapter'ları reddedilir.

`--root` projeyi açıkça seçer; varsayılan mevcut klasördür. Başka projede config eksikse bu depoya geri dönmez.

Doctor; Python, zorunlu yapı, geçerli `finding.schema.json`, ayrıştırılabilir/geçerli politika/config YAML'ı, AI kayıt listesi/runtime verifier yapısı, tarayıcı erişilebilirliği, gerçek runtime yazma/okuma/silme denemeleri ve foreign key açık SQLite initialization kontrolü yapar.

Zorunlu araç eksikse başarısızdır; isteğe bağlı araç config'e göre değerlendirilir. Boş AI listesi geçerlidir. Doctor **açık taramaz**; PASS yalnız ortam kontrolüdür.

<a id="tr-workflows"></a>
### CLI akışları

| Komut | Amaç |
| --- | --- |
| `security doctor --json` | Ortam/config doğrula |
| `security scan --target tests/fixtures/scanner-project --json` | Tarayıcı çalıştır, ham kanıt sakla |
| `security normalize --run-id RUN_ID --json` | Tamamlanan taramayı doğrula/normalize et |
| `security findings update --run-id RUN_ID --json` | Tekrar birleştir, kanonik JSON yaz, indeks güncelle |
| `security findings show SEC-0001 --json` | Kanonik bulgu oku |
| `security findings rebuild-index --json` | SQLite'ı kanonik kayıttan kur |
| `security gate --event release --json` | Release engeli değerlendir; girdisiz PASS yok |
| `security verify --target tests/fixtures/scanner-project --json` | Test/tekrar tarama/runtime kanıtı topla |
| `security ai-patch SEC-0001 --json` | İsteğe bağlı doğrulanmış öneri iste |

Örnek `RUN_ID`/`SEC-0001` yerine gerçek run ID ve bulgu kimliğinizi kullanın.

#### Tarama → normalizasyon → saklama

Örnek bilerek açık içeren testleri tarar. Hata varsa durun:

```powershell
$scan = security scan --target tests/fixtures/scanner-project --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Scanner execution failed" }
security normalize --run-id $scan.run_id --json
if ($LASTEXITCODE -ne 0) { throw "Normalization failed" }
security findings update --run-id $scan.run_id --json
if ($LASTEXITCODE -ne 0) { throw "Finding storage failed" }
```

`SCAN_COMPLETED` / exit `0`, tarayıcının çalıştığını gösterir; **hiç açık bulunmadığını göstermez**. Normalize bulgu ve gate kararını inceleyin.

#### Düzeltmeyi doğrulama ve kapanış isteme

Düzeltmeyi inceleyip uygulayın, [gate girdi sözleşmesine](docs/gate-input.md) uygun gerçek metadata hazırlayın. Kaynak hedefi `app`, mevcut bağlamı `.security/evidence/change.json` olan projede:

```powershell
security verify SEC-0001 --target app --input .security/evidence/change.json --close --json
```

Örnek yollar/ID yerine gerçek verinizi kullanın. Testler, ilgili tekrar tarama ve runtime doğrulamasından sonra politika değerlendirilir. `--close` kontrollü kapanış ister; bu seçenek olmadan otomatik kapanış yoktur. Eksik kanıt, başarısız test, kalan bulgu veya kaynak/kontrol değişimi kapanışı engeller. [Doğrulama sözleşmesine](docs/verification-contract.md) bakın.

Runtime `not_applicable`, `NOT_APPLICABLE` kaydedilir; runtime PASS değildir. Waiver gerekli insan onayını önceden içermelidir; AI onay oluşturamaz.

#### Çıkış kodları

| Kod | Sonuç |
| --- | --- |
| `0` | `PASS` / komut bağlamına göre başarılı işlem |
| `10` | `BLOCK` |
| `20` | `REVIEW_REQUIRED` |
| `30` | `CONFIG_ERROR` |
| `40` | `TOOL_ERROR` |
| `50` | `CONTRACT_ERROR` |
| `60` | `VERIFY_ERROR` |

Kodla sonuç alanını birlikte okuyun. Tamamlanan tarama temiz kapı değildir; öneri doğrulanmış düzeltme değildir.

<a id="tr-config"></a>
### Yapılandırma ve politikalar

[security.config.yml](security.config.yml); executable, argv, timeout, severity eşlemesi, sağlayıcı, runtime ve testleri tanımlar. Yerel Python Semgrep kuralları ve Trivy **sır taraması** kullanılır. İki tarayıcı enabled/mandatory, timeout 120 saniye, çıktı SARIF'tir.

AI listesi boş; runtime açıkça `not_applicable`. Yapılandırılmış doğrulama testi `python -m unittest discover -s tests/unit -v`; tam kabul ayrıca integration testlerini içerir.

Profil bağımlılık CVE, container veya IaC taramasını açmaz. Trivy'nin diğer yetenekleri bunların çalıştığının kanıtı değildir.

YAML hatası sessizce `{}` olmaz. Tekrarlı/merge anahtarları, yanlış tip, bilinmeyen config alanı ve bozuk zorunlu veri reddedilir. Şemalar uzak referans indirmeden yerel doğrulanır.

[security-policy.yml](.security/policies/security-policy.yml):

| Politika | Davranış |
| --- | --- |
| `POL-001` | OPEN/REOPENED kritik bulguda release engelle |
| `POL-002` | AI hedefli bulgunun merge öncesi ilgili tekrar taramada giderilmesini iste |
| `POL-003` | Lockfile + yeni bağımlılıkta insan incelemesi; etkinse SBOM diff |
| `POL-004` | Yapılandırılan coverage gerilemesini engelle |
| `POL-005` | Açık sır engelle; rotasyon teyidi iste |
| `POL-006` | Güvenlik açısından kritik yollarda insan incelemesi |
| `POL-007` | Yaşlanan HIGH/CRITICAL bulguyu 30/60/90 günde eskalasyon kuyruğuna al |

Kararlar/eskalasyon kalıcı ve denetlenebilirdir. Bildirim **QUEUED** kalır; gönderim uygulanmadı. Gate PASS bulguyu kapatmaz. Girdisiz gate mevcut engel olmasa da PASS iddia edemez.

<a id="tr-ai"></a>
### İsteğe bağlı AI sağlayıcıları

Çekirdek `ai.providers: []` ile çalışır. Native Codex için bu **kısmi config'i** mevcut dosyaya birleştirin; tüm dosyanın yerine koymayın:

```yaml
ai:
  providers:
    - id: codex
      adapter: codex
      enabled: true
      trust: standard
      executable: codex
      timeout_seconds: 120
      roles: [patch, review]
```

Codex yerelde kurulu ve oturum açılmış olmalıdır. `model` yoksa yerel seçim korunur. Tek sağlayıcıyla ayrı bağımsız reviewer yoktur. Dış native JSON köprüleri `adapter: command` kullanabilir; [AI adapter sözleşmesine](docs/ai-adapter-contract.md) bakın.

```powershell
security ai-patch SEC-0001 --provider codex --json
```

Bulgu/yanıt doğrulanır, unified diff yalıtılmış kopyada dry-run yapılır, öneri kaydedilir ve **REVIEW_REQUIRED / 20** döner. Yama uygulamaz, önerilen komutları çalıştırmaz veya bulguyu kapatmaz.

- Bağlam mevcut izinli tek dosyayla sınırlıdır; hassas sır çağrı öncesi insan incelemesine gider.
- Kimlik, yollar, diff ve dry-run kontrol edilir. Korunan dosya, bağımlılık manifesti, dosya oluşturma/silme ve path traversal reddedilir.
- Config sırası/roller fallback belirler: `patch`, `review` veya ikisi; varsayılan ikisidir. Sağlayıcı rol başına bir kez çalışır. Exit `0` olsa da bozuk çıktı fallback başlatır.
- İnceleme bulgu, yazar, reviewer ve tam diff hash'ine bağlıdır. Yazar kendi önerisini inceleyemez.
- `APPROVE`, `REJECT`, `CONCERNS` danışman sonuçlarıdır. Geçerli ret/kaygı sonrası başka onay aranmadan insan incelemesine gidilir.
- Bağımsız reviewer yoksa güven azalır; restricted trust ve geçerli insan incelemesi korunur.
- Boş/tükenen zincir insan incelemesine gider; deterministik/elle düzeltme kullanılabilir.

M5 gerçek Codex önerisini doğruladı. M6 review/fallback kabulü native **TEST_ONLY** köprü kullandı; iki bağımsız canlı AI doğrulanmadı. Operatör kimliği bağımsızlığın kriptografik kanıtı değildir. Adapter yalıtımı rastgele executable için genel sandbox garantisi değildir.

<a id="tr-storage"></a>
### Saklama ve yaşam döngüsü

```text
OPEN -> PATCH_PROPOSED -> VERIFYING -> CLOSED
                                      |
                         aynı açık tekrar oluşur
                                      v
                                  REOPENED
```

`ACCEPTED_RISK` da onaylı durumdur; insan risk kabulü akışı uygulanmadı ve taklit edilemez.

Kararlı parmak izi aynı açıkta önceki `SEC-XXXX` kimliğini kullanır. Doğrulanmış kapanış sonrası tekrar görülürse `REOPENED`, `regression: true` ve geçmiş kaydedilir. Tarama yokluğu bulguyu kapatmaz.

| Yol | İçerik |
| --- | --- |
| `.security/findings/` | Kanonik SEC JSON ve ID sırası |
| `.security/policies/`, `.security/playbooks/` | Politika ve olay rehberi |
| `.security/rules/` | Yerel tarayıcı kuralları |
| `.security/raw/`, `.security/sarif/` | Ham/normalize tarayıcı kanıtı |
| `.security/evidence/`, `.security/reports/` | Doğrulama, öneri, karar kanıtı |
| `.security/security.db` | Türetilmiş SQLite sorgu/denetim indeksi |
| `schemas/` | Bulgu/AI şemaları |
| `security-cli/` | CLI/çekirdek ve SQL şeması |

Kanonik JSON/ID sırası sürümlenebilir. Araçlar, runtime kanıtı ve SQLite Git dışıdır. Gerçek kanıtları yedekleyin; DB bunların yerine geçmez.

Atomik kanonik yazım, store kilidi ve SQLite transaction kullanılır. JSON sonrası indeks hatası TOOL_ERROR ve `canonical_written: true` döndürür. `security findings rebuild-index --json` ile kurtarın; eksik kanıt üretmiş gibi yapmayın.

<a id="tr-status"></a>
### Testler, aşamalar ve mevcut sınırlar

Tarayıcılar kurulu durumda kökten tam unit/integration paketini çalıştırın:

```powershell
python -m unittest discover -s tests -v
```

**2026-10-09** son tam uygulama doğrulamasında **162 test, 217.410 saniyede** geçti; gerçek Semgrep/Trivy yaşam döngüsü dahildir. Tarihli kanıt her checkout'ta otomatik CI anlamına gelmez.

| Aşama | Uygulama ve kabul |
| --- | --- |
| M0 — Bootstrap & Doctor | Doğrulandı |
| M1 — Scanner Layer | Doğrulandı |
| M2 — Normalize / Dedup / Finding Store | Doğrulandı |
| M3 — Policy Engine | Doğrulandı |
| M4 — Verification Layer | Doğrulandı |
| M5 — AI Adapter | Doğrulandı; gerçek Codex önerisi |
| M6 — Provider Fallback / Review | Doğrulandı; native TEST_ONLY köprüler |

[MVP ilerlemesi](MVP.md#42-progress) ve [son Git inceleme kanıtı](.agent/FINAL-GIT-REVIEW.md) ve [skill entegrasyon doğrulaması](.agent/SKILL-INTEGRATION-VERIFICATION.md).

Mevcut sınırlar:

- Bilerek açık test bulguları OPEN; kayıtlı root release gate BLOCK/10, çözümlenmemiş verification VERIFY_ERROR/60.
- Otomatik AI yama uygulama, PR, merge veya deploy yok.
- İnsan onayı/risk kabulü akışı, otomatik credential rotasyonu veya gerçek bildirim gönderimi yok.
- GitHub Actions, tam dashboard veya CodeQL/ZAP/MobSF entegrasyonu yok.
- Varsayılan profilde CVE/container/IaC taraması veya tam SBOM yok.
- Diğer OS/Python ve iki bağımsız canlı reviewer kabul testi yapılmadı.
- MVP kabulü üretim release güvenlik onayı değildir.

<a id="tr-docs"></a>
### Belgeler ve katkı

| Belge | Amaç |
| --- | --- |
| [MVP.md](MVP.md) | Onaylı kapsam ve kabul |
| [SECURITY_AGENT.md](SECURITY_AGENT.md) | Güvenlik değişmezleri |
| [AGENTS.md](AGENTS.md) | Ajan kuralları |
| [Gate girdi sözleşmesi](docs/gate-input.md) | Değişiklik bağlamı/politika kanıtı |
| [Doğrulama sözleşmesi](docs/verification-contract.md) | Doğrulama, makbuz, kapanış |
| [AI adapter sözleşmesi](docs/ai-adapter-contract.md) | Öneri/review/fallback sözleşmeleri |
| [Bulgu şeması](schemas/finding.schema.json) | Kanonik doğrulama |
| [Sır sızıntısı playbook'u](.security/playbooks/secret-leak.md) | Müdahale/rotasyon gereklilikleri |

Yamaları küçük ve görev kapsamında tutun, anlamlı uygulama testleri ekleyin, fail-closed koruyun ve fixture'da yalnız sahte kimlik bilgisi kullanın. Korunan sözleşme açık insan görevi ister. Gereksiz bağımlılık/mimari değişikliği yapmayın.

**Lisans:** henüz `LICENSE` yoktur. README lisans tanımlamaz.

---

<a id="tr-skill"></a>
### Protokolü ajan skill'i olarak kullanma

Detaylı ve taşınabilir [coding-security-protocol skill'i](.agents/skills/coding-security-protocol/SKILL.md) depoya eklendi. Codex, Claude Code ve Antigravity her biri bağımsız kullanabilir. Mevcut CLI ve güvenlik sözleşmeleri korunur; çekirdek için başka AI ajanı zorunlu değildir.

| İstemci | Bu depoda kullanım | Diğer projeler için kurulum |
| --- | --- | --- |
| Codex | `$coding-security-protocol` | Tam skill klasörünü `~/.agents/skills/coding-security-protocol/` altına kopyala |
| Claude Code | `/coding-security-protocol` | Tam klasörü `~/.claude/skills/coding-security-protocol/` altına kopyala |
| Antigravity | `coding-security-protocol` kullanmasını iste; güncel yüzeylerde `/coding-security-protocol` da desteklenir | Tam klasörü `~/.gemini/config/skills/coding-security-protocol/` altına kopyala; eski IDE `~/.gemini/antigravity/skills/` yolunu da destekler |

Ana paket `.agents/skills/coding-security-protocol/` içindedir. Küçük `.claude/skills/` girişi Claude'u bu pakete yönlendirir. Kullanıcı kurulumuna referanslar dahil tam paket kopyalanır. Proje talimatları AGENTS.md, CLAUDE.md ve GEMINI.md ile iş akışına bağlanır. Keşif/yenileme istemci sürümüne bağlıdır; dosya kurulumu canlı uygulama çağrısının kanıtı değildir.

Örnek istek: **“Bu özelliği Coding Security Protocol ile geliştir; gerekli deterministik kontrolleri çalıştır ve doğrulanmış devir kaydı bırak.”** Ajan gereken komutları çalıştırıp gerçek kanıtı raporlar. Skill seçimi göreve uygunluğa dayanır; protokolü benimseyen proje kuralları kullanımını açıkça isteyebilir. Bu teknik commit kilidi veya arka plan servisi değildir.

Başka uygulamada protokol dosya yapısını, tarayıcı/test/runtime config'ini ve politikalarını ayrıca kurup doctor'ı o uygulama kökünde çalıştırın. Skill kurulumu tek başına CLI bootstrap yapmaz veya ilgisiz uygulamaya doctor PASS sağlamaz. Bunun yerine bu depoyu taramayın.

#### Gerektiğinde okunan ayrıntılı rehberler

- [Doğrulama](.agents/skills/coding-security-protocol/references/verification.md): gerçek baseline, test/tekrar tarama/runtime/policy, kontrollü kapanış ve hatalar.
- [Hafıza ve araçlar](.agents/skills/coding-security-protocol/references/memory-and-tools.md): isteğe bağlı Serena/Zero-Waste/GSD/Obsidian, güncel kaynak, sınırlı bağlam ve sıralı devir.
- [AI ve fallback](.agents/skills/coding-security-protocol/references/ai-and-fallback.md): yalnız öneri transport'u, reviewer ayrımı, kota hatası ve geliştirme oturumu ayrımı.
- [Ajan entegrasyonu](.agents/skills/coding-security-protocol/references/agent-integration.md): tam kurulum, MCP config ve doğrulama düzeyleri.

#### Token maliyeti ve isteğe bağlı hızlandırıcılar

Semgrep, Trivy ve test süreçleri LLM çağrısı değildir. Modelin okuduğu skill/bağlam, araç çıktısı, AI önerisi ve bağımsız AI incelemesi model bağlamı/kullanımını tüketir. Ayrıntılı referanslar gerektiğinde okunur; büyük ham çıktılar dosyada kalır, sohbete kısa sonuç gelir. Sembol araması ve sınırlı okumalar gereksiz girdiyi azaltabilir; ancak **faturalandırılan token tasarrufu yüzdesi ölçülmedi**. Tasarruf için zorunlu kanıt atlanmaz.

Serena Python sembol okuması ve mevcut Zero-Waste MCP'nin gerçek indeks/sembol/okuma araçları yeni yerel stdio oturumlarında doğrulandı. İstemci MCP ayarları ve makine yolları yereldir; çekirdeğe MCP bağımlılığı eklenmez. İndeks gezinmeye yardım eder, güvenlik onayı vermez. Eski kalabilir ve kaynak kapsamı ayarı sandbox değildir. İsteğe bağlı arama bozulursa hedefli yerel aramaya dönülür.

Ortak `.agent/HANDOFF.md` ve yetkili kalıcı hafıza, kota bittiğinde diğer ajanın kayıtlı işten devam etmesini sağlar. Alan ajan güncel Git ve kanıtı kontrol eder. **Otomatik uygulama başlatma, gizli sohbet aktarımı veya kota izleyicisi kurulmadı.** Etkileşimli skill kurulumu native Claude/Antigravity `ai-patch` sağlayıcısı da oluşturmaz; bunun için ayrı doğrulanan JSON command köprüsü gerekir. Üç istemcide canlı UI çağrısı ve otomatik oturum geçişi iddia edilmez.

Resmî kurulum kaynakları: [Codex](https://learn.chatgpt.com/docs/build-skills), [Claude Code](https://code.claude.com/docs/en/skills), [Antigravity](https://antigravity.google/docs/skills).

---

<a id="support"></a>
## Support the project / Projeyi destekle

If this project helps your work, you can support its continued development.
Bu proje işinize katkı sağlıyorsa geliştirme çalışmalarını destekleyebilirsiniz.

**Patreon:** [patreon.com/opensource2](https://patreon.com/opensource2)

**Bitcoin (BTC) — Bitcoin network / Bitcoin ağı:**

```text
bc1q7kpfdc9stpnexvwgpzxl8nzaua8wfyp2ht8xxa
```

Thank you for supporting independent development.
Bağımsız geliştirme çalışmalarını desteklediğiniz için teşekkürler.

<a id="social"></a>
## Follow & connect / Takip et ve iletişimde kal

| Platform | Account / Hesap |
| --- | --- |
| GitHub | [Aristotheles](https://github.com/Aristotheles) |
| X | [@VibeKodlama](https://x.com/VibeKodlama) |
| YouTube | [Breath of Rumi](https://www.youtube.com/@BreathofRumi) |
| YouTube | [Kalpten Nağme](https://www.youtube.com/@KalptenNa%C4%9Fme) |
| Instagram | [GermanChunks Official](https://instagram.com/germanchunksofficial) |
| Instagram | [Kalpten Nağme](https://instagram.com/kalptennagme) |
| Website / Web sitesi | [Kalpten Nağmeler](https://kalptennagmeler.com) |

[Back to top / Başa dön](#top)
