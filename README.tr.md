<a id="top"></a>
# Coding Security Protocol v1.0 (Agent Skill + CLI)

**Claude Code, Codex ve Antigravity ile kodlama sırasında kullanılan bir güvenlik protokolü ve ajan skill’i.**

**Aristotheles / Vibe Hoca** tarafından geliştirilmektedir.

[Türkçe](README.tr.md) · [English](README.md#english) · [Destek](#support) · [Sosyal medya](#social)

Bu dosya, İngilizce README içeriğinin tam Türkçe karşılığıdır.

---


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
if ($LASTEXITCODE -ne 0) { throw "Tarayıcı çalıştırma başarısız" }
security normalize --run-id $scan.run_id --json
if ($LASTEXITCODE -ne 0) { throw "Normalizasyon başarısız" }
security findings update --run-id $scan.run_id --json
if ($LASTEXITCODE -ne 0) { throw "Bulgu saklama başarısız" }
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
## Projeyi destekle

Bu proje işinize katkı sağlıyorsa geliştirme çalışmalarını destekleyebilirsiniz.

**Patreon:** [patreon.com/opensource2](https://patreon.com/opensource2)

**Bitcoin (BTC) — Bitcoin ağı:**

```text
bc1q7kpfdc9stpnexvwgpzxl8nzaua8wfyp2ht8xxa
```

Bağımsız geliştirme çalışmalarını desteklediğiniz için teşekkürler.

<a id="social"></a>
## Takip et ve iletişimde kal

| Platform | Hesap |
| --- | --- |
| GitHub | [Aristotheles](https://github.com/Aristotheles) |
| X | [@VibeKodlama](https://x.com/VibeKodlama) |
| YouTube | [Breath of Rumi](https://www.youtube.com/@BreathofRumi) |
| YouTube | [Kalpten Nağme](https://www.youtube.com/@KalptenNa%C4%9Fme) |
| Instagram | [GermanChunks Official](https://instagram.com/germanchunksofficial) |
| Instagram | [Kalpten Nağme](https://instagram.com/kalptennagme) |
| Web sitesi | [Kalpten Nağmeler](https://kalptennagmeler.com) |

[Başa dön](#top)
