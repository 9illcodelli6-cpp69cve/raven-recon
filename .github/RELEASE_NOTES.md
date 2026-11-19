## RAVEN Recon 7.0.0 — first public release

**Scope-aware reconnaissance and AI-assisted security-testing workbench for bug-bounty hunters and penetration testers.**
Runs on **Windows 10/11** and **Kali Linux / Debian / Ubuntu** — as a desktop app, a local web UI, or from the terminal.

> ⚠️ **Authorised testing only.** Use RAVEN Recon only on systems you own or have written permission to test.
> Read [RESPONSIBLE_USE.md](https://github.com/mahmodaltory12-beep/raven-recon/blob/main/RESPONSIBLE_USE.md) first.

### What's inside
| Area | What you get |
|---|---|
| **Scope & workspaces** | One workspace per programme: allowed domains/wildcards, exclusions, ports. Every outgoing request is checked; out-of-scope and internal addresses are blocked. |
| **Recon** | Subdomains from certificate transparency, HTTP probing on allowed ports, endpoint discovery (links, robots.txt, sitemaps, JavaScript), change tracking between runs, review-priority ranking. |
| **Request lab** | Repeater, Intruder (header/body fuzzing with baseline anomaly detection), Decoder, HTTP history. |
| **Labs** | Access-control lab (compare two accounts on the same resource) and XSS lab (reflection-context analysis, no script execution). |
| **Findings** | Candidate findings with evidence, review workflow, Markdown workspace report export. |
| **AI Agent** | Claude Opus 5.5 plans and works with RAVEN's tools — **every target request and every command waits for your approval**. Seven built-in testing playbooks (API recon, API security, recon breadth, code audit, patch diff, PHP LFI→RCE, browser testing). |
| **AI Chat & terminal** | Ask questions, get payloads and code — in the app or with `raven-sec` in the terminal. Use Claude, or your own local model through Ollama. |
| **Safety** | Emergency Stop, per-workspace request/rate limits, per-task AI budget, offline command sandbox (Linux), encrypted API key, all data stays on your machine, no telemetry. |

### Downloads
| File | For |
|---|---|
| `RAVEN-Recon-windows-x64.zip` | Windows 10/11 — unzip and run `RAVEN.exe` |
| `RAVEN-Recon-linux-x64.tar.gz` | Kali / Debian / Ubuntu x64 — `tar -xzf …`, `sudo apt install -y gir1.2-webkit2-4.1 bubblewrap`, then `./RAVEN/RAVEN` |
| `SHA256SUMS.txt` | Checksums for both files |

Prefer installing from source (recommended on Kali — adds a menu entry plus the `raven-recon` and `raven-sec` commands):
```bash
git clone https://github.com/mahmodaltory12-beep/raven-recon.git && cd raven-recon && ./install.sh
```
Windows (PowerShell): `git clone … ; cd raven-recon ; powershell -ExecutionPolicy Bypass -File .\install.ps1`

### Verify your download
Official builds exist **only** on this Releases page. Each file is built by GitHub Actions from this repository and signed with a build-provenance attestation:
```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
gh attestation verify RAVEN-Recon-linux-x64.tar.gz --repo mahmodaltory12-beep/raven-recon
```
Copies from anywhere else ("PRO", "cracked", re-uploads) are not official and may be malicious.

### AI setup (optional — RAVEN works fully without AI)
- **Claude (recommended):** create a key at console.anthropic.com (set a spend limit), then **Settings → Claude (Anthropic API) → Save & test**. The key is stored encrypted and never shown again.
- **Your own local model (free, offline):** install Ollama, `ollama pull qwen2.5-coder:7b`, then **Settings → Optional external provider (Ollama)**.
- Advanced built-in local model (RAVEN-Sec) is off by default — see `docs/LOCAL_AI.md`.

### Known limitations
- The AI agent's command sandbox (bubblewrap) is Linux-only; on Windows the agent can search, read, send approved in-scope requests and write files, but not run commands.
- This is the first public build of the Windows package — please report any install problem in Issues.

### Licence
© 2026 mahmoud — **GNU AGPL-3.0-or-later** with additional terms in `NOTICE.md` (keep attribution; modified versions must be marked and may not claim to be the official RAVEN Recon; no rights to the RAVEN name or logo). Provided **without warranty**.

---

<div dir="rtl">

## RAVEN Recon 7.0.0 — أول إصدار عام

**منصة استطلاع وفحص أمني مدعومة بالذكاء الاصطناعي، بتحترم النطاق** — لصيادي الثغرات ومختبري الاختراق. بتشتغل على **ويندوز** و**كالي لينكس**: تطبيق مستقل، أو ويب محلي، أو من الترمنال.

> ⚠️ **للفحص المصرّح فيه فقط** — على أنظمة بتملكها أو معك إذن مكتوب بفحصها. اقرأ RESPONSIBLE_USE.md أول.

**شو فيها:** مساحات عمل بنطاق محدد وكل طلب بينفحص عليه · استطلاع (دومينات فرعية، فحص منافذ، اكتشاف مسارات، تتبّع التغييرات) · Repeater وIntruder وDecoder وسجل HTTP · مختبر صلاحيات ومختبر XSS · نتائج مع أدلة وتقرير · **وكيل ذكي (Claude Opus 5.5) ما بينفّذ ولا طلب ولا أمر بدون موافقتك** · محادثة وترمنال `raven-sec` · زر طوارئ، حدود صرف وسرعة، sandbox بدون إنترنت، وكل بياناتك عندك.

**التنزيل:** ويندوز ← `RAVEN-Recon-windows-x64.zip` وشغّل `RAVEN.exe` · كالي ← `RAVEN-Recon-linux-x64.tar.gz`، أو من المصدر: `git clone … && ./install.sh`.

**تحقّق من التنزيل:** النسخ الرسمية بس من هالصفحة، وكل ملف موقّع: `sha256sum -c SHA256SUMS.txt --ignore-missing` و`gh attestation verify <الملف> --repo mahmodaltory12-beep/raven-recon`. أي نسخة "PRO" أو "مكرّكة" من مكان تاني مش رسمية وممكن تكون ملغّمة.

**الذكاء الاصطناعي (اختياري):** Claude من Settings، أو موديلك المحلي المجاني عن طريق Ollama. الدليل الكامل بالعربي: README.ar.md.

**الترخيص:** © 2026 mahmoud — AGPL-3.0 أو أحدث مع شروط NOTICE.md. بدون أي ضمان.

</div>
