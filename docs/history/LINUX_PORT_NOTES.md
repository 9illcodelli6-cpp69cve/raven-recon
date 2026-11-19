# RAVEN Recon على لينكس / on Linux

<div dir="rtl">

## التشغيل السريع

| الطريقة | الأمر |
|---|---|
| من قائمة التطبيقات | ابحث عن **RAVEN Recon** (بعد `packaging/linux/install.sh`) |
| من الطرفية | `raven-recon` أو `./raven-app` |
| الملف التنفيذي المبني (بديل RAVEN.exe) | `./dist/RAVEN/RAVEN` |
| في المتصفح بدل النافذة | `./raven-app --browser` |

**مكان البيانات:** `~/.local/share/raven-recon` (مساحات العمل، قواعد V7، الإعدادات).
نفس المجلد للتشغيل من المصدر وللملف المبني. لتغييره: `RAVEN_DATA_DIR=/path ./raven-app`.

## التثبيت أول مرة

```bash
# 1) حزم النظام (مرة واحدة) — النافذة الأصلية + ترجمة إضافة C++
sudo apt update
sudo apt install -y gir1.2-webkit2-4.1 python3-dev

# 2) بيئة بايثون
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements-linux.txt
.venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu   # لنموذج RAVEN Native

# 3) أيقونة بقائمة التطبيقات + أمر raven-recon
packaging/linux/install.sh
#   نقل بيانات ويندوز القديمة (المجلد اللي كان فيه RAVEN.exe) بدون الكتابة فوق أي ملف:
#   packaging/linux/install.sh --import-data /path/to/old/dist
```

بدون `gir1.2-webkit2-4.1` التطبيق يشتغل عادي لكن بيفتح بالمتصفح الافتراضي بدل نافذته.

## بناء الملف التنفيذي

```bash
./build-linux.sh            # Rust bridge + إضافة C++ (لو python3-dev موجود) + PyInstaller
./build-linux.sh --install  # وكمان يخلي أيقونة القائمة تشغّل dist/RAVEN/RAVEN
```

الناتج مجلد `dist/RAVEN/` فيه الملف التنفيذي `RAVEN` (ELF) — هو المقابل لـ `RAVEN.exe`.
اخترنا onedir بدل ملف واحد لأن الحزمة فيها torch؛ الملف الواحد كان رح يفك ~1GB بـ /tmp كل تشغيل.

</div>

## What changed for Linux (summary)

| Area | Windows (before) | Linux (now) |
|---|---|---|
| Launcher | `RAVEN.bat` / `RAVEN.exe` | `raven-app`, `dist/RAVEN/RAVEN`, menu entry (`packaging/linux/`) |
| Native window | pywebview + EdgeChromium/.NET | pywebview + GTK/WebKit2GTK (`gir1.2-webkit2-4.1`); browser fallback with a printed reason |
| Data folder | next to `RAVEN.exe` | `~/.local/share/raven-recon` (`raven/platform_paths.py`; `RAVEN_DATA_DIR` overrides) |
| Terminal | PowerShell default | bash default; UI lists only shells that exist |
| Rust trusted core | `raven-bridge.exe` | `rust/target/release/raven-bridge` (ELF) |
| C++ accelerator | `_raven_native.cp313-win_amd64.pyd` | `_raven_native.cpython-3XX-x86_64-linux-gnu.so` (needs `python3-dev`) |
| Build | `build.bat` → onefile | `build-linux.sh` → onedir; same `RAVEN.spec` |

Bugs found and fixed during the port (all latent on Windows):

- **C++ `decompress()` infinite loop** on truncated gzip input (100% CPU forever) — zlib was
  not compiled into the Windows build, so it never ran there.
- C++ sources relied on MSVC-only transitive includes (`<algorithm>`, `<cstring>`), a
  zero-length array in a test, and a **wrong SHA-256 test vector**; OpenSSL/zlib were never
  linked on non-Windows.
- ML registry stored absolute `C:\Users\...` model paths — now resolved portably, and only
  inside the project's `models/` folder (pickle trust boundary).
- Native chat showed raw template tokens (`NORMAL_SUCCESS<|endturn|><eos>`) in the reply.

## Development after the port (2026-11-17)

- **Learning page is live** (was a "Not wired" placeholder): `GET /api/v7/learning` +
  `POST /api/v7/learning/assess` over `raven/learning/assessment.py`. "Run self-assessment"
  runs RAVEN's real exam categories in-process (no network), persists to
  `learning_mastery.json` in the data folder, and shows mastery per domain, gaps, the
  workspace's lessons and study resources. Refused while Emergency Stop is engaged.
- **Honesty fixes in the learning engine:** domains with no exam used to get a made-up
  8/10 (80%) score — now `NO_EXAM`, never scored; the self-study loop declared
  `GRADUATED` after its *first* exam — now it only graduates when every domain is tested.
- **28 dead buttons fixed:** the UI script runs inside a strict-mode closure, so every
  `onclick="fn()"` (Emergency Stop, all Refresh buttons, Run Agent/Program, Save Settings,
  Add entry, Browser Send, Start Collection, …) was a silent `ReferenceError`. They are now
  exported (`_INLINE_HANDLERS`); `tests/test_ui_inline_handlers.py` keeps the list in sync.
- **Table renderer now HTML-escapes cells** (Traffic/Evidence/Tasks/Recon/Knowledge/Plugins
  rows can carry target-derived URLs and titles; this window holds the API token).
- Top tab strip now follows sidebar navigation.

## Recon Workbench (the working tool)

<div dir="rtl">

من RAVEN OS: القائمة الجانبية ← **Recon Workbench** (أو `http://127.0.0.1:<port>/workbench`).
للرجوع: **◂ RAVEN OS** أعلى القائمة.

1. **مساحة عمل جديدة:** قائمة المساحات ← `+ new workspace…` ← الدومين + وضع النطاق + نطاقات إضافية +
   الاستثناءات + المنافذ (+ السماح بالعناوين الخاصة لمختبرك فقط).
2. **Run collection:** crt.sh (للدومينات فقط) + فحص كل المنافذ المحددة + اكتشاف المسارات
   (روابط الصفحة، robots.txt، sitemap، ملفات JS).
3. **Surface / Endpoints / Changes / Runs:** النتائج الحقيقية، مرتبة حسب أولوية المراجعة.
4. **Repeater / Intruder (مع Headers وBody) / Access Control / XSS Lab:** كل طلب يمر عبر المرسل
   المقيّد بالنطاق والميزانية؛ أي شيء خارج النطاق يُحجب.
5. **HTTP History:** كل طلب انبعت فعلاً — اضغط عليه يفتح في Repeater.
6. **Findings ← Export workspace report:** تقرير Markdown كامل (نطاق، أهداف، مسارات، كل المرشحين)؛
   ولكل finding: Copy / Download .md.
7. **Terminal:** shell حقيقي؛ `curl` بس هو المقيّد بالنطاق، وأي أداة ثانية مسؤوليتك.

</div>

What changed to make it real (2026-11-17): served at `/workbench` with the session token (it
was unreachable); identity load crash fixed (it paused all sending); demo counters, demo
HTTP History, demo ticker, demo workspaces and demo default URLs removed; full scope form
(exclusions, ports, private-address opt-in); real workspace list/switch; probe honours every
scoped port (custom ports were silently skipped); crt.sh skipped for IP targets; bounded
endpoint discovery (opt-in `discover` on `/api/collect`, the UIs send it); Intruder headers +
body + baseline anomaly detection; `/api/payloads` (was 500), ML readiness (AttributeError),
`/api/v7/techniques` (new), Evidence panel repointed, `/api/report` workspace report,
untruncated finding reports with copy/download; `Cache-Control: no-store` on pages + API.

## RAVEN-Sec — the cybersecurity + coding model and its agent

<div dir="rtl">

**شو هو بالضبط:** fine-tune (LoRA) لموديل مفتوح **Qwen2.5-Coder-0.5B-Instruct** (494 مليون باراميتر،
Apache-2.0) — مش مدرّب من الصفر (من الصفر على هاللابتوب بياخد سنين؛ القياسات تحت). متدرّب بس على
مصادر أمن سيبراني موثوقة + كتابة كود، وبيشتغل محلياً على الـ CPU بدون إنترنت.

- **AI Chat:** صار RAVEN-Sec؛ قبل الجواب بيدوّر بقاعدة المعرفة المحلية ويجاوب منها مع المصدر.
- **RAVEN-Sec Agent** (القائمة الجانبية): هدف ← بحث بالمصادر الموثوقة ← قراءة صفحات ← (بموافقتك)
  طلب لهدف داخل النطاق أو أمر terminal بـ sandbox ← جواب مع المصادر.
- **Research browser:** متصفحه الخاص — بيفتح بس نطاقات موثوقة (MITRE, OWASP, NVD, GitHub Advisories,
  PortSwigger, MDN…)، أي إشي غيرها مرفوض.
- **الأمان:** كل `http` لهدف وكل `shell` بيستنوا Approve منك (الموافقة على نفس الأمر اللي شفته بالضبط)؛
  طلب خارج النطاق بينحجب لحاله؛ الـ shell داخل bubblewrap (ما بيشوف مجلد البيت)؛ Emergency Stop بيوقفه.
- **الـ shell بدون إنترنت افتراضياً:** مشاركة شبكة الجهاز كانت بتخلي أمر واحد "بريء" يوصل لشاشة X11
  (يكتب ضغطات كيبورد على سطح المكتب) أو لخدمات 127.0.0.1 (منها RAVEN نفسه وBurp). الطلبات للهدف
  بتمر من أداة `http` المقيّدة بالنطاق. لو بدك شبكة بالـ shell: `RAVEN_SEC_SHELL_NETWORK=1 ./raven-app`
  (بينحجب وقتها أي UNIX socket عبر seccomp، بس 127.0.0.1 بيضل قابل للوصول — على مسؤوليتك).

</div>

### بالـ Terminal

```bash
raven-sec                                   # محادثة (الجواب بيطلع وهو بينكتب)
raven-sec -q "How do I test for SSRF?"      # سؤال واحد
raven-sec agent "Check for IDOR: as alice (cookie session=alice) request https://app.target.com/api/users/2" \
          --scope app.target.com            # الوكيل: بيسألك y/N قبل كل طلب أو أمر
#   --scope host:port لمنفذ غير 80/443 · --allow-private لمختبرك المحلي بس
#   جوّا المحادثة: /agent /scope /search /read /reset /quit
```

### هل هو مناسب لاختبار الاختراق؟ (اختبار فعلي 2026-11-18)

`python -m raven.sec_ai.pentest_bench` — 20 مهمة (IDOR, SQLi, XSS, SSRF, SSTI, JWT, CORS, XXE, command
injection, traversal, CSRF, open redirect, CWE/CVE, 3 مهام كود، عربي، سؤال متابعة):

| | جواب الموديل لحاله | الجواب الكامل (المصادر أولاً + ملخص الموديل) | ثانية/جواب |
|---|---|---|---|
| RAVEN-Sec 0.5B (v1) | 0.26 | **0.66** | 11 |
| Qwen2.5-Coder-0.5B الأصلي | 0.53 | 0.71 | 37 |

<div dir="rtl">

- **الصادق:** موديل 0.5B **مش موثوق لحاله** — بيخترع معلومات وروابط (مثلاً حكى إن Log4Shell ثغرة
  OpenSSL) وكوده بيترجم بس منطقه غالباً غلط. عشان هيك صار الجواب: **مقاطع حرفية من المصادر الموثوقة
  أولاً** (البايلودات والخطوات الحقيقية) وبعدها ملخص الموديل معلَّم "verify"، والروابط اللي مش بالمصادر
  بتنعلّم `⚠ unverified link`.
- **الوكيل** بيبعت الطلبات صح بموافقتك وبيعرض **الدليل الحقيقي** (الطلب + الرد) أول الجواب؛ تفسير
  الموديل للنتيجة ضعيف ومعلَّم.
- **مفيد كـ:** مرجع سريع بدون إنترنت للبايلودات وخطوات الفحص + منفّذ آمن للطلبات بموافقة. **مش بديل**
  عن خبرتك أو عن موديل أكبر.

</div>

| Piece | Where |
|---|---|
| Model weights / corpus / index / runs | `<data>/ai` (`RAVEN_AI_DIR` overrides; may be a symlink to a bigger disk) |
| Knowledge base | SQLite FTS5: MITRE CWE (956) + CAPEC (559) + ATT&CK (706) + OWASP WSTG (157) + Cheat Sheets (139) + PayloadsAllTheThings (140) |
| Training data | `dataset/train.jsonl` 9,742 examples (2,461 tool-use trajectories), `holdout.jsonl` 575 from documents never trained on |
| Training data build | `python -m raven.sec_ai.dataset --subset 3000` (every example fits the 512-token window; none loses its cited answer) |
| Fine-tune | `python -m raven.sec_ai.train_lora --data <ai>/dataset/train_3k.jsonl` (resumable — refuses a checkpoint made with other data/settings; atomic checkpoints) |
| Evaluation | `python -m raven.sec_ai.evaluate` → `raven-sec-0.5b/EVALUATION.md` (held-out loss, tool-protocol rate, sample answers, base vs tuned) |
| Code | `raven/sec_ai/` (corpus, kb, dataset, train_lora, llm, research, agent, evaluate) · tests `tests/test_sec_ai.py` |

Why not 400–600M from scratch: measured on this laptop (Core 5 120U, no GPU) a 110M model trains at
341 tokens/s and a 341M one at 101 tokens/s (without the optimizer). A compute-optimal 500M model
needs ~10B tokens → ~4.5 years here; even a weak 300M-token run is ~50 days at 100% CPU, and 500M
training needs ~8 GB RAM. Licences of the training sources: MITRE terms (attribution), OWASP
CC BY-SA 4.0, PayloadsAllTheThings MIT.

## Claude (Anthropic API) — RAVEN's brain

<div dir="rtl">

**التفعيل:** RAVEN ← Settings ← **Claude (Anthropic API)** ← الصق مفتاحك ← **Save &amp; test**.
(اعمل مفتاح جديد من console.anthropic.com ← API Keys، وحط حد صرف للحساب.)

- **وين بيشتغل:** AI Chat، وصفحة **Agent** (اختار المحرّك: Claude Opus 5.5 أو RAVEN-Sec المحلي)، والترمنال:
  `raven-sec --claude` (محادثة) · `raven-sec --claude agent "..." --scope app.target.com`.
- **المفتاح:** مشفّر بمجلد بيانات RAVEN (`claude/secret.key` + `claude/api_key.enc`، صلاحيات 600)، ما بيرجع
  للواجهة أبداً (بس تلميح `sk-ant-…abcd`)، وممسوح من بيئة أي عملية بتشغّلها RAVEN.
- **الأمان:** أي طلب للهدف (`http_request`) أو أمر (`run_command`) أو جمع (`start_collection`) بيستنى **Approve**
  منك؛ خارج النطاق بينحجب قبل ما يوصلك؛ الـ sandbox بدون إنترنت؛ Emergency Stop بيوقف الـ runs.
- **التكلفة:** Opus 5.5 = $4 / $20 لكل مليون token (إدخال/إخراج). كل run إله **حد صرف** (افتراضي $3) و**حد
  أدوار** (40)، بيتغيّروا من Settings. التكلفة التقريبية بتبيّن جنب كل run.
- **الرفض:** إذا نظام الأمان عند Anthropic رفض خطوة، API بيجرّب موديل بديل تلقائياً؛ إذا الكل رفض بيبيّن
  `REFUSED` مع الفئة — زيد سياق التفويض (الهدف، النطاق، قواعد البرنامج).

</div>

| RAVEN skill (`raven/skills/`) | Covers | Replaces ARTEX |
|---|---|---|
| `api-recon` | read-only API surface mapping | api-recon |
| `api-security` | BOLA/IDOR, BFLA, mass assignment, JWT, GraphQL/SOAP … | api-security |
| `recon-breadth` | subdomains, takeover indicators, archived URLs, params | bbot-recon |
| `code-audit` | attacker-first white-box review | codeaudit |
| `patch-diff` | vulnerability from a vendor fix | patch-diff |
| `php-lfi-rce` | PHP LFI; code-exec proof only where allowed / labs | php2shell |
| `browser-testing` | Playwright scripts the operator runs (sandbox is offline) | playwright-cli |

The playbooks were **written from scratch** for RAVEN from public methodology (ARTEX is
AGPL-3.0 and its prompt files came from an untrusted fork — nothing was copied). Not ported:
`edr-bypass-re` (EDR/AV evasion — by decision), `rea` and `scopesentry` (need their own MCP
servers / platform). Code: `raven/claude/` (keystore, client, prompts, skills, tools, agent,
chat) · tests `tests/test_claude_integration.py`.
