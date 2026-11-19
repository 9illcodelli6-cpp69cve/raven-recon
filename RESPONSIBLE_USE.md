# Responsible use — read before you run RAVEN Recon

RAVEN Recon is built **only for authorised security testing**: bug-bounty programs within
their published rules, penetration tests with a written agreement, your own systems and
labs, and training platforms (Hack The Box, TryHackMe, CTFs).

**You are fully responsible for how you use it.** Scanning, probing or attacking systems
without permission is illegal in most countries (for example the US Computer Fraud and Abuse
Act, the UK Computer Misuse Act, the EU directive on attacks against information systems,
and equivalent cybercrime laws in Arab and other countries) and can lead to criminal
charges, civil claims and bans from bug-bounty platforms.

## Before every engagement

1. **Get authorisation in writing** — the program's policy page, a signed scope/rules of
   engagement, or ownership of the system.
2. **Put exactly that scope into RAVEN** (in-scope hosts, exclusions, ports). RAVEN blocks
   requests outside it, but it can only enforce what you enter.
3. **Read the program's rules**: automation and rate limits, forbidden test types
   (denial of service, social engineering, physical), data handling, disclosure.
4. **Use your own test accounts and data.** Stop at the first record that proves access to
   someone else's data; never download, keep or share real users' data.

## What RAVEN is designed to do — and not do

- Every request to a target and every command the AI agent proposes **waits for your
  explicit approval**. Approve only what you understand and what your scope allows.
- Out-of-scope URLs, private/loopback addresses (unless you enable them for your own lab)
  and redirects to other hosts are blocked.
- RAVEN does **not** ship denial-of-service tools, malware, persistence, EDR/antivirus
  evasion or credential-stuffing features, and its AI playbooks forbid them.
- AI output (local RAVEN-Sec model or Claude) is **advisory**: it can be wrong. Verify every
  finding by hand before you report it.

## AI provider terms

If you connect Claude with your own Anthropic API key, your use must also follow
Anthropic's Usage Policy. You pay for your own API usage; set a spend limit in the Anthropic
console.

## No warranty

RAVEN Recon is provided **"as is", without any warranty** (see the GNU AGPL-3.0, sections
15–16). The authors are not liable for any damage or legal consequence arising from its use
or misuse.

## Reporting misuse or a security problem in RAVEN itself

See [`SECURITY.md`](SECURITY.md).

---

<div dir="rtl">

## الاستخدام المسؤول — اقرأ قبل ما تشغّل RAVEN Recon

RAVEN Recon مصمّم **للفحص الأمني المصرّح فيه فقط**: برامج Bug Bounty ضمن قواعدها المنشورة،
اختبارات الاختراق باتفاق مكتوب، أنظمتك ومختبراتك الخاصة، ومنصات التدريب (HackTheBox، TryHackMe، CTF).

**إنت المسؤول الوحيد عن طريقة استخدامك.** فحص أو مهاجمة أي نظام بدون إذن مخالف للقانون بمعظم
الدول (ومنها قوانين الجرائم الإلكترونية بالدول العربية) وممكن يوصل لملاحقة جنائية ودعاوى وحظر من منصات
الـ Bug Bounty.

**قبل كل فحص:**
1. خذ **إذن مكتوب** (صفحة سياسة البرنامج، اتفاق نطاق موقّع، أو ملكية النظام).
2. حط **نفس النطاق بالضبط** بـ RAVEN — الأداة بتحجب اللي برّاه، بس بتطبّق اللي إنت بتدخله.
3. اقرأ **قواعد البرنامج**: الأتمتة وحدود السرعة، الفحوصات الممنوعة (DoS، هندسة اجتماعية…)، التعامل مع البيانات.
4. استعمل **حساباتك التجريبية**؛ وقّف عند أول سجل بيثبت الوصول لبيانات حدا تاني، ولا تحمّل أو تحتفظ ببيانات ناس حقيقيين.

**شو بتعمل الأداة وشو ما بتعمل:** كل طلب للهدف وكل أمر بيقترحه الوكيل الذكي **بيستنى موافقتك**؛ اللي
برّا النطاق بينحجب؛ ما فيها أدوات حجب خدمة ولا برمجيات خبيثة ولا تخفّي من الحمايات (EDR/AV)؛ ومخرجات
الذكاء الاصطناعي **استشارية** — تأكد من كل نتيجة بإيدك قبل ما تبلّغ عنها.

**بدون ضمان:** الأداة مقدّمة "كما هي" بدون أي ضمان، والمطوّر غير مسؤول عن أي ضرر أو تبعات قانونية من استخدامها أو إساءة استخدامها.

</div>
