# -*- coding: utf-8 -*-
"""Generate the Arabic usage guide as a self-contained RTL HTML (images embedded),
ready for Edge/Chrome --headless --print-to-pdf. The browser shapes Arabic natively."""
import base64, html, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "screenshots"
OUT = ROOT / "docs" / "guide-ar.html"


def img(name):
    data = base64.b64encode((SHOTS / name).read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


# (title, body_html, image_or_None)
SECTIONS = [
    ("١. لوحة التحكم — Surface",
     "بعد فتح الأداة تصل مباشرةً إلى لوحة <b>Surface</b>. في الأعلى عدّادات: الأصول، وردود HTTP المرصودة، "
     "والروابط، وعائلات الروابط. في الوسط خريطة سطح الهجوم ورادار المسح الحيّ. في الأسفل جدول المضيفين مع "
     "<b>الدرجة</b> (وهي <b>أولوية مراجعة</b> وليست ثغرة مؤكدة)، وحالة HTTP، والعنوان، والخادم. اضغط أي صف لعرض الدليل الكامل.",
     "01-surface.png"),
    ("٢. إضافة هدف وتحديد النطاق (Scope)",
     "من محدِّد مساحة العمل أعلى اليسار اختر <b>+ new target</b>، ثم اكتب دومين برنامجك واختر: "
     "<b>wildcard</b> (<code>*.domain</code>) ليشمل كل النطاقات الفرعية على أي عمق، أو <b>apex</b> للدومين نفسه فقط. "
     "تُطبَّق قواعد النطاق على <b>كل</b> طلب: الأباكس منفصل عن الـwildcard، والاستثناءات لها الأولوية، وأي هدف خارج النطاق يُحجب. "
     "لا تستخدم الأداة إلا على أصول تملكها أو ضمن برنامج Bug Bounty مصرّح لك فيه.",
     None),
    ("٣. تشغيل التجميع ومركز المهام — Task Center",
     "فعّل مراحل التجميع (<b>Passive sources</b> عبر crt.sh، و<b>HTTP roots</b> لفحص الجذور الحيّة) ثم اضغط <b>Run collection</b>. "
     "يعمل التجميع كـ<b>مهمة بالخلفية</b> تتابعها في مركز المهام: الحالة، والتقدّم، وإيقاف مؤقّت/إلغاء، واستهلاك الميزانية. "
     "زر <b>Emergency Stop</b> يوقف كل التجميعات فورًا ويرفض أي جديدة. الميزانية <b>مشتركة لكل مساحة عمل</b> ولا تُتجاوز بإرسال مهام كثيرة، "
     "وزر <b>Reset budget</b> يجدّدها عندما لا تكون هناك مهمة شغّالة.",
     "11-tasks.png"),
    ("٤. خريطة سطح الهجوم — Graph",
     "رسم تفاعلي بأسلوب BloodHound لكل المضيفين والنقاط النهائية والسكربتات. اسحب العُقد، وحرّك اللوحة بالماوس، وكبّر/صغّر بالعجلة. "
     "تميّز الألوان نوع كل عقدة: أباكس، ومضيف عالي الأولوية، ومضيف، وendpoint، وscript.",
     "02-graph.png"),
    ("٥. النقاط النهائية — Endpoints",
     "كل الروابط المكتشفة مع درجتها وعائلتها ومصدرها. تُجمَّع العائلات لتوحيد اختلافات المعرّفات وأسماء الـquery. "
     "تمتلئ هذه اللوحة عند تشغيل استخراج الـJavaScript وأدوات جمع الروابط ضمن النطاق.",
     "03-endpoints.png"),
    ("٦. التغييرات والجولات — Changes & Runs",
     "لوحة <b>Changes</b> خط زمني لكل أصل/رابط جديد ولكل تغيّر في (status/title/server/final URL/body hash) عن آخر رصد HTTP. "
     "لوحة <b>Runs</b> تعرض تاريخ كل جولة تجميع: وضعها (مكتملة/ملغاة/متقطّعة) وملاحظاتها.",
     "04-changes.png"),
    ("٧. Repeater — إرسال طلبات حقيقية",
     "أرسل طلبات HTTP <b>حقيقية ومقيّدة بالنطاق</b>. اكتب الطلب، اضغط <b>Send</b>، وافحص الرد الخام (الحالة، الهيدرات، الجسم). "
     "أي هدف خارج النطاق يظهر <b>BLOCKED</b>. يمرّ كل طلب عبر نفس المُرسِل الآمن الذي يحجب العناوين الخاصة ويتحقق من TLS ولا يتبع التحويلات تلقائيًا.",
     "06-repeater.png"),
    ("٨. Intruder — فحص الحمولات",
     "اختبار حمولات (payloads) على نفس المُرسِل المقيّد بالنطاق. حدّد الموضع بـ<code>§FUZZ§</code>، والصق قائمة الحمولات، ثم ابدأ. "
     "تظهر لكل حمولة: رمز الحالة والحجم والزمن، مع إبراز الشذوذ (مثل ردود 4xx/5xx) للمراجعة.",
     "07-intruder.png"),
    ("٩. Decoder — ترميز وفكّ ترميز",
     "تحويل Base64 وURL وHex ترميزًا وفكًّا. يعمل <b>محليًا بالكامل</b> داخل الواجهة دون أي طلب شبكة — مفيد أثناء تحليل الطلبات والردود.",
     "08-decoder.png"),
    ("١٠. Access Control Lab — فحص الصلاحيات",
     "قارن وصول <b>جلستين</b> (المالك مقابل حساب آخر أو مجهول) إلى نفس المورد الذي <b>تملكه</b>. تقارن الأداة الردود "
     "بمساواة دقيقة <b>بدون خسارة</b> (لا تُخفي المعرّفات أو القيم الحسّاسة)، وتطلب منك تحديد <b>سياسة المورد</b> (خاص/عام) "
     "حتى لا تُخفي رؤيةُ المجهول ثغرةً حقيقية. النتائج <b>مرشّحات مراجعة</b> (EXPECTED / INCONSISTENT / INCONCLUSIVE) وليست ثغرات مؤكدة. "
     "بيانات الاعتماد في الذاكرة فقط ولا تُحفَظ ولا تظهر في التقارير.",
     "09-access.png"),
    ("١١. XSS Lab — تحليل الانعكاس الآمن",
     "تحليل آمن لانعكاس المدخلات: تُحقَن قيمة <b>canary</b> فريدة غير ضارّة ويُحلَّل سياق انعكاسها (HTML / attribute / …). "
     "<b>لا تُنفَّذ أي شِفرة JavaScript من الهدف</b> داخل واجهة RAVEN — الانعكاس وحده ليس تنفيذًا، ولا أي نتيجة تؤكّد ثغرة تلقائيًا. "
     "تصميم مُنفِّذ المتصفح المعزول (لتحقّق التنفيذ لاحقًا) موثّق في <code>docs/XSS_ISOLATION.md</code>.",
     "10-xss.png"),
    ("١٢. الترمنال المدمج والأمان",
     "اضغط زر <b>Terminal</b> أو <code>Ctrl+`</code> لفتح صدفة <code>root@hacker</code> مدمجة بنظام ملفات وهمي "
     "(<code>ls / cd / cat / grep / sed / touch / nano</code>) و<code>curl</code> حقيقي يمرّ عبر المُرسِل المقيّد بالنطاق.<br><br>"
     "<b>الأمان باختصار:</b> كل طلب يخضع لقواعد النطاق ويحجب العناوين الخاصة/المحليّة (SSRF) ويتحقق من شهادات TLS ولا يتبع التحويلات تلقائيًا. "
     "الـAPI المحلي محمي بتوكن لكل جلسة، ويرفض التأطير الخطير (chunked/التهريب). "
     "<b>استعمل الأداة فقط على ما تملكه أو ما صُرِّح لك به، واحترم قواعد البرنامج والقانون.</b>",
     None),
]

CARDS = ""
for title, body, image in SECTIONS:
    pic = f'<div class="shot"><img src="{img(image)}" alt=""></div>' if image else ''
    CARDS += f"""
    <section class="page">
      <h2>{html.escape(title)}</h2>
      <p>{body}</p>
      {pic}
    </section>"""

DOC = f"""<!doctype html>
<html dir="rtl" lang="ar">
<head><meta charset="utf-8">
<style>
  @page {{ size: A4 landscape; margin: 12mm; }}
  * {{ box-sizing: border-box; }}
  html,body {{ margin:0; padding:0; }}
  body {{ font-family:'Segoe UI','Tahoma',Arial,sans-serif; color:#0b1020; background:#fff;
          line-height:1.9; font-size:15px; }}
  code {{ font-family:'Consolas','Courier New',monospace; background:#eef1f8; color:#7a2ea6;
          padding:1px 5px; border-radius:4px; direction:ltr; unicode-bidi:embed; font-size:.92em; }}
  .cover {{ height:190mm; display:flex; flex-direction:column; align-items:center; justify-content:center;
            text-align:center; background:linear-gradient(150deg,#0a0e1a,#141a2e 60%,#1a0f24);
            color:#e8ecf8; border-radius:10px; page-break-after:always; }}
  .cover .logo {{ font-size:64px; font-weight:800; letter-spacing:2px;
                  background:linear-gradient(90deg,#00e7ff,#b967ff,#ff2a6d); -webkit-background-clip:text;
                  -webkit-text-fill-color:transparent; }}
  .cover h1 {{ font-size:30px; margin:10px 0 6px; font-weight:700; }}
  .cover .sub {{ font-size:18px; color:#9fb0d8; }}
  .cover .warn {{ margin-top:26px; max-width:78%; font-size:15px; color:#ffd7e2;
                  background:rgba(255,42,109,.14); border:1px solid rgba(255,42,109,.45);
                  padding:12px 18px; border-radius:8px; }}
  .cover .ways {{ margin-top:22px; color:#bcd; font-size:13.5px; }}
  .intro {{ page-break-after:always; padding:6mm 4mm; }}
  .intro h2 {{ color:#151a2e; border-right:5px solid #b967ff; padding-right:12px; font-size:23px; }}
  .intro .box {{ background:#f5f7fc; border:1px solid #dce2ef; border-radius:10px; padding:14px 18px; margin-top:12px; }}
  .page {{ page-break-before:always; padding-top:2mm; }}
  h2 {{ color:#151a2e; font-size:21px; margin:0 0 8px; border-right:5px solid #00b7d8; padding-right:12px; }}
  p {{ margin:0 0 12px; color:#232a3d; }}
  .shot img {{ width:100%; height:auto; border:1px solid #cdd5e6; border-radius:8px;
               box-shadow:0 4px 16px rgba(20,26,46,.14); }}
  .foot {{ text-align:center; color:#8a93a8; font-size:11px; margin-top:6px; }}
</style></head>
<body>
  <div class="cover">
    <div class="logo">🦅 RAVEN Recon</div>
    <h1>دليل الاستخدام الكامل</h1>
    <div class="sub">من التشغيل إلى كل ميزة — بالصور</div>
    <div class="warn">⚠️ للاستخدام في اختبارات الأمان <b>المصرّح بها فقط</b>: أصولك، أو ضمن نطاق برنامج Bug Bounty مُنضمّ إليه.
      الأداة لا تصنّف أي شيء كثغرة مؤكدة — الدرجات والنتائج <b>مرشّحات مراجعة</b> تؤكّدها بنفسك.</div>
    <div class="ways">التشغيل: <b>dist/RAVEN.exe</b> (تطبيق مستقل) · أو <code>python launch.py</code> (نافذة أصلية) · أو <code>python -m raven.api</code> ثم <code>http://localhost:8765</code></div>
  </div>

  <div class="intro">
    <h2>ما هي RAVEN؟</h2>
    <p>‏<b>RAVEN Recon</b> أداة سطح مكتب لتنظيم ريكون الويب وأبحاث الـBug Bounty المصرّح بها. تجمع اكتشاف النطاقات (crt.sh
       وأدوات اختيارية)، وفحص HTTP، وخريطة سطح هجوم تفاعلية، ومختبر طلبات مصغّر (Repeater / Intruder / Decoder)،
       ومختبر Access Control، ومختبر XSS للانعكاس، وترمنال مدمج — <b>كلها مقيّدة بالنطاق الذي تحدّده وآمنة</b>.</p>
    <div class="box">
      <b>مبادئ مهمة قبل البدء:</b>
      <ul>
        <li>استعمل الأداة فقط على أصول <b>تملكها</b> أو ضمن برنامج مصرّح لك فيه.</li>
        <li>الأداة <b>لا</b> تصنّف أي نتيجة كثغرة مؤكدة؛ الدرجات «أولوية مراجعة» والنتائج «مرشّحات» تؤكّدها يدويًا.</li>
        <li>لا استغلال، ولا تجاوز لحدود المعدّل، ولا تحايل على أنظمة كشف الروبوتات.</li>
        <li>بيانات الاعتماد في الذاكرة فقط، وتُحجب من الواجهة وقاعدة البيانات والتقارير.</li>
      </ul>
    </div>
    <div class="foot">RAVEN Recon — دليل عربي · النتائج مرشّحات مراجعة لا ثغرات مؤكدة</div>
  </div>
  {CARDS}
  <div class="foot" style="page-break-before:always;padding-top:20mm;font-size:13px">
    انتهى الدليل — للمزيد راجع <code>README.md</code> و<code>docs/</code> داخل المشروع.<br>
    استخدم RAVEN بمسؤولية وضمن حدود التصريح والقانون.
  </div>
</body></html>"""

OUT.write_text(DOC, encoding="utf-8")
print("wrote", OUT, f"({len(DOC)//1024} KB)")
