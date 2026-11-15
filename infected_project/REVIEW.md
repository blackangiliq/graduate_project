# Review of the scan results / مراجعة نتائج الفحص

## بالعربية

### ما هذه المراجعة؟

في الأداة طبقة ذكاء اصطناعي تراجع النتائج وتكتشف ما فات القواعد ثم تقترح قواعد جديدة. هذه الطبقة
لم تُربط بعد بنموذج، فقمنا بدورها يدوياً على المختبرات الـ 16:

1. **حصر الثغرات المقصودة** في كل مختبر من توثيقه وكوده (الثغرات الموجودة في الكود، لا إعدادات
   الخادم).
2. **مطابقتها بنتائج الفحص الستاتيكي:** تُعدّ الثغرة مكتشفة إذا ظهرت نتيجة في الملف نفسه، على
   بُعد 3 أسطر أو أقل، ومن نوع الضعف نفسه (CWE).
3. **فحص عيّنة من النتائج** (15 إلى 25 لكل مختبر): هل هي حقيقية أم إنذار كاذب، ولماذا.
4. **تحويل ما فات إلى قواعد وتحسينات** (وهذا عمل حلقة التعلّم)، ثم **إعادة الفحص والقياس**.

### النتيجة

| المختبر | الثغرات المقصودة المفحوصة | اكتُشف قبل المراجعة (1.3) | اكتُشف بعدها (1.4) |
|---|---:|---:|---:|
| Damn_Vulnerable_C_Program | 11 | 0 | **11** |
| govwa | 9 | 4 | **6** |
| railsgoat | 31 | 9 | **19** |
| DVWA | 19 | 5 | **9** |
| dvna | 19 | 4 | **9** |
| JavaVulnerableLab | 51 | 4 | **18** |
| pygoat | 48 | 20 | **22** |
| WebGoat.NET | 39 | 2 | **8** |
| NodeGoat | 20 | 2 | **6** |
| juice-shop | 30 | 6 | **17** |
| WebGoat | 34 | 13 | **24** |
| Broken-Vulnerable-Code-Snippets | 129 | 64 | **74** |
| xvwa | 20 | 10 | **13** |
| DVGA | 16 | 2 | **4** |
| DSVW | 21 | 6 | 6 |
| VAmPI | 9 | 2 | 2 |
| **المجموع** | **506** | **153 (30%)** | **248 (49%)** |

ومن 115 ثغرة فاتت الأداة وكانت ممكنة الكشف بقاعدة أو بتتبّع المدخلات، صارت **97** مكتشفة.

### ماذا تغيّر بسبب المراجعة

- **ملفات لم تكن تُفحص:** صفحات JSP و EJS و ASP.NET وملف Web.config ونسخ الإعداد الاحتياطية
  (`.dist` و `.bak`) وملفات المفاتيح (`.key` و `.pem`) ومجلد `config/env` في مشاريع Node.
- **كود JavaScript داخل الصفحات** صار يُفحص بقواعد JavaScript داخل `<script>` فقط، لا في نص الصفحة.
- **محرك جديد لأخطاء الذاكرة في C/C++:** التحرير المزدوج والاستخدام بعد التحرير والتسرب وتجاوز
  حجم الحجز والقسمة على صفر والفهارس خارج الحدود. لم يُخرج أي إنذار على 42,627 سطراً من مكتبات C
  ناضجة.
- **56 قاعدة مدمجة جديدة منذ الإصدار 1.3** (107 → 163)، منها 30 من جولة المراجعة الثانية: Go و
  Ruby و PHP و JavaScript/TypeScript و Java/JSP و C# و Web.config وقوالب Jinja و Python، وقواعد
  "مصبّ" لا تُطلق إلا إذا تُتُبّعت مدخلات المستخدم إليها عبر متغير.
- **تتبّع المدخلات:** معاملات Spring (`@RequestParam`) صارت مدخلات، وأنواع TypeScript لا تخفي
  المتغير، وكلمات النصوص الثابتة لم تعد تُعدّ متغيرات، و `mysqli_real_escape_string` صارت دالة تعقيم.

### الإنذارات الكاذبة التي أُزيلت

| السبب | مثال | أثره |
|---|---|---|
| ملفات الترجمة تُقرأ ككلمات مرور | `"INITIAL_TOKEN_TOOLTIP": "..."` | 171 في juice-shop |
| مكتبات JavaScript منسوخة داخل المشروع | jQuery و wysihtml5 و Ace | أغلب ضجيج WebGoat و DVGA |
| أسماء أنماط تُقرأ كمفاتيح | `token: "keyword.operator"` | 48 في WebGoat |
| أي قالب نصي يُعدّ SQL | ``this.http.get(`${host}/rest`)`` | 15 في juice-shop و NodeGoat |
| استعلامات Sequelize الآمنة | `findOne({ where: {...} })` | 9 في juice-shop |
| المقارنة تُقرأ كإسناد | `innerHTML === ""` | في WebGoat و juice-shop |
| كلمات في نصوص ثابتة تُعدّ متغيرات | `out.print("Missing url parameter")` | في JavaVulnerableLab |
| قيم مؤقتة تُعدّ أسراراً | `'your-secret-key-here'` و `'$pass_new'` | في pygoat و DVWA |

### ما يبقى خارج قدرة الفحص الستاتيكي

- **أخطاء المنطق والصلاحيات:** IDOR وغياب فحص الصلاحية و CSRF والقوة الغاشمة ومنطق العمل.
- **إصدارات المكتبات الضعيفة:** log4j و mathjs و express-jwt (تحتاج فاحص اعتماديات).
- **تدفق عبر الدوال والملفات:** صفحات WebForms التي تمرّر القيمة إلى طبقة أخرى، ومحللات GraphQL،
  و `BaseHTTPRequestHandler` في بايثون (DSVW و VAmPI و DVGA).

هذه هي المهام التي يُنتظر من الذكاء الاصطناعي (الفحص العميق ومراجعة النتائج) أن يغطيها عند ربطه.

**تنبيه:** التحسينات صُنعت أثناء النظر في هذه المختبرات، فالرقم الثاني يبيّن ما صارت الأداة تتعرف
عليه، لا أداءها على كود لم تره من قبل.

## In English

The tool has an AI layer that reviews findings, finds what the rules missed and proposes new
rules. It is not connected to a model yet, so its job was done by hand on the 16 labs: the
intended code-level vulnerabilities of each lab were listed from its documentation and code;
each was matched to the static findings (same file, within 3 lines, same weakness); 15-25
findings per lab were classified as true or false positives; the misses were turned into
rules and engine changes; and everything was scanned and measured again.

**Result:** 153 of 506 audited vulnerabilities (30%) were found before the review, 248 (49%)
after it. Of the 115 misses that a rule or input tracing could catch, 97 are found now. The
per-lab table is above. The changes: JSP, EJS, ASP.NET, Web.config, backup copies, key files
and Node's `config/env` are scanned; JavaScript rules run inside the `<script>` code of pages;
a new C/C++ memory engine (silent on 42,627 lines of mature C); 56 new built-in rules since
1.3 (107 → 163), 30 of them from the second review round, including sink rules that fire only
on traced input; Spring parameters are treated as input, TypeScript types no longer hide
variables, and words in string literals are no longer variables. The false-positive sources
that were removed are in the Arabic table (translation files, vendored libraries, style names,
template strings read as SQL, Sequelize queries, comparisons read as assignments, placeholder
values).

**Out of reach for static rules:** access control and logic flaws, CSRF and brute force,
vulnerable dependency versions, and flows across functions or files (WebForms code-behind,
GraphQL resolvers, Python `BaseHTTPRequestHandler`). These are what the AI deep scan and
review are meant to cover once a model is connected.

Caveat: the improvements were made while looking at these labs, so the second number shows
what the tool now recognises, not how it performs on code it has never seen.
