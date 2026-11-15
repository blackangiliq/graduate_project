# infected_project - مختبرات تدريب مصابة عمداً / Deliberately vulnerable training labs

> **تحذير:** كل المشاريع هنا غير آمنة عمداً. تُستخدم للفحص والتدريب فقط؛ لا تشغّلها على
> شبكة ولا تنشرها على خادم.
>
> **Warning:** every project here is insecure on purpose. Scan and study them only; never
> run them on a network or deploy them.

## بالعربية

هذا المجلد يجمع **16 مختبراً** من مصادر مختلفة (OWASP، وشركات أمن، وباحثين مستقلين) بـ
**أكثر من 10 لغات برمجة**، لنختبر عليها الأداة على كود لم يُكتب معها.

**لماذا لا يوجد كود المختبرات نفسه في المستودع؟** لأنها ملك مؤلفيها وبرخص مختلفة (GPL و MIT
وغيرها)، وحجمها معاً كبير، وبعضها يحوي مفاتيح وهمية عمداً يمنع GitHub رفعها. لذلك يحوي المستودع
قائمة المختبرات مثبّتةً على commit محدد (`labs.json`) وسكربتاً ينزّلها كلها بأمر واحد.

### التشغيل

```bash
python infected_project/fetch_labs.py          # ينزّل المختبرات الـ 16 (نحو 130 MB)
python infected_project/scan_labs.py           # يفحصها كلها ويكتب RESULTS.md
python infected_project/scan_labs.py --reports # ومعها تقرير HTML و JSON لكل مختبر
```

أو من اللوحة: القسم **1. المشروع ← مختبر تدريبي**، ثم **ابدأ الفحص**. والصفحة الأخيرة من
المقدمة فيها زر **افحص هذا المختبر**.

### المختبرات ومصادرها

| # | المختبر | اللغة | المصدر | الرخصة | ماذا يحوي |
|---:|---|---|---|---|---|
| 1 | DVWA | PHP | [digininja/DVWA](https://github.com/digininja/DVWA) | GPL-3.0 | حقن SQL و XSS وحقن الأوامر ورفع الملفات وتضمين الملفات و CSRF بأربعة مستويات صعوبة |
| 2 | pygoat | Python (Django) | [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | MIT | مختبرات OWASP Top 10 ببايثون |
| 3 | dvna | JavaScript (Node.js) | [appsecco/dvna](https://github.com/appsecco/dvna) | MIT | OWASP Top 10 في تطبيق Express، من شركة Appsecco |
| 4 | JavaVulnerableLab | Java, JSP | [CSPF-Founder/JavaVulnerableLab](https://github.com/CSPF-Founder/JavaVulnerableLab) | GPL-2.0 | الحقن و XSS و IDOR و CSRF و XXE و SSRF وفك التسلسل |
| 5 | govwa | Go | [0c34/govwa](https://github.com/0c34/govwa) | غير مذكورة | حقن SQL و XSS و IDOR والمصادقة في جهة العميل |
| 6 | railsgoat | Ruby on Rails | [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | MIT | OWASP Top 10 مع الإسناد الجماعي والانعكاس غير الآمن |
| 7 | WebGoat.NET | C# (ASP.NET) | [OWASP/WebGoat.NET](https://github.com/OWASP/WebGoat.NET) | غير مذكورة | حقن SQL و XSS والتلاعب بالمسارات وإعدادات Web.config غير الآمنة |
| 8 | Damn_Vulnerable_C_Program | C | [hardik05/Damn_Vulnerable_C_Program](https://github.com/hardik05/Damn_Vulnerable_C_Program) | غير مذكورة | أخطاء الذاكرة: التجاوز والتحرير المزدوج والاستخدام بعد التحرير والتسرب |
| 9 | NodeGoat | JavaScript (Node.js) | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | Apache-2.0 | OWASP Top 10 في تطبيق Node.js مع شرح لكل ثغرة |
| 10 | juice-shop | TypeScript | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | MIT | أشهر متجر غير آمن من OWASP، أكثر من 100 تحدٍّ |
| 11 | WebGoat | Java (Spring Boot) | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | GPL-2.0 | دروس OWASP التفاعلية: الحقن و XXE وفك التسلسل و JWT واجتياز المسارات |
| 12 | Broken-Vulnerable-Code-Snippets | لغات كثيرة | [snoopysecurity/Broken-Vulnerable-Code-Snippets](https://github.com/snoopysecurity/Broken-Vulnerable-Code-Snippets) | غير مذكورة | مقاطع كود ضعيفة صغيرة بلغات كثيرة لاختبار أدوات التحليل الستاتيكي |
| 13 | DSVW | Python | [stamparm/DSVW](https://github.com/stamparm/DSVW) | Unlicense | نحو 100 سطر بايثون فيها أكثر من 20 نوع ثغرة، من مؤلف sqlmap |
| 14 | VAmPI | Python (Flask API) | [erev0s/VAmPI](https://github.com/erev0s/VAmPI) | MIT | واجهة REST API ضعيفة تغطي OWASP API Security Top 10 |
| 15 | xvwa | PHP | [s4n7h0/xvwa](https://github.com/s4n7h0/xvwa) | GPL-3.0 | الحقن و XSS ورفع الملفات وإدارة الجلسات غير الآمنة |
| 16 | DVGA | Python (GraphQL) | [dolevf/Damn-Vulnerable-GraphQL-Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | MIT | الحقن و SSRF وحجب الخدمة وكشف المعلومات عبر GraphQL |

### مختبرات أونلاين (للمقارنة)

الأداة تقرأ الكود المصدري، فهذه المختبرات الأونلاين تصلح للفحص الديناميكي (من الخارج) وللمقارنة؛
ما له كود منشور منها (Juice Shop و Gruyere) يمكن فحصه بالأداة أيضاً.

| المختبر | الرابط | الكود المصدري |
|---|---|---|
| PortSwigger Web Security Academy | <https://portswigger.net/web-security> | غير منشور |
| OWASP Juice Shop (نسخة تجريبية) | <https://demo.owasp-juice.shop> | المختبر 10 أعلاه |
| Google Gruyere | <https://google-gruyere.appspot.com> | يُنزَّل من الموقع (Python) |
| Acunetix test sites | <http://testphp.vulnweb.com> | غير منشور |
| TryHackMe - OWASP Top 10 | <https://tryhackme.com/room/owasptop10> | غير منشور |
| Hack The Box Academy | <https://academy.hackthebox.com> | غير منشور |
| PentesterLab | <https://pentesterlab.com> | غير منشور |
| Root Me | <https://www.root-me.org> | غير منشور |

### النتائج

- [RESULTS.md](RESULTS.md): نتائج الفحص الستاتيكي لكل مختبر (عدد الملفات والنتائج والدرجة).
- [REVIEW.md](REVIEW.md): مراجعة النتائج يدوياً بدل الذكاء الاصطناعي: ما وُجد وما فات ولماذا.

## In English

This folder gathers **16 labs** from different sources (OWASP, security companies and
independent researchers) in **more than 10 programming languages**, to test the tool on code
that was not written together with it.

The labs' code is not stored in the repository: it belongs to its authors under different
licences, it is large, and some labs contain fake keys on purpose that GitHub refuses to
accept. The repository holds the list, pinned to one commit per lab (`labs.json`), and a
script that downloads all of them with one command.

```bash
python infected_project/fetch_labs.py          # downloads the 16 labs (about 130 MB)
python infected_project/scan_labs.py           # scans all of them, writes RESULTS.md
python infected_project/scan_labs.py --reports # plus an HTML and JSON report per lab
```

In the dashboard: **1. Project → Training lab**, then **Run scan**; the last introduction
page has a **Scan this lab** button.

| # | Lab | Language | Source | Licence | What it contains |
|---:|---|---|---|---|---|
| 1 | DVWA | PHP | [digininja/DVWA](https://github.com/digininja/DVWA) | GPL-3.0 | SQL injection, XSS, command injection, upload, file inclusion, CSRF at four levels |
| 2 | pygoat | Python (Django) | [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | MIT | OWASP Top 10 labs in Python |
| 3 | dvna | JavaScript (Node.js) | [appsecco/dvna](https://github.com/appsecco/dvna) | MIT | OWASP Top 10 in an Express app, by Appsecco |
| 4 | JavaVulnerableLab | Java, JSP | [CSPF-Founder/JavaVulnerableLab](https://github.com/CSPF-Founder/JavaVulnerableLab) | GPL-2.0 | Injections, XSS, IDOR, CSRF, XXE, SSRF, deserialization |
| 5 | govwa | Go | [0c34/govwa](https://github.com/0c34/govwa) | not stated | SQL injection, XSS, IDOR, client-side authentication |
| 6 | railsgoat | Ruby on Rails | [OWASP/railsgoat](https://github.com/OWASP/railsgoat) | MIT | OWASP Top 10 with mass assignment and unsafe reflection |
| 7 | WebGoat.NET | C# (ASP.NET) | [OWASP/WebGoat.NET](https://github.com/OWASP/WebGoat.NET) | not stated | SQL injection, XSS, path manipulation, insecure Web.config |
| 8 | Damn_Vulnerable_C_Program | C | [hardik05/Damn_Vulnerable_C_Program](https://github.com/hardik05/Damn_Vulnerable_C_Program) | not stated | Memory bugs: overflows, double free, use after free, leaks |
| 9 | NodeGoat | JavaScript (Node.js) | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | Apache-2.0 | OWASP Top 10 in a Node.js app with a tutorial per issue |
| 10 | juice-shop | TypeScript | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | MIT | OWASP's flagship insecure shop, 100+ challenges |
| 11 | WebGoat | Java (Spring Boot) | [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | GPL-2.0 | OWASP lessons: injection, XXE, deserialization, JWT, path traversal |
| 12 | Broken-Vulnerable-Code-Snippets | many | [snoopysecurity/Broken-Vulnerable-Code-Snippets](https://github.com/snoopysecurity/Broken-Vulnerable-Code-Snippets) | not stated | Small vulnerable snippets in many languages, for testing static analyzers |
| 13 | DSVW | Python | [stamparm/DSVW](https://github.com/stamparm/DSVW) | Unlicense | 100 lines of Python with 20+ kinds of vulnerability, by the author of sqlmap |
| 14 | VAmPI | Python (Flask API) | [erev0s/VAmPI](https://github.com/erev0s/VAmPI) | MIT | A vulnerable REST API for the OWASP API Security Top 10 |
| 15 | xvwa | PHP | [s4n7h0/xvwa](https://github.com/s4n7h0/xvwa) | GPL-3.0 | Injections, XSS, upload, insecure session handling |
| 16 | DVGA | Python (GraphQL) | [dolevf/Damn-Vulnerable-GraphQL-Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | MIT | Injections, SSRF, denial of service, information disclosure via GraphQL |

Online labs without published source (PortSwigger Web Security Academy, the Acunetix test
sites, TryHackMe, Hack The Box Academy, PentesterLab, Root Me) are listed in the Arabic
table above; they are for dynamic testing and comparison. The source of the Juice Shop demo
is lab 10, and Google Gruyere's source can be downloaded from its site.

Results: [RESULTS.md](RESULTS.md) (static scan of every lab) and [REVIEW.md](REVIEW.md)
(a manual review of those results, standing in for the AI review: what was found, what was
missed and why).
