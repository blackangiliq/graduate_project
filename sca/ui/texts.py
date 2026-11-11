"""Texts shared by the sidebar and the Guide tab, in English and Arabic.

Every setting of the dashboard is described once, in SETTINGS: the sidebar shows the text as
the tooltip of the control, and the Guide tab prints all of them as a table. Keeping one
source means the help can never disagree with itself.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# key -> group, label (en, ar), help (en, ar)
SETTINGS: Dict[str, Dict[str, Tuple[str, str]]] = {
    "ui_lang": {
        "group": ("General", "عام"),
        "label": ("Language", "اللغة"),
        "help": ("Language of the dashboard, of the explanations under each finding and of "
                 "the reports. Code, rule ids and CWE numbers stay in English.",
                 "لغة الواجهة ولغة الشرح تحت كل نتيجة ولغة التقارير. الكود وأسماء القواعد "
                 "وأرقام CWE تبقى بالإنجليزية."),
    },
    "target": {
        "group": ("1. Project", "1. المشروع"),
        "label": ("Folder path", "مسار المجلد"),
        "help": ("The project folder to scan. Every source file inside it is read; folders "
                 "such as node_modules, .git and venv are skipped.",
                 "مجلد المشروع المراد فحصه. تُقرأ كل ملفات الكود داخله، وتُتجاوز مجلدات مثل "
                 "node_modules و .git و venv."),
    },
    "browse": {
        "group": ("1. Project", "1. المشروع"),
        "label": ("Browse...", "استعراض..."),
        "help": ("Opens the folder dialog of your operating system.",
                 "يفتح نافذة اختيار المجلد في نظام التشغيل."),
    },
    "sample": {
        "group": ("1. Project", "1. المشروع"),
        "label": ("Use sample", "استخدم العيّنة"),
        "help": ("Scan the deliberately vulnerable demo app that ships with the tool "
                 "(71 known vulnerabilities).",
                 "يفحص التطبيق التجريبي المليء بالثغرات عمداً والمرفق مع الأداة "
                 "(71 ثغرة معروفة)."),
    },
    "use_rules": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Pattern rules", "قواعد الأنماط"),
        "help": ("Runs every active rule on every code line: the built-in rules, the rules "
                 "imported from DevSkim, the rules learned from the AI and your own rules. "
                 "Manage them in the Rules tab.",
                 "يشغّل كل قاعدة فعّالة على كل سطر كود: القواعد المدمجة، والمستوردة من "
                 "DevSkim، والمتعلَّمة من الذكاء الاصطناعي، وقواعدك الخاصة. تُدار من تبويب "
                 "القواعد."),
    },
    "use_ast": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Python AST taint analysis", "تحليل بايثون (AST وتتبّع التلوّث)"),
        "help": ("Parses Python files into a syntax tree and follows user input from where it "
                 "enters (a request parameter) to where it becomes dangerous (an SQL query, "
                 "a shell command), also across functions of the same file.",
                 "يحوّل ملفات بايثون إلى شجرة بنية ويتتبّع مدخلات المستخدم من مكان دخولها "
                 "(مثل متغيّر الطلب) إلى المكان الخطر (استعلام SQL أو أمر نظام)، وكذلك عبر "
                 "الدوال داخل الملف نفسه."),
    },
    "use_secrets": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Secrets detection", "كشف الأسرار"),
        "help": ("Finds hard-coded passwords, API keys and tokens: known key formats (the "
                 "built-in ones plus those imported from Gitleaks) and sensitive variable "
                 "names assigned a random-looking value. Found secrets are masked everywhere.",
                 "يجد كلمات المرور والمفاتيح المكتوبة داخل الكود: صيغ المفاتيح المعروفة "
                 "(المدمجة والمستوردة من Gitleaks) والمتغيّرات ذات الأسماء الحساسة المسنَد "
                 "إليها قيمة عشوائية الشكل. تُحجب الأسرار المكتشفة في كل مكان."),
    },
    "use_bandit": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Bandit", "Bandit"),
        "help": ("An established open-source Python security scanner, used as a second "
                 "opinion. Installed with the requirements.",
                 "أداة مفتوحة المصدر معروفة لفحص أمان بايثون، تُستخدم كرأي ثانٍ. تُنصَّب مع "
                 "المتطلبات."),
    },
    "use_semgrep": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Opengrep / Semgrep", "Opengrep / Semgrep"),
        "help": ("An external multi-language scanner. Optional: it runs only if you "
                 "installed opengrep or semgrep yourself.",
                 "ماسح خارجي متعدد اللغات. اختياري: يعمل فقط إن نصّبت opengrep أو semgrep "
                 "بنفسك."),
    },
    "use_gitleaks": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Gitleaks", "Gitleaks"),
        "help": ("The external Gitleaks program. Optional. Its key formats are already "
                 "imported into the built-in secrets engine, so you rarely need it.",
                 "برنامج Gitleaks الخارجي. اختياري. صيغ مفاتيحه مستوردة أصلاً إلى محرك "
                 "الأسرار المدمج، فقلّما تحتاجه."),
    },
    "use_taint_lite": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Input tracing for other languages", "تتبّع المدخلات للغات الأخرى"),
        "help": ("For JavaScript, PHP, Java, Go, C#, Ruby and C: checks whether a variable "
                 "on the flagged line was filled from user input a few lines earlier. If "
                 "yes, the finding is marked as traced and can be confirmed.",
                 "في JavaScript و PHP و Java و Go و C# و Ruby و C: يتحقق هل المتغيّر في "
                 "السطر المبلَّغ عنه أُخذ من مدخلات المستخدم قبل بضعة أسطر. إن كان كذلك "
                 "تُعلَّم النتيجة بأنها متتبَّعة ويمكن تأكيدها."),
    },
    "exclude_dirs": {
        "group": ("2. Static engines", "2. المحركات الستاتيكية"),
        "label": ("Folders to skip", "مجلدات تُتجاوز"),
        "help": ("Extra folder names to leave out, separated by commas, for example: "
                 "docs, third_party.",
                 "أسماء مجلدات إضافية لا تُفحص، مفصولة بفواصل، مثل: docs, third_party."),
    },
    "use_ml": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("ML classifier (second opinion)", "مصنّف تعلّم الآلة (رأي ثانٍ)"),
        "help": ("A small model trained on vulnerable and safe code lines scores each "
                 "finding between 0 and 100%. It counts for a quarter of the confidence and "
                 "is retrained with the lines you review. Runs on this computer.",
                 "نموذج صغير مدرَّب على أسطر كود مصابة وآمنة يعطي كل نتيجة درجة بين 0 و100%. "
                 "وزنه ربع الثقة، ويُعاد تدريبه بالأسطر التي تراجعها. يعمل على هذا الحاسوب."),
    },
    "provider": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("AI provider", "مزوّد الذكاء الاصطناعي"),
        "help": ("Where the large language model runs: Ollama (on this computer, nothing "
                 "leaves it) or a cloud API (OpenAI, Gemini, Anthropic, OpenRouter, Groq, "
                 "DeepSeek, Mistral, or any OpenAI-compatible address).",
                 "أين يعمل النموذج اللغوي: Ollama (على هذا الحاسوب ولا يخرج منه شيء) أو "
                 "خدمة سحابية (OpenAI أو Gemini أو Anthropic أو OpenRouter أو Groq أو "
                 "DeepSeek أو Mistral أو أي عنوان متوافق مع OpenAI)."),
    },
    "base_url": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("API address", "عنوان الـ API"),
        "help": ("The address of the provider. Filled in for you; change it only for a "
                 "proxy or a self-hosted server.",
                 "عنوان المزوّد. يُملأ تلقائياً، وغيّره فقط لوسيط (proxy) أو خادم خاص."),
    },
    "api_key": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("API key", "مفتاح الـ API"),
        "help": ("Kept in memory. Press 'Save AI settings' to store it in the .env file of "
                 "this project (git-ignored). It is never written to reports or the database.",
                 "يبقى في الذاكرة. اضغط «حفظ إعدادات الذكاء الاصطناعي» لتخزينه في ملف ‎.env "
                 "داخل المشروع (مستثنى من git). لا يُكتب أبداً في التقارير أو قاعدة البيانات."),
    },
    "model": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("Model", "النموذج"),
        "help": ("The model name exactly as the provider lists it.",
                 "اسم النموذج كما يكتبه المزوّد تماماً."),
    },
    "use_llm": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("AI review of findings", "مراجعة النتائج بالذكاء الاصطناعي"),
        "help": ("The model reads each finding with its surrounding code, says whether it is "
                 "real, explains it and proposes a fix. A finding it judges false is kept "
                 "and labelled, never deleted.",
                 "يقرأ النموذج كل نتيجة مع الكود المحيط بها، ويقول هل هي حقيقية، ويشرحها "
                 "ويقترح إصلاحاً. النتيجة التي يحكم بأنها كاذبة تبقى وتُعلَّم ولا تُحذف."),
    },
    "deep": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("Deep scan (AI audits whole files)", "الفحص العميق (النموذج يدقق ملفات كاملة)"),
        "help": ("Slower and uses more requests. Finds issues the static engines miss, "
                 "which the tool can then turn into new rules.",
                 "أبطأ ويستهلك طلبات أكثر. يكتشف ما لا تجده المحركات الستاتيكية، ثم تحوّله "
                 "الأداة إلى قواعد جديدة."),
    },
    "llm_max": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("Findings the AI reviews", "عدد النتائج التي يراجعها النموذج"),
        "help": ("The most severe findings go first. Each one costs one request.",
                 "تُراجَع الأخطر أولاً. كل نتيجة تكلّف طلباً واحداً."),
    },
    "deep_max_files": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("Files in a deep scan", "عدد ملفات الفحص العميق"),
        "help": ("How many files the model audits in a deep scan. Files with the most "
                 "findings and the most user input go first.",
                 "عدد الملفات التي يدققها النموذج في الفحص العميق. تُقدَّم الملفات الأكثر "
                 "نتائجَ ومدخلاتٍ."),
    },
    "llm_timeout": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("Seconds to wait for an answer", "ثواني انتظار الجواب"),
        "help": ("Raise it for a slow local model.", "ارفعها إن كان النموذج المحلي بطيئاً."),
    },
    "save_ai": {
        "group": ("3. Artificial intelligence", "3. الذكاء الاصطناعي"),
        "label": ("Save AI settings", "حفظ إعدادات الذكاء الاصطناعي"),
        "help": ("Stores the provider, model and key in the git-ignored .env file, so you "
                 "do not have to enter them again.",
                 "يحفظ المزوّد والنموذج والمفتاح في ملف ‎.env المستثنى من git كي لا تعيد "
                 "إدخالها."),
    },
    "strict": {
        "group": ("4. Precision", "4. الدقة"),
        "label": ("Strict mode (confirmed findings only)", "الوضع الصارم (المؤكَّد فقط)"),
        "help": ("Counts a finding only when independent evidence supports it: user input "
                 "was traced to the line, the AI review confirmed it, you confirmed it, or "
                 "(for weaknesses that need no data flow, such as a weak algorithm) two "
                 "engines agree. Everything else is kept under 'Needs review'.",
                 "يحتسب النتيجة فقط إن دعمها دليل مستقل: تتبّع مدخلات المستخدم حتى السطر، "
                 "أو تأكيد مراجعة الذكاء الاصطناعي، أو تأكيدك أنت، أو (للثغرات التي لا تحتاج "
                 "تدفق بيانات مثل خوارزمية ضعيفة) اتفاق محركين. الباقي يُنقل إلى «تحتاج "
                 "مراجعة»."),
    },
    "skip_tests": {
        "group": ("4. Precision", "4. الدقة"),
        "label": ("Skip test code", "تجاوز كود الاختبارات"),
        "help": ("Do not scan tests/, test_*.py, *.spec.js and similar. When they are "
                 "scanned, findings in test code get a lower confidence and are never "
                 "confirmed automatically.",
                 "لا يفحص tests/ و test_*.py و ‎*.spec.js وما يشبهها. وإن فُحصت فنتائجها "
                 "تأخذ ثقة أقل ولا تُؤكَّد تلقائياً."),
    },
    "use_feedback": {
        "group": ("4. Precision", "4. الدقة"),
        "label": ("Apply my earlier reviews", "طبّق مراجعاتي السابقة"),
        "help": ("Findings you dismissed stay dismissed, findings you confirmed stay "
                 "confirmed, and each rule's confidence follows its record in your reviews "
                 "(a rule with repeated false positives is quarantined). Switch off to see "
                 "the raw result.",
                 "ما رفضتَه يبقى مرفوضاً وما أكّدتَه يبقى مؤكَّداً، وثقة كل قاعدة تتبع سجلّها "
                 "في مراجعاتك (القاعدة المتكررة الإنذارات الكاذبة تُحجر). عطّله لترى النتيجة "
                 "الخام."),
    },
    "save_scan": {
        "group": ("5. Output", "5. المخرجات"),
        "label": ("Save this scan in History", "احفظ هذا الفحص في السجل"),
        "help": ("Stores the result in the local database (data/sca.db), so the History tab "
                 "can show how the score changes over time.",
                 "يحفظ النتيجة في قاعدة البيانات المحلية (data/sca.db) ليعرض تبويب السجل "
                 "تغيّر الدرجة مع الزمن."),
    },
    "run": {
        "group": ("5. Output", "5. المخرجات"),
        "label": ("Run scan", "ابدأ الفحص"),
        "help": ("Scans the folder with the settings above.",
                 "يفحص المجلد بالإعدادات أعلاه."),
    },
}

TABS: List[Tuple[str, str, str, str]] = [
    ("Dashboard", "اللوحة",
     "The summary of the last scan: security score and grade, findings per severity and per "
     "OWASP Top 10 category, the most affected files, and which engines ran.",
     "ملخص آخر فحص: درجة الأمان وتقديرها، عدد النتائج حسب الخطورة وحسب فئات OWASP Top 10، "
     "أكثر الملفات إصابة، والمحركات التي عملت."),
    ("Findings", "النتائج",
     "Every finding with its code, why it was (or was not) confirmed, the explanation, the "
     "fix and the AI review. Two buttons teach the tool: Real vulnerability / False positive.",
     "كل نتيجة مع كودها وسبب تأكيدها أو عدمه والشرح والإصلاح ومراجعة الذكاء الاصطناعي. "
     "زرّان يعلّمان الأداة: ثغرة حقيقية / إنذار كاذب."),
    ("Rules", "القواعد",
     "Full control of the rule set: browse, filter, read, edit, switch on or off, write a "
     "new rule, try an expression on code, import and export.",
     "تحكم كامل بالقواعد: تصفّح وفلترة وقراءة وتعديل وتفعيل وتعطيل، وكتابة قاعدة جديدة، "
     "وتجربة تعبير على كود، واستيراد وتصدير."),
    ("Learning", "التعلّم",
     "The AI proposes rules from what it found; each proposal shows its automatic checks "
     "and waits for your approval. Also: rule track record and coverage per language.",
     "يقترح الذكاء الاصطناعي قواعد مما اكتشفه، وكل اقتراح يعرض فحوصه الآلية وينتظر "
     "مصادقتك. وفيه أيضاً سجل أداء القواعد والتغطية لكل لغة."),
    ("Reports", "التقارير",
     "Download the current scan as HTML, PDF, JSON or SARIF.",
     "تنزيل الفحص الحالي بصيغة HTML أو PDF أو JSON أو SARIF."),
    ("History", "السجل",
     "Earlier scans of each project and how the score changed; any saved scan can be "
     "opened again.",
     "الفحوص السابقة لكل مشروع وتغيّر الدرجة، ويمكن فتح أي فحص محفوظ."),
    ("Guide", "التعليمات",
     "This page: how to use the tool, what every setting does, how to write rules, the "
     "diagrams with their explanation, the references and the limits.",
     "هذه الصفحة: طريقة الاستخدام، ووظيفة كل إعداد، وكتابة القواعد، والمخططات مع شرحها، "
     "والمراجع، والحدود."),
]

QUICK_START: List[Tuple[str, str]] = [
    ("**Choose the project.** Type the folder path in the sidebar, press *Browse...*, or "
     "press *Use sample* to try the demo application.",
     "**اختر المشروع.** اكتب مسار المجلد في الشريط الجانبي أو اضغط *استعراض...* أو اضغط "
     "*استخدم العيّنة* لتجربة التطبيق التجريبي."),
    ("**Choose the engines.** The defaults are right for a first scan. Each option has a "
     "small (?) that explains it.",
     "**اختر المحركات.** الإعدادات الافتراضية مناسبة لأول فحص. بجانب كل خيار علامة (?) "
     "تشرحه."),
    ("**Optional: connect the AI.** Pick a provider, paste the API key, choose a model and "
     "press *Save AI settings*. With Ollama no key is needed and nothing leaves your computer.",
     "**اختياري: اربط الذكاء الاصطناعي.** اختر المزوّد والصق المفتاح واختر النموذج ثم اضغط "
     "*حفظ إعدادات الذكاء الاصطناعي*. مع Ollama لا تحتاج مفتاحاً ولا يخرج شيء من حاسوبك."),
    ("**Press Run scan.** The Dashboard tab shows the score; the Findings tab shows each "
     "issue with its code, explanation and fix.",
     "**اضغط ابدأ الفحص.** تبويب اللوحة يعرض الدرجة، وتبويب النتائج يعرض كل مشكلة مع "
     "كودها وشرحها وإصلاحها."),
    ("**Review.** Under each finding press *Real vulnerability* or *False positive*. The "
     "tool remembers it and adjusts the rule that produced the finding.",
     "**راجع.** تحت كل نتيجة اضغط *ثغرة حقيقية* أو *إنذار كاذب*. الأداة تتذكر ذلك وتعدّل "
     "ثقة القاعدة التي أنتجت النتيجة."),
    ("**Teach.** In the Learning tab press *Learn from this scan* (after a scan with AI "
     "review and Deep scan). Read each proposed rule and approve or reject it.",
     "**علّم الأداة.** في تبويب التعلّم اضغط *Learn from this scan* (بعد فحص مع مراجعة "
     "الذكاء الاصطناعي والفحص العميق). اقرأ كل قاعدة مقترحة ثم صادق أو ارفض."),
    ("**Control the rules.** In the Rules tab switch rules on or off, edit them, or write "
     "your own.",
     "**تحكّم بالقواعد.** في تبويب القواعد فعّل أو عطّل أو عدّل، أو اكتب قاعدتك."),
    ("**Download the report** from the Reports tab and follow the score in History.",
     "**نزّل التقرير** من تبويب التقارير وتابع الدرجة في السجل."),
]

# image base name in docs/images ("<name>.png" English, "<name>.ar.png" Arabic)
DIAGRAMS: List[Dict[str, str]] = [
    {"name": "overview",
     "title_en": "1. The whole project on one page",
     "title_ar": "1. المشروع كله في صفحة واحدة",
     "text_en": "Read it from top to bottom as six layers. The **interface** (dashboard, "
                "command line, launchers) starts the scan of a folder. **Static analysis** "
                "reads the code without running it: secrets, pattern rules, the Python "
                "taint engine, optional external scanners, and input tracing for other "
                "languages. **Fusion and AI** merges duplicate reports into one finding, "
                "adds the opinion of the classifier, and lets the AI provider review "
                "findings and audit whole files. **Decision** splits findings into "
                "confirmed and probable and computes the risk of each finding and the "
                "score of the project. **Outputs** are the findings view, the reports and "
                "the history. **Learning and rule control** closes the loop: your reviews "
                "and the AI's discoveries become validated, approved rules, and the Rules "
                "tab lets you change any rule, so the next scan is smarter.",
     "text_ar": "يُقرأ من الأعلى إلى الأسفل كست طبقات. **الواجهة** (الداشبورد وسطر الأوامر "
                "وملفات التشغيل) تبدأ فحص مجلد. **التحليل الستاتيكي** يقرأ الكود دون "
                "تنفيذه: الأسرار، وقواعد الأنماط، ومحرك بايثون لتتبّع التلوّث، والماسحات "
                "الخارجية الاختيارية، وتتبّع المدخلات للغات الأخرى. **الدمج والذكاء** يدمج "
                "البلاغات المكررة في نتيجة واحدة، ويضيف رأي المصنّف، ويجعل مزوّد الذكاء "
                "الاصطناعي يراجع النتائج ويدقق ملفات كاملة. **القرار** يقسم النتائج إلى "
                "مؤكَّدة ومحتملة ويحسب خطورة كل نتيجة ودرجة المشروع. **المخرجات** هي عرض "
                "النتائج والتقارير والسجل. **التعلّم والتحكم بالقواعد** يغلق الحلقة: "
                "مراجعاتك واكتشافات الذكاء الاصطناعي تصبح قواعد مفحوصة ومصادَقاً عليها، "
                "وتبويب القواعد يتيح لك تغيير أي قاعدة، فيصبح الفحص التالي أذكى."},
    {"name": "usage",
     "title_en": "2. How to use it, step by step",
     "title_ar": "2. خطوات الاستخدام",
     "text_en": "The practical path of a user: install, run, optionally connect the AI "
                "(through an API key or a local Ollama model), choose the folder, scan, "
                "read and review the findings, let the tool learn, download the report. "
                "The dashed arrow at the end is the point of the whole design: the next "
                "scan is better than the previous one, because the approved rules are "
                "active and your reviews are remembered.",
     "text_ar": "المسار العملي للمستخدم: التنصيب ثم التشغيل ثم ربط الذكاء الاصطناعي "
                "اختيارياً (بمفتاح API أو بنموذج Ollama محلي) ثم اختيار المجلد ثم الفحص ثم "
                "قراءة النتائج ومراجعتها ثم التعلّم ثم تنزيل التقرير. السهم المنقّط في "
                "النهاية هو غاية التصميم كله: الفحص التالي أفضل من السابق، لأن القواعد "
                "المصادَق عليها فعّالة ومراجعاتك محفوظة."},
    {"name": "pipeline",
     "title_en": "3. Every stage, with its tools and techniques",
     "title_ar": "3. كل مرحلة مع أدواتها وتقنياتها",
     "text_en": "The detailed version of diagram 1. Each box names the stage, the source "
                "file that implements it, and the technique or library it uses: os.walk to "
                "collect files, YAML rules and regular expressions, Python's ast module for "
                "taint analysis, Shannon entropy for secrets, noisy-OR to combine "
                "confidence, TF-IDF with logistic regression for the classifier, the "
                "provider APIs for the language model, an exponential formula for the "
                "score, and SQLite for storage. Use it to answer 'how exactly is this step "
                "done?'.",
     "text_ar": "النسخة التفصيلية من المخطط 1. كل مربع يذكر المرحلة والملف البرمجي الذي "
                "ينفّذها والتقنية أو المكتبة المستخدمة: os.walk لجمع الملفات، قواعد YAML "
                "والتعابير النمطية، مكتبة ast في بايثون لتتبّع التلوّث، إنتروبيا شانون "
                "للأسرار، قاعدة Noisy-OR لدمج الثقة، TF-IDF مع الانحدار اللوجستي للمصنّف، "
                "واجهات المزوّدين للنموذج اللغوي، صيغة أسّية للدرجة، و SQLite للتخزين. "
                "استخدمه للإجابة عن سؤال: كيف تُنفَّذ هذه الخطوة بالضبط؟"},
    {"name": "taint",
     "title_en": "4. Taint analysis: following user input",
     "title_ar": "4. تتبّع التلوّث: ملاحقة مدخلات المستخدم",
     "text_en": "A value that comes from the user (a **source**, such as a request "
                "parameter) is marked as tainted. The mark **propagates** through "
                "assignments, string building and function calls. A **sanitizer** (a "
                "parameterized query, an escaping function, a type conversion) removes it. "
                "If a tainted value reaches a **sink** (an SQL query, a shell command, a "
                "file path), that is a vulnerability with evidence, not a guess. The "
                "diagram shows the three passes of the Python engine: inside a function, "
                "function summaries, and call sites.",
     "text_ar": "القيمة القادمة من المستخدم (**مصدر** مثل متغيّر الطلب) تُعلَّم بأنها "
                "ملوّثة. العلامة **تنتشر** عبر الإسناد وبناء النصوص واستدعاء الدوال. "
                "**المعقِّم** (استعلام مُعدّ مسبقاً أو دالة ترميز أو تحويل نوع) يزيلها. إن "
                "وصلت قيمة ملوّثة إلى **مصبّ** (استعلام SQL أو أمر نظام أو مسار ملف) فهذه "
                "ثغرة بدليل وليست تخميناً. المخطط يبيّن المرات الثلاث لمحرك بايثون: داخل "
                "الدالة، ثم ملخصات الدوال، ثم مواضع الاستدعاء."},
    {"name": "finding-status",
     "title_en": "5. What happens to one finding",
     "title_ar": "5. مصير النتيجة الواحدة",
     "text_en": "This is how false alarms are kept down. A raw match first meets your "
                "earlier verdicts and the track record of its rule, then input tracing, "
                "merging, the classifier and the AI review. A finding becomes **confirmed** "
                "only with independent evidence (you, the AI with high confidence, traced "
                "input, or two engines for weaknesses that need no data flow). Otherwise it "
                "is **probable**; in strict mode a probable finding moves to *Needs review* "
                "and does not count in the score.",
     "text_ar": "هكذا تُقلَّل الإنذارات الكاذبة. المطابقة الخام تمرّ أولاً على أحكامك "
                "السابقة وسجل قاعدتها، ثم تتبّع المدخلات والدمج والمصنّف ومراجعة الذكاء "
                "الاصطناعي. لا تصبح النتيجة **مؤكَّدة** إلا بدليل مستقل (أنت، أو الذكاء "
                "الاصطناعي بثقة عالية، أو تتبّع المدخلات، أو اتفاق محركين للثغرات التي لا "
                "تحتاج تدفق بيانات). وإلا فهي **محتملة**، وفي الوضع الصارم تُنقل المحتملة "
                "إلى *تحتاج مراجعة* ولا تدخل في الدرجة."},
    {"name": "learning-loop",
     "title_en": "6. The learning loop",
     "title_ar": "6. حلقة التعلّم",
     "text_en": "How a discovery of the AI becomes a permanent rule. The model proposes a "
                "rule as JSON; nine automatic checks test it (valid, fast, specific, matches "
                "the evidence and its own examples, silent on safe code, not too broad, "
                "new); a failed rule is sent back once for correction; a rule that passes "
                "waits for your approval; an approved rule starts on probation with a "
                "modest confidence, and your later reviews raise it or quarantine it.",
     "text_ar": "كيف يصبح اكتشاف الذكاء الاصطناعي قاعدة دائمة. يقترح النموذج قاعدة بصيغة "
                "JSON، وتختبرها تسعة فحوص آلية (صحيحة، سريعة، محددة، تطابق الدليل وأمثلتها، "
                "صامتة على الكود الآمن، غير واسعة، جديدة). القاعدة الفاشلة تُعاد مرة واحدة "
                "للتصحيح، والناجحة تنتظر مصادقتك، والمصادَق عليها تبدأ تحت التجربة بثقة "
                "متواضعة، ثم ترفعها مراجعاتك اللاحقة أو تحجرها."},
    {"name": "rules",
     "title_en": "7. Where rules come from and how you control them",
     "title_ar": "7. مصادر القواعد وكيف تتحكم بها",
     "text_en": "Four origins feed one rule set: **built-in** rules written with the tool, "
                "**imported** rules converted from DevSkim and Gitleaks (each one checked "
                "and measured on real code before it was allowed in), **learned** rules "
                "approved in the Learning tab, and **your own** rules. Your changes to a "
                "shipped rule are kept in a separate small file, so they survive an update "
                "and can be undone. From the Rules tab or the command line you can browse, "
                "edit, switch off, test and export any rule.",
     "text_ar": "أربعة مصادر تصبّ في مجموعة قواعد واحدة: قواعد **مدمجة** كُتبت مع الأداة، "
                "وقواعد **مستوردة** حُوِّلت من DevSkim و Gitleaks (كل واحدة فُحصت وقيست على "
                "كود حقيقي قبل قبولها)، وقواعد **متعلَّمة** صودق عليها في تبويب التعلّم، "
                "و**قواعدك الخاصة**. تعديلاتك على قاعدة مرفقة مع الأداة تُحفظ في ملف صغير "
                "منفصل، فتبقى بعد التحديث ويمكن التراجع عنها. من تبويب القواعد أو من سطر "
                "الأوامر تستطيع تصفّح أي قاعدة وتعديلها وتعطيلها واختبارها وتصديرها."},
]

REFERENCES: List[Tuple[str, str, str, str]] = [
    ("OWASP Top 10 (2021)", "https://owasp.org/Top10/",
     "The categories used to group findings.", "الفئات المستخدمة لتصنيف النتائج."),
    ("MITRE CWE", "https://cwe.mitre.org/",
     "The identifiers and definitions of weaknesses (CWE-89, CWE-79, ...).",
     "أرقام وتعاريف نقاط الضعف (CWE-89 و CWE-79 ...)."),
    ("SARIF 2.1.0 (OASIS)", "https://www.oasis-open.org/committees/sarif",
     "The exchange format of the SARIF report.", "صيغة تبادل تقرير SARIF."),
    ("Microsoft DevSkim (MIT)", "https://github.com/microsoft/DevSkim",
     "Source of the imported pattern rules.", "مصدر قواعد الأنماط المستوردة."),
    ("Gitleaks (MIT)", "https://github.com/gitleaks/gitleaks",
     "Source of the imported credential formats; also an optional external engine.",
     "مصدر صيغ المفاتيح المستوردة، وهو أيضاً محرك خارجي اختياري."),
    ("OWASP Benchmark", "https://owasp.org/www-project-benchmark/",
     "Public test cases (Java and Python) used for the external evaluation.",
     "حالات اختبار عامة (Java و Python) استُخدمت في التقييم الخارجي."),
    ("Bandit (Apache-2.0)", "https://github.com/PyCQA/bandit",
     "Python security scanner used as an engine and as the baseline of the evaluation.",
     "ماسح أمان بايثون المستخدم كمحرك وكخط أساس في التقييم."),
    ("Opengrep", "https://github.com/opengrep/opengrep",
     "Optional external multi-language engine.", "محرك خارجي اختياري متعدد اللغات."),
    ("Semgrep", "https://github.com/semgrep/semgrep",
     "Optional external multi-language engine.", "محرك خارجي اختياري متعدد اللغات."),
    ("Python ast module", "https://docs.python.org/3/library/ast.html",
     "The syntax tree used by the Python taint engine.",
     "شجرة البنية التي يعتمد عليها محرك بايثون."),
    ("Python re module", "https://docs.python.org/3/library/re.html",
     "The regular-expression syntax of rule patterns.",
     "صيغة التعابير النمطية المستخدمة في القواعد."),
    ("scikit-learn", "https://scikit-learn.org/",
     "TF-IDF and logistic regression of the classifier.",
     "TF-IDF والانحدار اللوجستي للمصنّف."),
    ("Streamlit", "https://streamlit.io/", "The dashboard framework.", "إطار عمل الداشبورد."),
    ("Ollama", "https://ollama.com", "Runs language models on this computer.",
     "يشغّل النماذج اللغوية على هذا الحاسوب."),
    ("OpenAI API reference", "https://platform.openai.com/docs/api-reference/chat",
     "The chat-completions format spoken by most cloud providers.",
     "صيغة chat-completions التي تتكلمها أغلب الخدمات السحابية."),
    ("Anthropic API", "https://platform.claude.com/docs/en/api/messages",
     "The Messages API used by the Anthropic client.",
     "واجهة Messages التي يستخدمها عميل Anthropic."),
    ("Mermaid", "https://mermaid.js.org/", "The diagrams are written in Mermaid.",
     "المخططات مكتوبة بلغة Mermaid."),
    ("Livshits and Lam, Finding Security Vulnerabilities in Java Applications with Static "
     "Analysis (USENIX Security 2005)",
     "https://www.usenix.org/conference/14th-usenix-security-symposium/finding-security-vulnerabilities-java-applications-static",
     "Classic paper on taint analysis.", "بحث مرجعي في تتبّع التلوّث."),
    ("Feng et al., CodeBERT (2020)", "https://arxiv.org/abs/2002.08155",
     "Background for the optional experiment in experiments/train_codebert.py.",
     "خلفية للتجربة الاختيارية في experiments/train_codebert.py."),
]

LIMITS: List[Tuple[str, str]] = [
    ("No static analyzer can promise zero false alarms or zero missed vulnerabilities. "
     "Strict mode shows only findings backed by independent evidence, at the cost of moving "
     "the rest to *Needs review*.",
     "لا يستطيع أي محلل ستاتيكي أن يضمن صفر إنذارات كاذبة أو صفر ثغرات فائتة. الوضع الصارم "
     "يعرض فقط ما يدعمه دليل مستقل، وثمن ذلك نقل الباقي إلى *تحتاج مراجعة*."),
    ("AI answers can be wrong. A finding judged false by the AI is kept and labelled, never "
     "deleted, and a rule written by the AI is never active before validation and approval.",
     "أجوبة الذكاء الاصطناعي قد تخطئ. النتيجة التي يحكم بأنها كاذبة تبقى وتُعلَّم ولا "
     "تُحذف، والقاعدة التي يكتبها لا تُفعَّل قبل الفحص الآلي والمصادقة."),
    ("A rule is a regular expression on one line. It cannot see a weakness that spans "
     "several lines or depends on program logic; the Python taint engine and the AI deep "
     "scan cover part of that gap.",
     "القاعدة تعبير نمطي على سطر واحد، فلا ترى ثغرة تمتد على عدة أسطر أو تعتمد على منطق "
     "البرنامج. محرك بايثون والفحص العميق يغطيان جزءاً من هذه الفجوة."),
    ("On the OWASP Benchmark the tool scores +0.44 (Java) and +0.43 (Python) out of 1. "
     "Weaknesses visible on one line are found reliably; injection in Java stays close to "
     "guessing, because there is no real data-flow engine for Java.",
     "على معيار OWASP Benchmark درجة الأداة +0.44 (Java) و +0.43 (Python) من 1. الثغرات الظاهرة "
     "في سطر واحد تُكتشف بثبات، أما الحقن في Java فيبقى قريباً من التخمين لغياب محرك تدفق "
     "بيانات حقيقي لها."),
    ("Imported rules were checked automatically and measured on real code, but were not "
     "each proven against real vulnerabilities. Rules that looked noisy ship switched off.",
     "القواعد المستوردة فُحصت آلياً وقيست على كود حقيقي، لكنها لم تُثبَت واحدةً واحدة على "
     "ثغرات حقيقية. القواعد التي بدت مزعجة تأتي معطَّلة."),
    ("With a cloud AI provider, parts of the code under review are sent to that provider. "
     "Only the secrets the tool detected are masked first.",
     "مع مزوّد سحابي تُرسَل أجزاء من الكود المفحوص إلى ذلك المزوّد. تُحجب أولاً الأسرار التي "
     "اكتشفتها الأداة فقط."),
    ("The security score is a heuristic of this tool and not an official CVSS score.",
     "درجة الأمان مقياس تقريبي خاص بهذه الأداة وليست درجة CVSS رسمية."),
]

CLI: List[Tuple[str, str, str]] = [
    ("python -m sca ui", "Start this dashboard.", "تشغيل هذه الواجهة."),
    ("python -m sca scan PATH", "Scan a folder with the static engines.",
     "فحص مجلد بالمحركات الستاتيكية."),
    ("python -m sca scan PATH --llm --deep --strict", "Add AI review, deep scan, strict mode.",
     "مع مراجعة الذكاء الاصطناعي والفحص العميق والوضع الصارم."),
    ("python -m sca config", "Choose the AI provider and store the key in .env.",
     "اختيار مزوّد الذكاء الاصطناعي وحفظ المفتاح في ‎.env."),
    ("python -m sca learn PATH --rounds 5 --auto-approve",
     "Keep learning rules from a project until a round finds nothing new.",
     "الاستمرار في تعلّم القواعد من مشروع حتى لا تجد جولة شيئاً جديداً."),
    ("python -m sca learn --bootstrap all", "Ask the AI for rules for every coverage gap.",
     "طلب قواعد من الذكاء الاصطناعي لكل فجوات التغطية."),
    ("python -m sca rules list", "Proposed rules waiting for approval.",
     "القواعد المقترحة التي تنتظر المصادقة."),
    ("python -m sca rules approve ID", "Approve a proposed rule.", "المصادقة على قاعدة مقترحة."),
    ("python -m sca rules catalog --lang php", "Every rule for a language.",
     "كل القواعد الخاصة بلغة."),
    ("python -m sca rules show ID", "One rule in full.", "عرض قاعدة كاملة."),
    ("python -m sca rules disable ID", "Switch a rule off (enable = on again).",
     "تعطيل قاعدة (enable لإعادتها)."),
    ("python -m sca rules disable --origin imported --lang swift",
     "Switch off every rule that matches the filters.", "تعطيل كل القواعد المطابقة للفلاتر."),
    ("python -m sca rules edit ID --set severity=low --set confidence=0.4",
     "Change fields of a rule.", "تعديل حقول قاعدة."),
    ("python -m sca rules reset ID", "Undo your changes to a shipped rule.",
     "التراجع عن تعديلاتك على قاعدة مرفقة."),
    ("python -m sca rules template > my-rule.yaml", "An empty rule to fill in.",
     "قالب قاعدة فارغ لتملأه."),
    ("python -m sca rules new my-rule.yaml", "Add your own rule from a file.",
     "إضافة قاعدتك من ملف."),
    ("python -m sca rules test ID PATH", "Show the lines a rule marks in a file or folder.",
     "عرض الأسطر التي تعلّمها قاعدة في ملف أو مجلد."),
    ("python -m sca rules export --origin custom -o rules.yaml", "Export your rules.",
     "تصدير قواعدك."),
    ("python -m sca feedback fp ID", "Mark a finding as a false positive (tp = real).",
     "تعليم نتيجة كإنذار كاذب (tp = حقيقية)."),
    ("python -m sca coverage", "Rules per language and weakness.",
     "عدد القواعد لكل لغة وثغرة."),
    ("python -m sca doctor", "Which engines and AI components are available.",
     "المحركات ومكوّنات الذكاء الاصطناعي المتاحة."),
    ("python -m sca history", "Earlier scans.", "الفحوص السابقة."),
]

RULE_GUIDE_EN = """
#### What a rule is

A rule is one regular expression that marks a dangerous line, plus the information shown
with the finding. The engine reads each code line (comments and very long generated lines
are skipped) and reports the line if `pattern` matches and `exclude` does not.

| Field | Meaning |
|---|---|
| `id` | Unique name, for example `MY-SQLI-001`. |
| `title` | Short description shown in the findings list. |
| `languages` | The languages the rule applies to, or `any`. TypeScript uses the JavaScript rules, C++ the C rules, Kotlin/Scala/Groovy the Java rules. |
| `cwe` | The weakness, as a CWE number (`CWE-89` = SQL injection). It decides the explanation, the fix text and the OWASP category. |
| `severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `confidence` | 0 to 1: how sure the rule is on its own. Start a new rule around 0.5 to 0.6; your reviews move it. |
| `pattern` | Regular expression (Python `re` syntax) that marks a vulnerable line. |
| `exclude` | Optional expression; if it also matches, the line is ignored. This is how a rule is taught about a safe variant. |
| `ignore_case` | Match upper and lower case alike. |
| `near`, `within` | Optional context: the rule fires only if `near` matches a line at most `within` lines above or below. For patterns that are ordinary code on their own. |
| `requires_taint` | `true` = report only when a variable on the line was filled from user input in the lines above. For rules that name a common function. |
| `message`, `fix` | Optional explanation and advice shown with the finding. |
| `examples_vulnerable` | Lines the rule must match. Checked every time the rule is saved. |
| `examples_safe` | Lines the rule must not match. |

#### Writing a good rule

1. Start from a real vulnerable line and a safe version of the same line.
2. Anchor the expression on a literal name (a function or API), then describe what makes
   the call dangerous: `db\\.query\\(\\s*"[^"]*"\\s*\\+` means "db.query( followed by a string
   and a +", which is string concatenation into SQL.
3. Put the safe variant in `exclude` instead of making `pattern` complicated.
4. Avoid `.*` at both ends and nested repetition such as `(a+)+`: they make a rule slow and
   broad. The tool refuses an expression that does not finish on its stress lines.
5. Add both kinds of examples. They are your regression test.
6. Use **Try an expression** to see what the rule marks in real code before saving.

#### What happens when you save

The tool checks the rule first. **Errors** block saving: a missing field, an expression
that does not compile or is too slow, an example of its own that the rule fails.
**Warnings** inform you but do not block: the rule matches everyday code or known-safe
code, or repeats another rule.

#### Editing rules that ship with the tool

Built-in and imported rules are never rewritten. Your change (a new severity, a stricter
pattern, or simply switching the rule off) is stored in `learned/edits.yaml`. It survives
an update of the tool, and **Restore original** removes it.

#### Where the rules are stored

| Origin | File | Changed by |
|---|---|---|
| built-in | `sca/rules/*.yaml` | the project (edit through the Rules tab) |
| imported | `sca/rules/imported/*.yaml` | `tools/import_rules.py` |
| learned | `learned/rules.yaml` | the Learning tab, after your approval |
| your own | `learned/custom.yaml` | the Rules tab, `python -m sca rules new` |
| your edits | `learned/edits.yaml` | the Rules tab, `python -m sca rules edit` |
| exclusions | `learned/overrides.yaml` | approved exclusions from the Learning tab |
"""

RULE_GUIDE_AR = """
#### ما هي القاعدة؟

القاعدة تعبير نمطي واحد يعلّم السطر الخطر، مع المعلومات التي تظهر مع النتيجة. يقرأ المحرك
كل سطر كود (تُتجاوز التعليقات والأسطر الطويلة جداً المولَّدة آلياً) ويبلّغ عن السطر إذا
طابقه `pattern` ولم يطابقه `exclude`.

| الحقل | المعنى |
|---|---|
| `id` | اسم فريد، مثل `MY-SQLI-001`. |
| `title` | وصف قصير يظهر في قائمة النتائج. |
| `languages` | اللغات التي تنطبق عليها القاعدة، أو `any` للجميع. TypeScript تستخدم قواعد JavaScript، و C++ قواعد C، و Kotlin و Scala و Groovy قواعد Java. |
| `cwe` | نوع الثغرة برقم CWE (مثل `CWE-89` لحقن SQL). منه يؤخذ الشرح ونص الإصلاح وفئة OWASP. |
| `severity` | الخطورة: `critical` أو `high` أو `medium` أو `low` أو `info`. |
| `confidence` | من 0 إلى 1: مدى ثقة القاعدة بنفسها. ابدأ القاعدة الجديدة بين 0.5 و 0.6، ومراجعاتك تحرّكها. |
| `pattern` | تعبير نمطي (بصيغة مكتبة `re` في بايثون) يعلّم السطر المصاب. |
| `exclude` | تعبير اختياري، إن طابق السطر أيضاً فيُتجاهل. بهذا تتعلّم القاعدة الصيغة الآمنة. |
| `ignore_case` | عدم التفريق بين الأحرف الكبيرة والصغيرة. |
| `near` و `within` | سياق اختياري: لا تعمل القاعدة إلا إذا طابق `near` سطراً يبعد `within` أسطر على الأكثر فوق السطر أو تحته. للأنماط التي هي كود عادي بمفردها. |
| `requires_taint` | القيمة `true` تعني: بلّغ فقط إذا كان متغيّر في السطر قد أُخذ من مدخلات المستخدم في الأسطر السابقة. للقواعد التي تذكر دالة شائعة. |
| `message` و `fix` | شرح ونصيحة اختياريان يظهران مع النتيجة. |
| `examples_vulnerable` | أسطر يجب أن تطابقها القاعدة. تُفحص عند كل حفظ. |
| `examples_safe` | أسطر يجب ألّا تطابقها القاعدة. |

#### كتابة قاعدة جيدة

1. ابدأ من سطر مصاب حقيقي ومن نسخة آمنة للسطر نفسه.
2. ثبّت التعبير على اسم حرفي (دالة أو واجهة)، ثم صِف ما يجعل الاستدعاء خطراً. مثلاً
   `db\\.query\\(\\s*"[^"]*"\\s*\\+` تعني: db.query( يتبعها نص ثم علامة +، أي دمج نص داخل SQL.
3. ضع الصيغة الآمنة في `exclude` بدلاً من تعقيد `pattern`.
4. تجنّب `.*` في الطرفين والتكرار المتداخل مثل `(a+)+` لأنهما يجعلان القاعدة بطيئة
   وواسعة. الأداة ترفض التعبير الذي لا ينتهي على أسطر الإجهاد.
5. أضف النوعين من الأمثلة، فهي اختبارك عند أي تعديل لاحق.
6. استخدم **تجربة تعبير** لترى ما تعلّمه القاعدة في كود حقيقي قبل الحفظ.

#### ماذا يحدث عند الحفظ؟

تفحص الأداة القاعدة أولاً. **الأخطاء** تمنع الحفظ: حقل ناقص، أو تعبير لا يُترجَم أو بطيء
جداً، أو مثال من أمثلة القاعدة تفشل فيه. **التحذيرات** تُعلمك ولا تمنع: القاعدة تطابق
كوداً عادياً أو كوداً معروفاً أنه آمن، أو تكرّر قاعدة أخرى.

#### تعديل القواعد المرفقة مع الأداة

القواعد المدمجة والمستوردة لا يُعاد كتابة ملفاتها. تعديلك (خطورة جديدة، أو نمط أدق، أو
مجرد تعطيل القاعدة) يُحفظ في `learned/edits.yaml`، فيبقى بعد تحديث الأداة، وزر
**استرجاع الأصل** يزيله.

#### أين تُحفظ القواعد؟

| المصدر | الملف | من يغيّره |
|---|---|---|
| مدمجة | `sca/rules/*.yaml` | المشروع (عدّلها من تبويب القواعد) |
| مستوردة | `sca/rules/imported/*.yaml` | السكربت `tools/import_rules.py` |
| متعلَّمة | `learned/rules.yaml` | تبويب التعلّم بعد مصادقتك |
| قواعدك | `learned/custom.yaml` | تبويب القواعد أو `python -m sca rules new` |
| تعديلاتك | `learned/edits.yaml` | تبويب القواعد أو `python -m sca rules edit` |
| الاستثناءات | `learned/overrides.yaml` | الاستثناءات المصادَق عليها في تبويب التعلّم |
"""


def setting(key: str, lang: str) -> Tuple[str, str]:
    """(label, help) of a setting in the given language ("en" or "ar")."""
    item = SETTINGS[key]
    index = 1 if lang == "ar" else 0
    return item["label"][index], item["help"][index]
