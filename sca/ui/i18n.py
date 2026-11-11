"""Arabic texts of the dashboard. English is the source language: a text that is missing
here is shown in English. Placeholders such as %s and %d must stay in the same order."""
from __future__ import annotations

AR = {
    # ---- tabs
    "Dashboard": "اللوحة", "Findings": "النتائج", "Rules": "القواعد", "Learning": "التعلّم",
    "Reports": "التقارير", "History": "السجل", "Guide": "التعليمات",
    # ---- sidebar
    " (not installed)": " (غير منصَّب)",
    "1. Project folder": "1. مجلد المشروع",
    "2. Static engines": "2. المحركات الستاتيكية",
    "3. Artificial intelligence": "3. الذكاء الاصطناعي",
    "4. Precision": "4. الدقة",
    "5. Output": "5. المخرجات",
    "Static + AI vulnerability detection that learns - v%s":
        "كشف ثغرات ستاتيكي وبالذكاء الاصطناعي مع تعلّم مستمر - الإصدار %s",
    "%d active rules of %d - manage them in the Rules tab":
        "%d قاعدة فعّالة من %d - تُدار من تبويب القواعد",
    "More engine options": "خيارات إضافية للمحركات",
    "More AI options": "خيارات إضافية للذكاء الاصطناعي",
    "AI provider ready: %s": "مزوّد الذكاء الاصطناعي جاهز: %s",
    "AI provider not ready: %s. The static scan works without it.":
        "مزوّد الذكاء الاصطناعي غير جاهز: %s. الفحص الستاتيكي يعمل بدونه.",
    "With this provider, the code under review is sent to %s. Secrets found by the tool are "
    "masked first. Choose Ollama to keep everything on this computer.":
        "مع هذا المزوّد يُرسَل الكود المفحوص إلى %s. تُحجب أولاً الأسرار التي تكتشفها الأداة. "
        "اختر Ollama ليبقى كل شيء على هذا الحاسوب.",
    "Saved to %s": "حُفظ في %s",
    "Choose a project folder first.": "اختر مجلد المشروع أولاً.",
    "This path does not exist: %s": "هذا المسار غير موجود: %s",
    "The scan failed: %s": "فشل الفحص: %s",
    # ---- dashboard tab
    "Scan a project to begin": "افحص مشروعاً للبدء",
    "Choose a folder in the sidebar and press **Run scan**. To see a full example, press "
    "**Use sample** first.":
        "اختر مجلداً من الشريط الجانبي واضغط **ابدأ الفحص**. لترى مثالاً كاملاً اضغط "
        "**استخدم العيّنة** أولاً.",
    "Static engines always run on this computer. The optional AI review uses the provider "
    "you choose: a local model (Ollama) or a cloud API.":
        "المحركات الستاتيكية تعمل دائماً على هذا الحاسوب. مراجعة الذكاء الاصطناعي الاختيارية "
        "تستخدم المزوّد الذي تختاره: نموذج محلي (Ollama) أو خدمة سحابية.",
    "%s - %s - %d files, %d lines, %.1f s": "%s - %s - %d ملف، %d سطر، %.1f ثانية",
    "Security score (grade %s)": "درجة الأمان (التقدير %s)",
    "Confirmed / open": "المؤكَّدة / المفتوحة",
    "Not counted in the score: ": "لا تدخل في الدرجة: ",
    "By severity": "حسب الخطورة",
    "By OWASP Top 10 category": "حسب فئات OWASP Top 10",
    "No open findings.": "لا توجد نتائج مفتوحة.",
    "Most affected files": "أكثر الملفات إصابة",
    "Engines": "المحركات",
    "Open": "مفتوحة", "Needs review": "تحتاج مراجعة",
    "Likely false positives (AI)": "إنذارات كاذبة على الأرجح (الذكاء الاصطناعي)",
    "Dismissed by you": "رفضتَها أنت",
    "Critical": "حرجة", "High": "عالية", "Medium": "متوسطة", "Low": "منخفضة", "Info": "معلومة",
    "Engine": "المحرك", "Status": "الحالة", "Line": "السطر", "Tier": "التصنيف",
    "Confidence %": "الثقة %", "ML %": "المصنّف %", "AI": "الذكاء الاصطناعي",
    "Id": "المعرّف", "Failed checks": "الفحوص الفاشلة", "Approved": "تاريخ المصادقة",
    "Confirmed": "مؤكَّدة", "False positives": "إنذارات كاذبة",
    "Written confidence": "الثقة المكتوبة", "Adjusted confidence": "الثقة المعدَّلة",
    "Check": "الفحص", "Result": "النتيجة", "Detail": "التفصيل",
    "No folder was chosen (or the folder dialog is not available here). You can paste the "
    "path instead.": "لم يُختر مجلد (أو أن نافذة الاختيار غير متاحة هنا). يمكنك لصق المسار.",
    "%d candidate(s) proposed: %d passed validation, %d rejected automatically.":
        "اقتُرحت %d قاعدة: %d نجحت في الفحوص و %d رُفضت آلياً.",
    "%d exclusion(s) proposed.": "اقتُرح %d استثناء.",
    "Rejected %s.": "رُفضت %s.", "Removed learned rule %s.": "حُذفت القاعدة المتعلَّمة %s.",
    "Approved %s. It is active from the next scan.": "صودق على %s. تعمل من الفحص القادم.",
    "Change all the rules shown (%d)": "غيّر كل القواعد المعروضة (%d)",
    "Applies to every rule in the table above. Use the filters first to choose which ones.":
        "يُطبَّق على كل قاعدة في الجدول أعلاه. استخدم الفلاتر أولاً لتحديد المطلوب.",
    "Enable all shown": "فعّل كل المعروض", "Disable all shown": "عطّل كل المعروض",
    "Enabled %d rules.": "فُعّلت %d قاعدة.", "Disabled %d rules.": "عُطّلت %d قاعدة.",
    # ---- findings tab
    "No scan yet.": "لم يُجرَ فحص بعد.",
    "No findings. A clean scan is not a proof of security.":
        "لا توجد نتائج. الفحص النظيف ليس دليلاً على الأمان.",
    "Show": "اعرض", "All": "الكل", "Severity": "الخطورة", "File": "الملف",
    "Search (title, CWE, code)": "بحث (العنوان، CWE، الكود)",
    "%d of %d findings. Your reviews are remembered: a finding you dismiss stays dismissed "
    "in later scans, and each review adjusts the confidence of the rule that produced it.":
        "%d من %d نتيجة. مراجعاتك محفوظة: النتيجة التي ترفضها تبقى مرفوضة في الفحوص "
        "القادمة، وكل مراجعة تعدّل ثقة القاعدة التي أنتجتها.",
    "Details": "التفاصيل",
    "Risk": "الخطر", "Confidence": "الثقة", "ML score": "درجة المصنّف",
    "AI verdict": "حكم الذكاء الاصطناعي",
    "Confirmed: ": "مؤكَّدة: ",
    "Probable: a rule matched and no independent evidence confirms it yet%s.":
        "محتملة: طابقت قاعدة ولا يوجد بعد دليل مستقل يؤكدها%s.",
    "Flagged line: %d - found by: %s - rule: %s": "السطر: %d - وجدها: %s - القاعدة: %s",
    "**Why it matters**": "**لماذا هي خطرة**",
    "**How to fix**": "**طريقة الإصلاح**",
    "**AI review** (%s)": "**مراجعة الذكاء الاصطناعي** (%s)",
    "Reference: %s": "المرجع: %s",
    "Real vulnerability": "ثغرة حقيقية", "False positive": "إنذار كاذب",
    "Clear my review": "امسح مراجعتي",
    "Showing the first 150. Use the filters, or download the full report.":
        "تُعرض أول 150 نتيجة. استخدم الفلاتر أو نزّل التقرير الكامل.",
    # ---- learning tab
    "Active rules": "القواعد الفعّالة", "Learned rules": "القواعد المتعلَّمة",
    "Waiting for approval": "تنتظر المصادقة", "Your reviews": "مراجعاتك",
    "Quarantined rules": "القواعد المحجورة",
    "The AI proposes, the tool validates, you approve. A proposed rule becomes active only "
    "after it passes every automatic check and you approve it.":
        "الذكاء الاصطناعي يقترح، والأداة تفحص، وأنت تصادق. القاعدة المقترحة لا تُفعَّل إلا "
        "بعد نجاحها في كل الفحوص الآلية ومصادقتك عليها.",
    "Teach the tool": "علّم الأداة",
    "Learning needs a working AI provider (section 3 of the sidebar).":
        "التعلّم يحتاج مزوّد ذكاء اصطناعي يعمل (القسم 3 في الشريط الجانبي).",
    "**From the current scan**": "**من الفحص الحالي**",
    "Uses what the AI found or rejected in the last scan. Run the scan with *AI review* and "
    "*Deep scan* switched on.":
        "يستخدم ما اكتشفه أو رفضه الذكاء الاصطناعي في آخر فحص. شغّل الفحص مع *مراجعة "
        "النتائج* و*الفحص العميق*.",
    "Learn from this scan": "تعلّم من هذا الفحص",
    "**Fill gaps for a language**": "**املأ فجوات لغة**",
    "Language": "اللغة",
    "%d weaknesses without a rule in %d languages (up to %d AI requests)":
        "%d ثغرة بلا قاعدة في %d لغة (حتى %d طلباً للذكاء الاصطناعي)",
    "Weaknesses without a rule: %s": "ثغرات بلا قاعدة: %s",
    "Write rules for the gaps": "اكتب قواعد للفجوات",
    "**From your false positives**": "**من إنذاراتك الكاذبة**",
    "Proposes a narrow exclusion for each finding you dismissed, so the rule stops reporting "
    "that kind of safe code.":
        "يقترح استثناءً ضيقاً لكل نتيجة رفضتَها، فتتوقف القاعدة عن التبليغ عن هذا النوع من "
        "الكود الآمن.",
    "Learn exclusions": "تعلّم الاستثناءات",
    "Proposing and validating rules": "اقتراح القواعد وفحصها",
    "Asking the model for rules": "طلب القواعد من النموذج",
    "Proposing and validating exclusions": "اقتراح الاستثناءات وفحصها",
    "Waiting for your approval (%d)": "تنتظر مصادقتك (%d)",
    "Nothing is waiting.": "لا شيء ينتظر.",
    "%s - proposed by %s - origin: %s": "%s - اقترحها %s - المصدر: %s",
    "Written from the model's own knowledge, without an example from a real project. Its "
    "only evidence is the examples below.":
        "كُتبت من معرفة النموذج نفسه، بلا مثال من مشروع حقيقي. دليلها الوحيد هو الأمثلة أدناه.",
    "**Lines matching this are skipped by the rule**": "**الأسطر المطابقة لهذا تتجاوزها القاعدة**",
    "**Pattern**": "**النمط**",
    "**Unless the line also matches**": "**إلا إذا طابق السطر أيضاً**",
    "**Learned from** `%s`": "**تُعلِّمت من** `%s`",
    "**Must match**": "**يجب أن تطابق**", "**Must not match**": "**يجب ألّا تطابق**",
    "**Automatic checks**": "**الفحوص الآلية**",
    "**What it would flag in the scanned project (%d lines)**":
        "**ما ستبلّغ عنه في المشروع المفحوص (%d سطر)**",
    "Approve": "صادِق", "Reject": "ارفض",
    "Rejected automatically (%d most recent)": "رُفضت آلياً (آخر %d)",
    "Learned rules (%d)": "القواعد المتعلَّمة (%d)",
    "Remove a learned rule": "احذف قاعدة متعلَّمة", "Remove rule": "احذف القاعدة",
    "No learned rules yet. They are stored in learned/rules.yaml.":
        "لا قواعد متعلَّمة بعد. تُحفظ في learned/rules.yaml.",
    "Rule track record": "سجل أداء القواعد",
    "No reviews yet. Use the buttons under each finding to confirm or dismiss it.":
        "لا مراجعات بعد. استخدم الأزرار تحت كل نتيجة لتأكيدها أو رفضها.",
    "Coverage: rules per language and weakness": "التغطية: عدد القواعد لكل لغة وثغرة",
    "Python is analysed mainly by the AST taint engine; its few pattern rules are imported "
    "ones. Languages without rules are still covered by the AI deep scan, and by "
    "Opengrep/Semgrep when installed.":
        "بايثون يحلّلها أساساً محرك AST، وقواعد الأنماط القليلة لها مستوردة. اللغات التي بلا "
        "قواعد يغطيها الفحص العميق بالذكاء الاصطناعي، و Opengrep/Semgrep إن كان منصَّباً.",
    # ---- reports and history
    "Download the results of the current scan.": "نزّل نتائج الفحص الحالي.",
    "HTML report": "تقرير HTML", "PDF report": "تقرير PDF",
    "PDF unavailable: %s": "ملف PDF غير متاح: %s",
    "The HTML report contains everything, including Arabic text. The PDF uses built-in fonts "
    "and leaves non-Latin text out. SARIF can be uploaded to GitHub code scanning or opened "
    "in VS Code.":
        "تقرير HTML يحتوي كل شيء بما فيه النص العربي. تقرير PDF يستخدم خطوطاً مدمجة ويحذف "
        "النص غير اللاتيني. ملف SARIF يُرفع إلى GitHub code scanning أو يُفتح في VS Code.",
    "No saved scans yet.": "لا فحوص محفوظة بعد.",
    "Project": "المشروع", "Security score over time": "درجة الأمان عبر الزمن",
    "Open a saved scan": "افتح فحصاً محفوظاً", "Load this scan": "حمّل هذا الفحص",
    # ---- rules tab
    "All rules": "كل القواعد", "Active": "الفعّالة", "Active / total": "الفعّالة / الكل",
    "%d of them active": "الفعّال منها %d",
    "Built in": "مدمجة", "Imported": "مستوردة", "Learned": "متعلَّمة", "Your own": "قواعدك",
    "Edited by you": "عدّلتَها",
    "Every rule the tool knows. Browse and filter them, read and change any field, switch a "
    "rule off or on, write your own, and try an expression on code. Nothing here needs the AI.":
        "كل القواعد التي تعرفها الأداة. تصفّحها وفلترها، واقرأ أي حقل وغيّره، وعطّل قاعدة أو "
        "فعّلها، واكتب قاعدتك، وجرّب تعبيراً على كود. لا شيء هنا يحتاج الذكاء الاصطناعي.",
    "Browse and edit": "تصفّح وتعديل", "New rule": "قاعدة جديدة",
    "Try an expression": "تجربة تعبير", "Import and export": "استيراد وتصدير",
    "Origin": "المصدر", "Weakness": "الثغرة", "State": "الحالة",
    "Enabled": "مفعّلة", "Disabled": "معطّلة", "Credential formats": "صيغ المفاتيح",
    "Search (id, title, expression)": "بحث (الاسم، العنوان، التعبير)",
    "Built in: written with the tool. Imported: converted from DevSkim and Gitleaks. Learned: "
    "proposed by the AI and approved by you. Your own: written by you.":
        "مدمجة: كُتبت مع الأداة. مستوردة: حُوِّلت من DevSkim و Gitleaks. متعلَّمة: اقترحها "
        "الذكاء الاصطناعي وصادقتَ عليها. قواعدك: كتبتَها أنت.",
    "%d of %d rules.": "%d من %d قاعدة.",
    "Rule": "القاعدة", "Source": "الأصل", "Title": "العنوان", "Languages": "اللغات",
    "on": "تعمل", "off": "متوقفة",
    "Download these rules (YAML)": "نزّل هذه القواعد (YAML)",
    "Rule details": "تفاصيل القاعدة", "Choose a rule": "اختر قاعدة",
    "enabled": "مفعّلة", "DISABLED": "معطّلة", "edited by you": "عدّلتَها",
    "credential format": "صيغة مفتاح",
    "Source: %s": "الأصل: %s",
    "Disable": "عطّل", "Enable": "فعّل", "Restore original": "استرجاع الأصل",
    "Delete rule": "احذف القاعدة", "Save changes": "احفظ التعديلات", "Remove": "احذف",
    "The rule stays in the list but takes no part in scans.":
        "تبقى القاعدة في القائمة لكنها لا تشارك في الفحص.",
    "Undo every change you made to this rule.": "التراجع عن كل تعديلاتك على هذه القاعدة.",
    "In your reviews: %d confirmed, %d false positives. Confidence used in scans: %.2f%s":
        "في مراجعاتك: %d مؤكَّدة و %d إنذاراً كاذباً. الثقة المستخدمة في الفحص: %.2f%s",
    " - QUARANTINED (not counted until you confirm one of its findings)":
        " - محجورة (لا تُحتسب حتى تؤكّد إحدى نتائجها)",
    "This rule ships with the tool. Your changes are stored in learned/edits.yaml and can be "
    "undone with 'Restore original'.":
        "هذه القاعدة مرفقة مع الأداة. تعديلاتك تُحفظ في learned/edits.yaml ويمكن التراجع "
        "عنها بزر «استرجاع الأصل».",
    "The original definition": "التعريف الأصلي",
    "Approved exclusions of this rule": "الاستثناءات المصادَق عليها لهذه القاعدة",
    "Weakness (CWE)": "الثغرة (CWE)",
    "Pattern (regular expression that marks a vulnerable line)":
        "النمط (تعبير نمطي يعلّم السطر المصاب)",
    "Exclude (optional: if this also matches, the line is ignored)":
        "الاستثناء (اختياري: إن طابق السطر أيضاً فيُتجاهل)",
    "Ignore upper/lower case": "تجاهل حالة الأحرف",
    "Context (optional: must match a neighbouring line)":
        "السياق (اختياري: يجب أن يطابق سطراً مجاوراً)",
    "Use it when the pattern alone is ordinary code and the lines around it make it a "
    "weakness, for example a random number used near the word token.":
        "استخدمه حين يكون النمط وحده كوداً عادياً والأسطر المحيطة هي ما يجعله ثغرة، مثل رقم "
        "عشوائي قرب كلمة token.",
    "Within lines": "ضمن أسطر",
    "How many lines above and below are searched for the context.":
        "عدد الأسطر فوق السطر وتحته التي يُبحث فيها عن السياق.",
    "Only when user input is traced to the line": "فقط إذا تُتبِّعت مدخلات المستخدم إلى السطر",
    "For rules that name a common function (opening a file, running a query): the rule stays "
    "silent unless a variable on the line was filled from the request a few lines earlier.":
        "للقواعد التي تذكر دالة شائعة (فتح ملف أو تنفيذ استعلام): تبقى القاعدة صامتة ما لم "
        "يكن متغيّر في السطر قد أُخذ من الطلب قبل بضعة أسطر.",
    "Why it is dangerous (optional)": "لماذا هي خطرة (اختياري)",
    "How to fix it (optional)": "طريقة الإصلاح (اختياري)",
    "Lines the rule must match (one per line)": "أسطر يجب أن تطابقها القاعدة (سطر لكل مثال)",
    "Lines the rule must NOT match (one per line)":
        "أسطر يجب ألّا تطابقها القاعدة (سطر لكل مثال)",
    "Short description shown in the findings list.": "وصف قصير يظهر في قائمة النتائج.",
    "The languages the rule applies to. 'any' means every file. TypeScript uses the "
    "JavaScript rules, C++ the C rules, and Kotlin, Scala and Groovy the Java rules.":
        "اللغات التي تنطبق عليها القاعدة. any تعني كل الملفات. TypeScript تستخدم قواعد "
        "JavaScript، و C++ قواعد C، و Kotlin و Scala و Groovy قواعد Java.",
    "The kind of weakness as a CWE number, for example CWE-89 for SQL injection. It decides "
    "the explanation, the fix text and the OWASP category shown with the finding.":
        "نوع الثغرة برقم CWE، مثل CWE-89 لحقن SQL. منه يؤخذ الشرح ونص الإصلاح وفئة OWASP "
        "المعروضة مع النتيجة.",
    "How bad the weakness is if it is real. It weighs on the score.":
        "مدى خطورة الثغرة إن كانت حقيقية. تؤثر في الدرجة.",
    "How sure the rule is on its own, from 0 to 1. Lower it for a rule that is often wrong; "
    "your reviews also move it automatically.":
        "مدى ثقة القاعدة بنفسها من 0 إلى 1. اخفضها لقاعدة كثيرة الخطأ، ومراجعاتك تحرّكها "
        "تلقائياً أيضاً.",
    "Python regular-expression syntax. The rule reports a code line when this matches it.":
        "بصيغة التعابير النمطية في بايثون. تبلّغ القاعدة عن سطر الكود إذا طابقه هذا التعبير.",
    "Use it to describe the safe variant of the same call, instead of making the pattern "
    "complicated.":
        "استخدمه لوصف الصيغة الآمنة للاستدعاء نفسه بدلاً من تعقيد النمط.",
    "Checked every time the rule is saved, so a later edit cannot silently break it.":
        "تُفحص عند كل حفظ، فلا يكسر تعديل لاحق القاعدة دون أن تعلم.",
    "This is a credential format: it is run by the secrets engine, and what it finds is "
    "masked in every report.":
        "هذه صيغة مفتاح: يشغّلها محرك الأسرار، وما تجده يُحجب في كل التقارير.",
    "Write your own rule. It is stored in learned/custom.yaml and takes part in the next "
    "scan. The Guide tab explains every field.":
        "اكتب قاعدتك. تُحفظ في learned/custom.yaml وتشارك في الفحص القادم. تبويب التعليمات "
        "يشرح كل حقل.",
    "Rule id": "اسم القاعدة",
    "A unique name: letters, digits, '-', '_' or '.'.":
        "اسم فريد: أحرف وأرقام و '-' و '_' و '.'.",
    "Check the rule": "افحص القاعدة", "Save the rule": "احفظ القاعدة",
    "Tests the rule without saving it.": "يختبر القاعدة دون حفظها.",
    "The rule cannot be saved:": "لا يمكن حفظ القاعدة:",
    "The rule can be saved. Look at these points first:":
        "يمكن حفظ القاعدة. انظر في هذه النقاط أولاً:",
    "The rule passed every check.": "نجحت القاعدة في كل الفحوص.",
    "Download an empty rule file (YAML template)": "نزّل ملف قاعدة فارغاً (قالب YAML)",
    "See which lines an expression marks, before you put it in a rule. The expression runs "
    "in a separate process with a time limit, so a bad one cannot freeze the tool.":
        "شاهد أي الأسطر يعلّمها التعبير قبل وضعه في قاعدة. يعمل التعبير في عملية منفصلة بحدّ "
        "زمني، فلا يجمّد التعبيرُ السيئ الأداةَ.",
    "Start from an existing rule (optional)": "ابدأ من قاعدة موجودة (اختياري)",
    "Pattern": "النمط", "Exclude (optional)": "الاستثناء (اختياري)",
    "Code to test on (paste some lines)": "الكود المراد التجربة عليه (الصق بعض الأسطر)",
    "Run the expression": "شغّل التعبير",
    "Give an expression and some code.": "أدخل تعبيراً وبعض الكود.",
    "The expression failed: %s": "فشل التعبير: %s",
    "%d of %d lines matched.": "طابق %d من %d سطر.",
    "Export": "تصدير", "Import": "استيراد",
    "Save rules to a file, to back them up or use them on another computer.":
        "احفظ القواعد في ملف لنسخها احتياطياً أو استخدامها على حاسوب آخر.",
    "Your own rules": "قواعدك", "Every rule (%d)": "كل القواعد (%d)",
    "Add rules from a YAML file. Each rule is checked first and is stored as one of your own "
    "rules.":
        "أضف قواعد من ملف YAML. تُفحص كل قاعدة أولاً وتُحفظ ضمن قواعدك.",
    "Rule file (.yaml)": "ملف القواعد (‎.yaml)", "Import the rules": "استورد القواعد",
    "Added: %s": "أُضيفت: %s",
    "Enabled %s.": "فُعّلت %s.", "Disabled %s.": "عُطّلت %s.", "Deleted %s.": "حُذفت %s.",
    "Saved %s.": "حُفظت %s.", "Not saved: %s": "لم تُحفظ: %s",
    "Added %s. It is active from the next scan.": "أُضيفت %s. تعمل من الفحص القادم.",
    "Restored %s to its original definition.": "أُعيدت %s إلى تعريفها الأصلي.",
    "Removed the exclusion from %s.": "حُذف الاستثناء من %s.",
    # ---- guide tab
    "Quick start": "البدء السريع", "Every setting": "كل الإعدادات",
    "Writing rules": "كتابة القواعد", "Diagrams": "المخططات", "Command line": "سطر الأوامر",
    "References and limits": "المراجع والحدود", "Full documents": "الوثائق الكاملة",
    "How to use the tool": "طريقة استخدام الأداة",
    "What each tab is for": "وظيفة كل تبويب",
    "Tab": "التبويب", "What it shows": "ماذا يعرض",
    "The dashboard after scanning the sample application": "اللوحة بعد فحص التطبيق التجريبي",
    "The steps as a diagram": "الخطوات كمخطط",
    "Every control of the sidebar, what it does and when to change it. The same text appears "
    "as the (?) tooltip next to each control.":
        "كل عناصر الشريط الجانبي، وماذا يفعل كل واحد ومتى تغيّره. النص نفسه يظهر عند علامة "
        "(?) بجانب كل عنصر.",
    "Setting": "الإعداد", "What it does": "ماذا يفعل",
    "The rule set today": "مجموعة القواعد الآن",
    "Where they come from": "من أين جاءت",
    "Written and tested with this tool, per language.": "كُتبت واختُبرت مع هذه الأداة، لكل لغة.",
    "Converted from Microsoft DevSkim (code patterns) and Gitleaks (credential formats), both "
    "MIT licensed. Each rule was checked automatically and measured on 2.4 million lines of "
    "well-known open-source code; noisy ones ship switched off.":
        "حُوِّلت من Microsoft DevSkim (أنماط الكود) و Gitleaks (صيغ المفاتيح)، وكلاهما برخصة "
        "MIT. فُحصت كل قاعدة آلياً وقيست على 2.4 مليون سطر من كود مفتوح المصدر معروف، "
        "والمزعجة منها تأتي معطَّلة.",
    "Proposed by the AI, validated automatically, approved by you in the Learning tab.":
        "اقترحها الذكاء الاصطناعي وفُحصت آلياً وصادقتَ عليها في تبويب التعلّم.",
    "Written by you in the Rules tab or in a YAML file.":
        "كتبتَها أنت في تبويب القواعد أو في ملف YAML.",
    "An empty rule to start from": "قاعدة فارغة تبدأ منها",
    "Seven diagrams explain the project from the general picture to the details. Each one "
    "starts with what it means.":
        "سبعة مخططات تشرح المشروع من الصورة العامة إلى التفاصيل. بعد كل مخطط شرح معناه.",
    "Show each diagram in both languages": "اعرض كل مخطط باللغتين",
    "Everything the dashboard does can also be done from a terminal, in the project folder.":
        "كل ما تفعله الواجهة يمكن فعله من الطرفية أيضاً، داخل مجلد المشروع.",
    "References": "المراجع", "Limits": "الحدود",
    "The documents of the repository, readable here with their images.":
        "وثائق المستودع، تُقرأ هنا مع صورها.",
    "Document": "الوثيقة",
}
