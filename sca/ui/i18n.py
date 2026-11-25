"""Arabic texts of the dashboard. English is the source language: a text that is missing
here is shown in English. Placeholders such as %s and %d must stay in the same order."""
from __future__ import annotations

AR = {
    # ---- tabs
    "Dashboard": "اللوحة", "Findings": "النتائج", "Rules": "القواعد", "Learning": "التعلّم",
    "Reports": "التقارير", "History": "السجل", "Guide": "التعليمات",
    # ---- sidebar
    " (not installed)": " (غير منصَّب)",
    " (%s not installed)": " (%s غير منصَّب)",
    "1. Project folder or app": "1. مجلد المشروع أو التطبيق",
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
    "Choose a project folder or an app file first.": "اختر مجلد المشروع أو ملف التطبيق أولاً.",
    "This path does not exist: %s": "هذا المسار غير موجود: %s",
    "The scan failed: %s": "فشل الفحص: %s",
    "Upload an app file": "ارفع ملف تطبيق",
    "An app file: it is decoded and read, never installed or run.":
        "ملف تطبيق: يُفكّ ويُقرأ، ولا يُثبَّت ولا يُشغَّل أبداً.",
    "A Flutter project: the Flutter / Android checks run as well.":
        "مشروع Flutter: تعمل فحوص Flutter و Android أيضاً.",
    "An Android project: the Flutter / Android checks run as well.":
        "مشروع Android: تعمل فحوص Flutter و Android أيضاً.",
    "The upload could not be saved: %s": "تعذّر حفظ الملف المرفوع: %s",
    "No app file was chosen (or the file dialog is not available here). You can paste the "
    "path instead.": "لم يُختر ملف تطبيق (أو أن نافذة الاختيار غير متاحة هنا). يمكنك لصق المسار.",
    "Only app files (.apk, .aab, .apks, .xapk, .apkm) can be uploaded.":
        "لا يمكن رفع إلا ملفات التطبيقات (‎.apk و ‎.aab و ‎.apks و ‎.xapk "
        "و ‎.apkm).",
    "This file is not a readable app package (it is not a ZIP archive): %s":
        "هذا الملف ليس حزمة تطبيق قابلة للقراءة (ليس أرشيف ZIP): %s",
    "The app file cannot be read: %s": "تعذّرت قراءة ملف التطبيق: %s",
    # ---- what the scan is doing (sca.pipeline.Message)
    "Scanning %s": "جارٍ فحص %s",
    "Starting": "البدء",
    "Scan finished in %.1f s: %d files, %d findings":
        "انتهى الفحص في %.1f ثانية: %d ملف، %d نتيجة",
    "What the scan did, step by step": "ماذا فعل الفحص، خطوة بخطوة",
    "Collecting the source files of %s": "جمع ملفات الكود المصدري في %s",
    "Left out %d test files": "استُبعد %d ملف اختبار",
    "%d files, %d lines: %s": "%d ملف، %d سطر: %s",
    "%s: skipped - %s": "%s: تُخطّي - %s",
    "%s: failed - %s": "%s: فشل - %s",
    "%s: file %d of %d - %s": "%s: الملف %d من %d - %s",
    "%s: %d found in %.1f s": "%s: وُجد %d في %.1f ثانية",
    "Secrets": "الأسرار",
    "Pattern rules": "قواعد الأنماط",
    "looking for keys, passwords and tokens": "البحث عن المفاتيح وكلمات المرور والرموز",
    "checking every line against the active rules": "مطابقة كل سطر مع القواعد الفعّالة",
    "Python AST": "تحليل بايثون (AST)",
    "C memory checks": "فحوص الذاكرة في C",
    "following pointers and outside data through each C function":
        "تتبّع المؤشرات والبيانات الخارجية داخل كل دالة C",
    "no C or C++ files": "لا توجد ملفات C أو C++",
    "following user input through the Python code": "تتبّع مدخلات المستخدم داخل كود بايثون",
    "running the Bandit analyzer on the Python files": "تشغيل محلّل Bandit على ملفات بايثون",
    "running the external rule engine": "تشغيل محرّك القواعد الخارجي",
    "searching the files for leaked credentials": "البحث في الملفات عن بيانات اعتماد مسرَّبة",
    "switched off": "معطَّل",
    "not installed": "غير منصَّب",
    "no Python files": "لا توجد ملفات بايثون",
    "Rules switched off after repeated false positives: %s":
        "قواعد أُوقفت بعد إنذارات كاذبة متكررة: %s",
    "Input tracing: checking whether user input reaches each finding":
        "تتبّع المدخلات: هل تصل مدخلات المستخدم إلى كل نتيجة؟",
    "Input tracing: user input reaches %d findings":
        "تتبّع المدخلات: تصل مدخلات المستخدم إلى %d نتيجة",
    "Merging: removing duplicates and combining the evidence of the engines":
        "الدمج: إزالة التكرار وجمع أدلة المحركات",
    "%d raw results merged into %d findings": "دُمجت %d نتيجة أولية في %d نتيجة",
    "%d findings are in test code: lower confidence, never confirmed automatically":
        "%d نتيجة في كود الاختبار: ثقة أقل، ولا تؤكَّد تلقائياً",
    "Your earlier reviews: %d dismissed, %d confirmed": "مراجعاتك السابقة: %d مستبعدة، %d مؤكَّدة",
    "ML classifier": "مصنِّف التعلّم الآلي",
    "ML classifier: a second opinion on each finding": "مصنِّف التعلّم الآلي: رأي ثانٍ في كل نتيجة",
    "ML classifier: scored %d findings": "مصنِّف التعلّم الآلي: قيّم %d نتيجة",
    "AI review": "مراجعة الذكاء الاصطناعي",
    "AI review: asking the model about the most severe findings":
        "مراجعة الذكاء الاصطناعي: سؤال النموذج عن أخطر النتائج",
    "AI review %d of %d: %s": "مراجعة الذكاء الاصطناعي %d من %d: %s",
    "AI deep scan %d of %d: %s": "الفحص العميق بالذكاء الاصطناعي %d من %d: %s",
    "AI verification %d of %d": "تحقّق الذكاء الاصطناعي %d من %d",
    "Scoring: the risk of each finding and the score of the project":
        "التقييم: خطورة كل نتيجة ودرجة المشروع",
    "Score %d/100, grade %s: %d open findings, %d confirmed":
        "الدرجة %d/100، التقدير %s: %d نتيجة مفتوحة، %d مؤكَّدة",
    "Scan finished in %.1f s": "انتهى الفحص في %.1f ثانية",
    "Saved in the history": "حُفظ في السجل",
    "Flutter/Android checks": "فحوص Flutter و Android",
    "checking the app's manifest, network and signing settings, build and dependencies":
        "فحص ملف manifest للتطبيق وإعدادات الشبكة والتوقيع والبناء والاعتماديات",
    "Unpacking the app %s": "فكّ حزمة التطبيق %s",
    "Decoded the app: %d files, %s build": "فُكّت حزمة التطبيق: %d ملف، ونوع البناء %s",
    "Found a Flutter project: %s": "وُجد مشروع Flutter: %s",
    "Found an Android project: %s": "وُجد مشروع Android: %s",
    "not used for app packages": "لا يُستخدم مع حزم التطبيقات",
    "no Flutter or Android files": "لا توجد ملفات Flutter أو Android",
    # build modes of a Flutter app (also shown in the app panel)
    "debug": "تصحيح (debug)", "profile": "قياس الأداء (profile)",
    "release": "إصدار (release)", "unknown": "غير معروف",
    # ---- Rules tab: file types and where a rule is defined
    "File types": "أنواع الملفات",
    "**Applies to:** %s": "**تُطبَّق على:** %s",
    "every file": "كل الملفات",
    " and the `<script>` code of %s pages": " وعلى كود `<script>` داخل صفحات %s",
    "Defined in %s": "معرّفة في %s",
    " - your changes are saved in learned/edits.yaml, the file itself stays as shipped":
        " - تعديلاتك تُحفظ في learned/edits.yaml ويبقى الملف الأصلي كما هو",
    # ---- dashboard tab
    "Scan a project to begin": "افحص مشروعاً للبدء",
    "Choose a folder or an app file (.apk, .aab) in the sidebar and press **Run scan**. To "
    "see a full example, press **Use sample** first.":
        "اختر مجلداً أو ملف تطبيق (‎.apk أو ‎.aab) من الشريط الجانبي واضغط **ابدأ "
        "الفحص**. لترى مثالاً كاملاً اضغط **استخدم العيّنة** أولاً.",
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
    "By OWASP Mobile Top 10 (2024)": "حسب فئات OWASP Mobile Top 10 (2024)",
    "By MASVS group": "حسب مجموعات MASVS",
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
    # ---- app panel of the Dashboard tab (sca/ui/app_panel.py)
    "Flutter app: %s": "تطبيق Flutter: %s", "Android app: %s": "تطبيق Android: %s",
    "Flutter project: %s": "مشروع Flutter: %s", "Android project: %s": "مشروع Android: %s",
    "Package": "الحزمة", "Version": "الإصدار", "Build mode": "نوع البناء",
    "Platforms": "المنصّات", "Min / target SDK": "SDK الأدنى / المستهدف",
    "SDK levels set in Gradle: %s": "مستويات SDK المحددة في Gradle: %s",
    "the Flutter SDK default": "القيمة الافتراضية في Flutter SDK",
    "About the app": "عن التطبيق", "Fact": "المعلومة", "Value": "القيمة",
    "Type": "النوع", "Name": "الاسم", "Size": "الحجم", "%.1f MB": "%.1f ميغابايت",
    "%d KB": "%d كيلوبايت",
    "Uses Flutter": "يستخدم Flutter", "Dart SDK constraint": "قيد إصدار Dart SDK",
    "Compile SDK": "إصدار SDK المستخدم في الترجمة (compileSdk)",
    "Debug manifests (not checked)": "ملفات manifest الخاصة بالتصحيح (لا تُفحص)",
    "ABIs": "معماريات المعالج (ABIs)", "Dart version": "إصدار Dart",
    "Flutter engine revision": "مراجعة محرك Flutter",
    "Snapshot hash": "بصمة اللقطة (snapshot)", "Snapshot features": "خصائص اللقطة (snapshot)",
    "Dart code obfuscated": "كود Dart مموَّه",
    "Debug symbols in libapp.so": "رموز التصحيح في libapp.so",
    "Dart source files recovered": "ملفات Dart المصدرية المستعادة",
    "DEX files, classes, strings": "ملفات DEX والأصناف والنصوص",
    "Plugins": "الإضافات (plugins)", "Debuggable": "قابل للتصحيح",
    "Backup allowed": "النسخ الاحتياطي مسموح", "Cleartext HTTP": "HTTP غير المشفّر",
    "Network security config": "إعدادات أمان الشبكة",
    "Dependency issues": "مشكلات الاعتماديات",
    "yes": "نعم", "no": "لا", "allowed": "مسموح", "not allowed": "غير مسموح",
    "allowed for some domains": "مسموح لبعض النطاقات", "default": "القيمة الافتراضية",
    "network security config": "إعدادات أمان الشبكة", "none": "لا يوجد",
    "default for targetSdk %d": "القيمة الافتراضية مع targetSdk %d",
    ", with backup rules": "، مع قواعد للنسخ الاحتياطي",
    "Permissions (%d, %d dangerous)": "الصلاحيات (%d، منها %d خطرة)",
    "Permission": "الصلاحية", "Dangerous": "خطرة", "None.": "لا يوجد.",
    "Signing": "التوقيع",
    "Signature schemes: %s. The signature is not verified cryptographically (apksigner did "
    "not run).": "مخططات التوقيع: %s. لم يُتحقَّق من التوقيع تشفيرياً (لم تعمل أداة apksigner).",
    "Signature schemes: %s. apksigner verified the signature.":
        "مخططات التوقيع: %s. تحقّقت أداة apksigner من صحة التوقيع.",
    "Signature schemes: %s. apksigner reports that the signature does not verify.":
        "مخططات التوقيع: %s. تفيد أداة apksigner بأن التوقيع غير صحيح.",
    "none (not signed)": "لا شيء (غير موقَّع)",
    "Subject": "صاحب الشهادة", "Issuer": "المُصدِر", "Valid": "مدة الصلاحية",
    "Key": "المفتاح", "Signature algorithm": "خوارزمية التوقيع",
    "Android debug certificate": "شهادة التصحيح في Android",
    "Components (%d, %d exported)": "المكوّنات (%d، منها %d مُصدَّرة)",
    "Exported": "مُصدَّر", "Launcher": "نقطة البدء (launcher)",
    "Deep links (%d)": "الروابط العميقة (%d)", "Link": "الرابط", "Opens": "يفتح",
    "Dart packages (%d)": "حزم Dart (%d)", "Found in": "وُجدت في",
    "Dependency": "نوع الاعتمادية",
    "Server addresses in the code (%d, %d without TLS)":
        "عناوين الخوادم في الكود (%d، منها %d دون TLS)",
    "Address": "العنوان", "Without TLS": "دون TLS",
    "Decoder warnings (%d)": "تحذيرات فك الترميز (%d)",
    "Parts of the app that could not be read as expected. Many unusual ones can be a sign "
    "that the package was changed to hinder analysis.":
        "أجزاء من التطبيق لم تُقرأ كما هو متوقع. كثرة الحالات غير المعتادة قد تدل على أن "
        "الحزمة عُدّلت لإعاقة التحليل.",
    "Android app (APK)": "تطبيق Android (APK)",
    "Android App Bundle (AAB)": "حزمة Android App Bundle (AAB)",
    "Set of APK files (APKS, XAPK, APKM)": "مجموعة ملفات APK (APKS أو XAPK أو APKM)",
    "Flutter project": "مشروع Flutter", "Android project": "مشروع Android",
    "Activity": "نشاط (Activity)", "Activity alias": "اسم بديل لنشاط (activity-alias)",
    "Service": "خدمة (Service)", "Broadcast receiver": "مستقبِل بث (Broadcast receiver)",
    "Content provider": "مزوّد محتوى (Content provider)",
    "Dart kernel (debug build)": "ملف kernel لـ Dart (نسخة التصحيح)",
    "Dart snapshot (libapp.so)": "لقطة Dart (libapp.so)",
    "License notices (NOTICES.Z)": "إشعارات الرخص (NOTICES.Z)",
    "Plugin registration (DEX)": "تسجيل الإضافات (DEX)",
    "Direct": "مباشرة", "Development only": "للتطوير فقط",
    "Overridden": "مُستبدَلة (override)", "Indirect": "غير مباشرة",
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
    "Files (optional: name patterns separated by commas)":
        "الملفات (اختياري: أنماط أسماء مفصولة بفواصل)",
    "The rule reads only the files of its languages whose path or name matches one of these "
    "patterns. Leave it empty for every file of its languages.":
        "لا تقرأ القاعدة من ملفات لغاتها إلا ما يطابق مساره أو اسمه أحد هذه الأنماط. اتركه "
        "فارغاً لتشمل كل ملفات لغاتها.",
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
    "Flutter and APK": "Flutter و APK",
    "Checks of the Flutter / Android engine (%d)": "فحوص محرك Flutter و Android (%d)",
    "Severity and confidence are the defaults: a finding can lower them, for example when a "
    "setting is only implied by a default.":
        "الخطورة والثقة هنا قيم افتراضية، وقد تكون أقل في النتيجة نفسها، مثلاً حين لا يُكتب "
        "الإعداد صراحةً ويُؤخذ من قيمته الافتراضية.",
    "Area": "المجال", "Runs on": "يعمل على",
    "Dart and Flutter rules (%d)": "قواعد Dart و Flutter (%d)",
    "%d pattern rules for Dart code, %d pattern rules for the files around a Flutter app (CI "
    "build scripts, Firebase Security Rules, web/index.html) and %d credential formats, which "
    "the secrets engine runs. Like every rule, they can be read, changed or switched off in the "
    "Rules tab.":
        "%d قاعدة أنماط لكود Dart، و %d قاعدة أنماط للملفات المحيطة بتطبيق Flutter (سكربتات "
        "البناء في CI وقواعد أمان Firebase وملف web/index.html)، و %d صيغة مفتاح يشغّلها محرك "
        "الأسرار. ومثل كل قاعدة يمكن قراءتها وتعديلها وتعطيلها من تبويب القواعد.",
    "Kind": "الصنف", "Dart code": "كود Dart", "Files around the app": "ملفات حول التطبيق",
    "OWASP Mobile Top 10 (2024) and MASVS": "OWASP Mobile Top 10 (2024) و MASVS",
    "The findings of a mobile app are tagged with one risk and one MASVS group, chosen from "
    "their CWE. The mapping is the project's own, not an official OWASP one.":
        "تُعلَّم كل نتيجة في تطبيق الجوال بفئة خطر واحدة ومجموعة MASVS واحدة تُختاران من رقم "
        "CWE الخاص بها. هذا الربط من وضع المشروع، وليس ربطاً رسمياً من OWASP.",
    "Group": "المجموعة",
    # ---- APIs and keys (sca/flutter/inventory.py, sca/ui/app_panel.py)
    "APIs and keys: %d server addresses, %d keys, %d serious alerts":
        "واجهات API والمفاتيح: %d عنوان خادم، %d مفتاح، %d تنبيه خطير",
    "Every server address, API call, API path and key the analyzer found, with the file and "
    "line of each place. Keys are masked. Nothing was contacted: the addresses are only read.":
        "كل عنوان خادم واستدعاء API ومسار API ومفتاح وجده المحلل، مع الملف والسطر لكل موضع. "
        "المفاتيح مخفيّة جزئياً. لم يُتصل بأي عنوان: العناوين تُقرأ فقط.",
    "Server addresses": "عناوين الخوادم", "Hosts": "الخوادم", "Keys (secret)": "المفاتيح (السرية)",
    "API calls": "استدعاءات API", "API paths": "مسارات API", "Alerts (%d)": "التنبيهات (%d)",
    "No alerts: no keys, unencrypted addresses or test servers were found.":
        "لا تنبيهات: لم يُعثر على مفاتيح ولا عناوين غير مشفّرة ولا خوادم اختبار.",
    "Keys (%d)": "المفاتيح (%d)", "Server addresses (%d)": "عناوين الخوادم (%d)",
    "Hosts (%d)": "الخوادم (%d)", "API calls (%d)": "استدعاءات API (%d)",
    "API paths (%d)": "مسارات API (%d)", "Service IDs (%d)": "معرّفات الخدمات (%d)",
    ".env entries (%d)": "قيم ملفات env. (%d)",
    "Host": "الخادم", "Service provider": "مزوّد الخدمة", "Addresses": "العناوين",
    "Alerts": "التنبيهات", "Method": "الطريقة", "Target": "الهدف", "Place": "الموضع",
    "Places": "المواضع", "Path": "المسار", "Secret": "سري", "TLS": "TLS",
    "Times found": "مرات الظهور", "Value (masked)": "القيمة (مخفيّة جزئياً)",
    "Public by design": "علني بطبيعته", "What to do": "ما العمل",
    "Firebase project": "مشروع Firebase",
    "Calls of HTTP, WebSocket and GraphQL clients in the code. A release build keeps no code "
    "text, so for it see the addresses and API paths.":
        "استدعاءات عملاء HTTP و WebSocket و GraphQL في الكود. نسخة release لا تحتفظ بنص "
        "الكود، فانظر فيها إلى العناوين ومسارات API.",
    "Parts of addresses kept as texts, such as /api/v1/login: a compiled app keeps them even "
    "when the full address is put together at run time.":
        "أجزاء من العناوين محفوظة كنصوص، مثل /api/v1/login: يحتفظ بها التطبيق المترجم حتى حين "
        "يُركَّب العنوان الكامل وقت التشغيل.",
    "Keys, tokens and passwords, masked. A key inside an app package is public: anyone can "
    "unpack the app and read it.":
        "المفاتيح والرموز (tokens) وكلمات المرور، مخفيّة جزئياً. المفتاح داخل حزمة التطبيق "
        "علني: يستطيع أي أحد فك الحزمة وقراءته.",
    "Identifiers of the services the app uses. They are not secrets, but they tell which "
    "projects and accounts to check (security rules, key restrictions).":
        "معرّفات الخدمات التي يستخدمها التطبيق. ليست أسراراً، لكنها تدل على المشاريع "
        "والحسابات التي يجب فحصها (قواعد الأمان وقيود المفاتيح).",
    "Lists were cut to keep the report small: %s.":
        "اختُصرت القوائم ليبقى التقرير صغيراً: %s.",
    "Download the inventory (JSON)": "نزّل الجرد (JSON)",
    "no TLS": "دون TLS", "tunnel": "نفق", "webhook": "Webhook", "bot token": "رمز بوت",
    "key in the address": "مفتاح في العنوان", "password in the address": "كلمة مرور في العنوان",
    "test server": "خادم اختبار", "private IP": "IP خاص", "IP address": "رقم IP",
    "Tunnel or test service": "نفق أو خدمة اختبار", "Webhook": "Webhook",
    "App server": "خادم التطبيق", "Cloud backend": "خلفية سحابية",
    "Third-party API": "API لطرف ثالث", "SDK, analytics or ads": "SDK أو تحليلات أو إعلانات",
    "HTTP request": "طلب HTTP", "Address built with Uri": "عنوان مبني بـ Uri",
    "Retrofit/Chopper route": "مسار Retrofit/Chopper", "Base address": "العنوان الأساسي",
    "Firebase app ID": "معرّف تطبيق Firebase", "Firebase sender ID": "معرّف مرسِل Firebase",
    "Firebase project ID": "معرّف مشروع Firebase", "Storage bucket": "حاوية التخزين",
    "Realtime Database URL": "عنوان Realtime Database",
    "Firebase auth domain": "نطاق مصادقة Firebase",
    "Analytics measurement ID": "معرّف قياس Analytics",
    "Google OAuth client ID": "معرّف عميل Google OAuth",
    "Google OAuth client ID (reversed)": "معرّف عميل Google OAuth (معكوس)",
    "iOS bundle ID": "معرّف حزمة iOS", "Facebook app ID": "معرّف تطبيق Facebook",
    "Facebook client token": "رمز عميل Facebook", "AdMob app ID": "معرّف تطبيق AdMob",
    "AdMob ad unit ID": "معرّف وحدة إعلان AdMob", "OneSignal app ID": "معرّف تطبيق OneSignal",
    "Supabase project URL": "عنوان مشروع Supabase",
    "Google Maps API key": "مفتاح Google Maps API", "Branch key": "مفتاح Branch",
    "Stripe publishable key": "مفتاح Stripe العلني", "Mapbox public token": "رمز Mapbox العلني",
    "Google API key": "مفتاح Google API", "Unknown service": "خدمة غير معروفة",
    "App signing": "توقيع التطبيق", "Encryption": "التشفير", "Password": "كلمة مرور",
    "Private key": "مفتاح خاص",
    "API inventory: listing the server addresses, API calls and keys of the app":
        "جرد API: حصر عناوين الخوادم واستدعاءات API والمفاتيح في التطبيق",
    "API inventory: %d server addresses on %d hosts (%d without TLS), %d keys (%d secret), "
    "%d API calls, %d API paths":
        "جرد API: %d عنوان خادم على %d خادم (%d دون TLS)، %d مفتاح (%d سري)، %d استدعاء API، "
        "%d مسار API",
    "API inventory": "جرد API",
    # the alerts (inventory.ALERTS)
    "The app package holds %s secret keys, tokens or passwords. Anyone who downloads the app "
    "can extract them: revoke them and keep them on a server.":
        "حزمة التطبيق تحوي %s من المفاتيح أو الرموز أو كلمات المرور السرية. يستطيع كل من ينزّل "
        "التطبيق استخراجها: ألغِها واحفظها على خادم.",
    "The code holds %s secret keys, tokens or passwords. They go into every build of the app: "
    "revoke them and keep them on a server.":
        "الكود يحوي %s من المفاتيح أو الرموز أو كلمات المرور السرية، وتدخل في كل نسخة تُبنى من "
        "التطبيق: ألغِها واحفظها على خادم.",
    "%s (%s) at %s.": "%s (%s) في %s.",
    "Supabase service_role key at %s: it bypasses Row Level Security and gives full access to "
    "the database.":
        "مفتاح service_role الخاص بـ Supabase في %s: يتجاوز Row Level Security ويعطي وصولاً "
        "كاملاً إلى قاعدة البيانات.",
    "%s server addresses use unencrypted http:// or ws://, for example %s: data and tokens "
    "sent to them can be read and changed on the network.":
        "%s من عناوين الخوادم تستخدم http:// أو ws:// دون تشفير، مثل %s: البيانات والرموز "
        "المرسلة إليها يمكن قراءتها وتغييرها على الشبكة.",
    "Temporary tunnel or request-catcher address %s (%s): a developer's computer or a test "
    "service, reachable from the internet.":
        "عنوان نفق مؤقت أو خدمة لالتقاط الطلبات %s (%s): جهاز مطوّر أو خدمة اختبار مكشوفة "
        "على الإنترنت.",
    "Webhook address %s: whoever extracts the full address can post messages in the name of "
    "the app.":
        "عنوان Webhook هو %s: من يستخرج العنوان كاملاً يستطيع نشر رسائل باسم التطبيق.",
    "Telegram bot token in the address %s: whoever extracts it controls the bot.":
        "رمز بوت Telegram داخل العنوان %s: من يستخرجه يتحكم بالبوت.",
    "A key or token is part of the address %s (at %s). Addresses are kept in server logs, "
    "proxies and history: send it in a header instead.":
        "مفتاح أو رمز جزء من العنوان %s (في %s). العناوين تُحفظ في سجلات الخوادم والوسطاء "
        "وسجل التصفح: أرسله في ترويسة (header) بدلاً من ذلك.",
    "A user name and password are part of the address %s.":
        "اسم مستخدم وكلمة مرور جزء من العنوان %s.",
    "Development, test or sandbox server in the app: %s.":
        "خادم تطوير أو اختبار أو بيئة تجريبية (sandbox) داخل التطبيق: %s.",
    "Private network address %s: only reachable inside a local network, usually a leftover of "
    "development.":
        "عنوان شبكة خاصة %s: لا يُوصل إليه إلا من داخل شبكة محلية، وغالباً بقي من مرحلة "
        "التطوير.",
    "Server addressed by its IP address: %s. A TLS certificate rarely matches an IP address, "
    "which invites turning certificate checks off.":
        "خادم يُخاطَب برقم IP هو %s. نادراً ما تطابق شهادة TLS رقم IP، وهذا يغري بإيقاف فحص "
        "الشهادات.",
    "Firebase Realtime Database %s: make sure its security rules do not allow public reading "
    "or writing (anyone can request %s/.json).":
        "قاعدة Firebase Realtime Database هي %s: تأكد أن قواعد الأمان لا تسمح بالقراءة أو "
        "الكتابة للعموم (يستطيع أي أحد طلب %s/.json).",
    "Storage bucket %s: make sure its security rules do not allow public listing, reading or "
    "writing.":
        "حاوية التخزين %s: تأكد أن قواعد الأمان لا تسمح للعموم بسرد الملفات أو قراءتها أو "
        "كتابتها.",
    "Supabase project %s: every table needs Row Level Security, because the key in the app "
    "can call the database API directly.":
        "مشروع Supabase هو %s: كل جدول يحتاج Row Level Security، لأن المفتاح الموجود في "
        "التطبيق يستطيع استدعاء واجهة قاعدة البيانات مباشرة.",
    "Amazon S3 bucket %s: make sure the bucket policy does not allow public listing or "
    "writing.":
        "حاوية Amazon S3 هي %s: تأكد أن سياسة الحاوية لا تسمح للعموم بسرد الملفات أو الكتابة.",
    "The .env file %s is inside the app package with %s entries: every value in it can be "
    "read by anyone who has the app.":
        "ملف env. هذا (%s) موجود داخل حزمة التطبيق وفيه %s من القيم: كل قيمة فيه يقرؤها من "
        "يملك التطبيق.",
    "The .env file %s holds %s entries; if it is listed under assets in pubspec.yaml "
    "(flutter_dotenv), it is copied into the app package as it is.":
        "ملف env. هذا (%s) فيه %s من القيم؛ إذا كان مدرجاً ضمن assets في pubspec.yaml "
        "(flutter_dotenv) فإنه يُنسخ إلى حزمة التطبيق كما هو.",
    "Debug build: the complete Dart source code is inside the package (%s files), with every "
    "address and key in it.":
        "نسخة debug: كود Dart المصدري كاملاً داخل الحزمة (%s ملف)، بكل ما فيه من عناوين "
        "ومفاتيح.",
    "All the texts of the compiled Dart code can be read from libapp.so (%s texts). "
    "Obfuscation hides class and method names, not texts: addresses and keys stay readable "
    "either way.":
        "كل نصوص كود Dart المترجم تُقرأ من libapp.so (%s نص). التمويه (obfuscation) يخفي "
        "أسماء الأصناف والدوال لا النصوص: العناوين والمفاتيح تبقى مقروءة في الحالتين.",
    "The app talks to %s services: %s.": "يتصل التطبيق بـ %s من الخدمات: %s.",
    # what to do with a key (inventory.ADVICE)
    "Revoke this key and issue a new one; keep it on a server that the app calls, never in "
    "the app.":
        "ألغِ هذا المفتاح وأصدر غيره، واحفظه على خادم يستدعيه التطبيق، لا داخل التطبيق.",
    "Restrict the key in the Google Cloud console: allow only this app (package name and "
    "SHA-1 certificate fingerprint) and only the APIs it needs.":
        "قيّد المفتاح في Google Cloud console: اسمح لهذا التطبيق وحده (اسم الحزمة وبصمة SHA-1 "
        "للشهادة) وللواجهات التي يحتاجها فقط.",
    "A Firebase configuration value identifies the project and is not a secret: restrict the "
    "API key and protect the data with Firebase Security Rules and App Check.":
        "قيم إعدادات Firebase تعرّف المشروع وليست سراً: قيّد مفتاح API واحمِ البيانات بقواعد "
        "أمان Firebase و App Check.",
    "A publishable or public key is meant to ship in apps: nothing to rotate, but check that "
    "it cannot do more than intended.":
        "المفتاح العلني (publishable) مصمَّم ليكون داخل التطبيقات: لا حاجة لتغييره، لكن تأكد "
        "أنه لا يستطيع أكثر مما يُراد له.",
    "A Stripe secret key must never be in an app: roll it in the Stripe dashboard; the app "
    "may only hold the publishable key (pk_) and payments are created on the server.":
        "مفتاح Stripe السري لا يوضع في تطبيق أبداً: بدّله من لوحة Stripe؛ ولا يحمل التطبيق "
        "إلا المفتاح العلني (pk_) وتُنشأ عمليات الدفع على الخادم.",
    "Deactivate the access key in AWS IAM; give the app short-lived credentials through "
    "Amazon Cognito or a backend instead.":
        "عطّل مفتاح الوصول في AWS IAM، وأعطِ التطبيق صلاحيات مؤقتة عبر Amazon Cognito أو "
        "خادم خلفي بدلاً منه.",
    "A token built into the app is the same for every user: revoke it and let each user get "
    "their own token when they sign in.":
        "الرمز المبني داخل التطبيق واحد لكل المستخدمين: ألغِه ودع كل مستخدم يحصل على رمزه "
        "عند تسجيل الدخول.",
    "Rotate the Supabase service_role key at once; the app may only hold the anon key, with "
    "Row Level Security on every table.":
        "بدّل مفتاح service_role في Supabase فوراً؛ لا يحمل التطبيق إلا مفتاح anon مع "
        "Row Level Security على كل جدول.",
    "Remove the private key from the app and replace the key pair: whoever has it can act as "
    "its owner.":
        "احذف المفتاح الخاص من التطبيق واستبدل زوج المفاتيح: من يملكه يستطيع التصرف باسم "
        "صاحبه.",
    "Remove the password from the app and change it; let users or a server provide "
    "credentials.":
        "احذف كلمة المرور من التطبيق وغيّرها، ودع المستخدمين أو الخادم يقدّمون بيانات الدخول.",
    "An encryption key inside the app protects nothing, because anyone can read it: generate "
    "the key on the device and keep it in Android Keystore / iOS Keychain "
    "(flutter_secure_storage).":
        "مفتاح التشفير داخل التطبيق لا يحمي شيئاً لأن أي أحد يستطيع قراءته: ولّد المفتاح على "
        "الجهاز واحفظه في Android Keystore أو iOS Keychain (flutter_secure_storage).",
    "Keep signing passwords out of the code: read them from environment variables or from a "
    "key.properties file that is not committed.":
        "أبقِ كلمات مرور التوقيع خارج الكود: اقرأها من متغيرات البيئة أو من ملف key.properties "
        "لا يُرفع إلى المستودع.",
    "Delete the webhook or revoke the bot token and create a new one; let a server post "
    "the messages, so that the app never holds the address.":
        "احذف الـ Webhook أو ألغِ رمز البوت وأنشئ غيره، ودع خادماً ينشر الرسائل حتى لا يحمل "
        "التطبيق العنوان أبداً.",
    "Keys": "المفاتيح", "Service IDs": "معرّفات الخدمات", ".env entries": "قيم ملفات env.",
}
