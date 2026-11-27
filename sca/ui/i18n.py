"""Arabic texts of the dashboard. English is the source language: a text that is missing
here is shown in English. Placeholders such as %s and %d must stay in the same order."""
from __future__ import annotations

AR = {
    "Evidence": "نوع الدليل",
    "Classification": "التصنيف",
    "Extraction coverage": "نطاق الاستخراج وحدوده",
    "Native library string coverage": "تغطية نصوص المكتبات الأصلية",
    "Base64 literal coverage": "تغطية فك النصوص بترميز Base64",
    "Complex Android resources": "موارد Android المركّبة",
    "Read and omitted inputs, decoding budgets and derived-text counts "
    "describe coverage; they do not prove that every vulnerability was found.":
        "توضح الملفات المقروءة والمستبعدة وحدود فك الترميز وعدد النصوص الناتجة نطاق التغطية؛ "
        "ولا تثبت اكتشاف جميع الثغرات.",
    "Credential candidate; review required": "قيمة محتملة لبيانات اعتماد؛ تحتاج مراجعة",
    "SDK client identifier": "معرّف تطبيق لمكتبة SDK",
    "Service configuration": "إعداد خدمة",
    "Service configuration and credential candidates found in the files. "
    "Client identifiers can be public; a name alone does not establish "
    "privileges or exploitability. Select a value to inspect its source.":
        "إعدادات الخدمات والقيم المرشّحة لبيانات الاعتماد الموجودة في الملفات. قد تكون معرّفات "
        "التطبيق عامة؛ اسم الحقل وحده لا يثبت صلاحياته أو قابليته للاستغلال. اختر قيمة لعرض مصدرها.",
    "URL template": "قالب رابط يحتاج قيماً أثناء التشغيل",
    "URL literal": "رابط نصي داخل الملفات",
    "Host literal": "اسم مضيف داخل الملفات",
    "URL templates are shown exactly as stored, including placeholders. "
    "Their final addresses require runtime values; finding a literal "
    "does not prove a network request occurred.":
        "تظهر قوالب الروابط كما خُزّنت تماماً، بما فيها المتغيرات. يتطلب العنوان النهائي قيماً "
        "من وقت التشغيل؛ ووجود النص داخل الملف لا يثبت حصول طلب شبكي.",
    "JADX loaded %d files. Scope: the base APK's manifest package and declared "
    "components; limits: %d files and %d seconds. Other DEX contents are still "
    "examined as extracted strings.":
    "حمّل JADX عدد %d من الملفات. النطاق: حزمة التطبيق والمكوّنات المعلنة في ملف APK الأساسي؛ "
    "الحدود: %d ملف و%d ثانية. تُفحص محتويات DEX الأخرى كنصوص مستخرجة.",
    "%d long lines exceed the code-pattern analysis limit. Secrets and literal URLs "
    "are checked separately; code vulnerability coverage is partial.":
        "يتجاوز %d سطراً طويلاً حدّ تحليل الأنماط البرمجية. تُفحص الأسرار والروابط النصية بشكل منفصل؛ "
        "تغطية ثغرات الكود جزئية.",
    "The scan recovered %s text strings from compiled Dart code in libapp.so. These observed "
    "strings can contain addresses and keys; encrypted or runtime-generated values may not be present.":
        "استخرج الفحص %s نصاً من كود Dart المترجم في libapp.so. قد تحتوي النصوص المكتشفة روابط ومفاتيح؛ "
        "وقد لا تظهر القيم المشفّرة أو التي تتولّد أثناء التشغيل.",
    "Addresses associated with %s services were found: %s. Runtime use was not verified.":
        "وُجدت عناوين مرتبطة بـ %s خدمات: %s. لم يُتحقق من استخدامها أثناء التشغيل.",
    "Jump to column": "انتقل إلى العمود",
    "Download this file": "نزّل هذا الملف",
    "Columns %d–%d of %d": "الأعمدة %d–%d من أصل %d",
    "This is a long source line. Navigate by column or download the complete file.":
        "هذا سطر مصدري طويل. انتقل إلى عمود محدد أو نزّل الملف كاملاً.",
    "Showing columns %d–%d of %d. The selected value is complete; "
    "open the file to navigate the rest of this line.":
        "تظهر الأعمدة %d–%d من أصل %d. القيمة المحددة كاملة؛ افتح الملف لتصفّح بقية السطر.",
    "%d long code lines were checked for literal URLs, but their API call expressions "
    "could not be fully analyzed.":
        "فُحص %d سطراً برمجياً طويلاً بحثاً عن الروابط النصية، لكن تعذّر تحليل تعبيرات استدعاء API فيها بالكامل.",
    "This saved result has no original file snapshot. Rescan its input to display "
    "and export the complete observed values.":
        "هذه النتيجة المحفوظة لا تحتوي نسخة من الملفات الأصلية. أعد فحص الإدخال لعرض القيم المكتشفة وتصديرها كاملة.",
    "Detected value": "القيمة المكتشفة",
    "Addresses, API calls, paths and keys observed in the scanned files, with "
    "their recorded locations. Values are shown in full. No service was contacted.":
        "العناوين واستدعاءات API والمسارات والمفاتيح الموجودة في الملفات المفحوصة، مع مواضعها المسجّلة. "
        "تظهر القيم كاملة. لم يتم الاتصال بالخدمات.",
    "Values are shown in full. The severity reflects the evidence in the scanned "
    "files. Service permissions and restrictions require separate verification.":
        "تظهر القيم كاملة. تعكس درجة الخطورة الأدلة الموجودة في الملفات المفحوصة. "
        "تتطلب صلاحيات الخدمة وقيودها تحققاً مستقلاً.",
    "Source files": "ملفات المصدر",
    "Filter source files": "تصفية ملفات المصدر",
    "No source files match this filter.": "لا توجد ملفات مصدر تطابق التصفية.",
    "Source file": "ملف مصدري",
    "Browse source files": "تصفّح ملفات المصدر",
    "The original file changed or is unavailable. Rescan to view the current source.":
        "تغيّر الملف الأصلي أو تعذّر فتحه. أعد الفحص لعرض محتواه الحالي.",
    "Line numbers refer to the scanned source. Previews mask literal values.":
        "تشير أرقام الأسطر إلى الملفات المصدرية التي فُحصت. تُحجب القيم الحرفية في المعاينة.",
    "Compare a known key locally": "مطابقة مفتاح معروف محلياً",
    "Find the matching key in your source file": "ابحث عن المفتاح المطابق في ملف من مشروعك",
    "Choose the text file from your project that contains the value, such as strings.xml or local.properties.":
        "اختر الملف النصي الذي يحتوي قيمة المفتاح في مشروعك، مثل strings.xml أو local.properties.",
    "Choose a source file of at most %d bytes.": "اختر ملفاً مصدرياً لا يتجاوز حجمه %d بايت.",
    "Could not confirm a unique matching key in this source file.":
        "تعذّر تأكيد مفتاح واحد من هذا الملف يطابق الموضع المحدد.",
    "Rescan this APK to match a key from your source file.":
        "أعد فحص حزمة APK لمطابقة المفتاح مع ملف من مشروعك.",
    "The APK preview masks credential values. Choose your original source file below to display "
    "the value that matches this line.":
        "تحجب معاينة APK قيم المفاتيح. اختر ملف السورس الأصلي أدناه لعرض القيمة المطابقة لهذا السطر.",
    "The highlighted attribute shows the matching value from your source file.":
        "القيمة الظاهرة في الخاصية المميّزة مطابقة للقيمة الموجودة في ملفك المصدري.",
    "Matched value on this line": "القيمة المطابقة في هذا السطر",
    "Checks the complete value you enter against this rule's matches on the selected line. "
    "The comparison stays on this computer.":
        "أدخل القيمة الكاملة من مشروعك لمقارنتها بالقيم التي اكتشفتها هذه القاعدة في السطر المحدد. "
        "تجري المقارنة على هذا الجهاز.",
    "Known value from your project": "القيمة المعروفة من مشروعك",
    "Check exact match": "تحقّق من تطابق القيمة",
    "Enter the value you want to compare.": "أدخل القيمة التي تريد مقارنتها.",
    "Exact match with a value detected on this line.": "تطابقت القيمة بالكامل مع قيمة مكتشفة في هذا السطر.",
    "The entered value differs from the matches on this line.": "تختلف القيمة المُدخلة عن القيم المكتشفة في هذا السطر.",
    "Values are masked. The severity reflects the evidence in the scanned files. "
    "Service permissions and restrictions require separate verification.":
        "القيم محجوبة. تعكس درجة الخطورة الأدلة الموجودة في الملفات المفحوصة. "
        "تتطلب صلاحيات الخدمة وقيودها تحققاً مستقلاً.",
    "No inventory alerts at the current thresholds.": "لا توجد تنبيهات للجرد وفق حدود التنبيه الحالية.",
    "APK files in this scan": "ملفات APK الداخلة في الفحص",
    "%d of %d APK files read without a reported input limit.":
        "اكتملت قراءة %d من أصل %d ملف APK ضمن حدود إدخال الفاحص.",
    "Read": "مقروء", "Partially read": "مقروء جزئياً", "Skipped": "تم تخطّيه",
    "Base APK": "الملف الأساسي", "Split APK": "جزء من التطبيق", "Alternative APK": "نسخة بديلة",
    "Package role": "دور الملف",
    "Native library count limit reached": "تجاوز عدد المكتبات الأصلية حدّ الفحص",
    "Optional Java decompilation covers the base APK": "فكّ ترجمة Java الاختياري يشمل الملف الأساسي",
    "APK package does not match the base": "معرّف التطبيق يختلف عن معرّف الملف الأساسي",
    "APK version does not match the base": "إصدار الجزء يختلف عن إصدار الملف الأساسي",
    "Duplicate split ID": "معرّف الجزء مكرّر",
    "Unreadable base manifest": "تعذّرت قراءة ملف Manifest الأساسي",
    "Unreadable split manifest": "تعذّرت قراءة ملف Manifest لهذا الجزء",
    "APK has no declared split ID": "لا يصرّح ملف APK بمعرّف جزء",
    "Alternative installation variant": "نسخة تثبيت بديلة",
    "APK count limit": "تجاوز عدد ملفات APK الحدّ",
    "The base APK was not supplied": "ملف APK الأساسي غير موجود ضمن الإدخال",
    "Duplicate APK member filename": "اسم ملف APK مكرّر داخل الحزمة",
    "This value appears in Firebase client configuration. The file scan cannot establish access to project data.":
        "تظهر هذه القيمة في إعدادات عميل Firebase. لا يبيّن فحص الملف صلاحيات الوصول إلى بيانات المشروع.",
    "Review the allowed apps and APIs in Google Cloud and verify the project's Firebase Security Rules.":
        "راجع التطبيقات والواجهات المسموح بها في Google Cloud وتحقق من قواعد الوصول إلى البيانات في Firebase.",
    "The package was found, but its version could not be matched to the affected versions in the advisory.":
        "اكتُشفت المكتبة، وتعذّر مطابقة إصدارها مع الإصدارات المتأثرة الواردة في النشرة الأمنية.",
    "Check the resolved dependency version against the advisory before classifying this as a vulnerability.":
        "طابق إصدار المكتبة الفعلي مع النشرة الأمنية قبل تصنيف النتيجة كثغرة.",
    "APK size limit": "تجاوز حجم ملف APK الحدّ",
    "Compressed APK size limit": "تجاوز حجم APK المضغوط الحدّ",
    "A decoder could not finish": "تعذّر على إحدى أدوات فك الملف إكمال القراءة",
    "Localized string resource limit reached": "تجاوز عدد موارد الترجمة الحدّ",
    "An archive entry could not be read within the scan limits": "تعذّرت قراءة عنصر الأرشيف ضمن حدود الفحص",
    "Decoded text limit reached": "تجاوز النص المفكوك حدّ الحجم",
    "An XML resource could not be decoded": "تعذّر فكّ أحد موارد XML",
    "XML resource count limit reached": "تجاوز عدد موارد XML الحدّ",
    "String resource count limit reached": "تجاوز عدد الموارد النصية الحدّ",
    "Text asset size limit reached": "تجاوز حجم أحد الأصول النصية الحدّ",
    "Text asset count limit reached": "تجاوز عدد الأصول النصية الحدّ",
    "DEX count limit reached": "تجاوز عدد ملفات DEX الحدّ",
    "APK containing this file: %s": "ملف APK الذي يحتوي هذا الموضع: %s",
    "Line numbers index the extracted strings. The original source line and byte offset "
    "are unavailable in this view.":
        "رقم السطر يخص قائمة النصوص المستخرجة من الملف الثنائي. سطر المصدر الأصلي وموضع البايت "
        "غير متاحين في هذه المعاينة.",
    "Line numbers refer to the code reconstructed by JADX.":
        "تخص أرقام الأسطر الكود الذي أعادت أداة JADX بناءه.",
    "Scan archive": "أرشيف الفحوصات", "Archive database": "مكان قاعدة بيانات الأرشيف",
    "Find scans by file name or path": "ابحث في الأرشيف باسم الملف أو مساره",
    "No saved scans match this path.": "لا توجد فحوصات محفوظة تطابق هذا المسار.",
    "Archive page": "صفحة الأرشيف", "%d saved scans · page %d of %d": "%d فحصاً محفوظاً · صفحة %d من %d",
    "Scan target": "المسار المفحوص", "Started": "وقت الفحص", "Grade": "التقدير", "ID": "الرقم",
    "Use this path for a new scan": "استخدم هذا المسار لفحص جديد",
    "Saved results keep the locations recorded at scan time. A new scan of the original path "
    "rebuilds file previews from the files currently on disk.":
        "تحفظ نتائج الأرشيف مواضع الأدلة وقت الفحص. لإعادة بناء المعاينات من الملفات الموجودة الآن، "
        "ابدأ فحصاً جديداً للمسار الأصلي.",
    "Scan workspace": "إعداد الفحص",
    "Scan settings": "خيارات الفحص",
    "Samples": "العيّنات",
    "Static engines": "محركات الفحص الستاتيكي",
    "Artificial intelligence": "الذكاء الاصطناعي",
    "Precision and output": "الدقة وحفظ النتائج",
    "Include adjacent APK parts (%d files)": "تضمين أجزاء APK الموجودة بجانب الملف (%d ملفات)",
    "APK files selected: %d": "عدد ملفات APK المحددة: %d",
    "Selected input: %s": "الهدف المحدد للفحص: %s",
    "%d selected APK files": "%d ملفات APK محددة",
    "One archive up to %d MiB, or up to %d MiB total for a split set. "
    "Download the report before closing this session.":
        "حد الأرشيف الواحد %d ميبيبايت، وحد مجموعة الملفات المجزّأة %d ميبيبايت إجمالاً. "
        "نزّل التقرير قبل إغلاق هذه الجلسة.",
    "The selected APKs exceed the combined size limit.": "يتجاوز مجموع أحجام ملفات APK الحد المسموح.",
    "Select distinct APK filenames from the same app.": "اختر ملفات APK مختلفة الأسماء من التطبيق نفسه.",
    "One of the selected APKs is empty.": "أحد ملفات APK المختارة فارغ.",
    "Select the base APK and its split APKs together.": "اختر ملف APK الأساسي وأجزاءه معاً.",
    "Select a directory with a base APK and its splits, or choose one APK.":
        "اختر مجلداً يضم ملف APK الأساسي وأجزاءه، أو اختر ملف APK واحداً.",
    "Too many APKs in the selected set.": "يتجاوز عدد ملفات APK في المجموعة الحد المسموح.",
    "An APK set cannot contain links or special files.": "يجب أن تضم المجموعة ملفات APK عادية فقط.",
    "The scanner checks the ZIP contents to identify a source project or a split APK set.":
        "يفحص المحرك محتويات ZIP لتمييز مشروع الكود المصدري عن مجموعة APK المجزأة.",
    "Choose your files in **Scan input**, then press **Run scan**.":
        "اختر ملفاتك من **مصدر الفحص** ثم اضغط **ابدأ الفحص**.",
    "Choose a working AI provider in Scan settings to use learning.":
        "اختر مزوّد ذكاء اصطناعي متاحاً من خيارات الفحص لاستخدام التعلّم.",
    "The help next to each scan setting explains what it does.":
        "تعرض المساعدة بجانب كل خيار وظيفته عند الفحص.",
    "Decoded files": "الملفات المفكوكة",
    "No decoded files are available for this scan.": "لا توجد ملفات مفكوكة متاحة لهذا الفحص.",
    "Filter decoded files": "تصفية الملفات المفكوكة",
    "No decoded files match this filter.": "لا توجد ملفات تطابق التصفية.",
    "Decoded file": "الملف المفكوك",
    "Jump to line": "الانتقال إلى السطر",
    "Previous page": "الصفحة السابقة",
    "Next page": "الصفحة التالية",
    "Showing lines %d–%d of %d": "عرض الأسطر %d–%d من أصل %d",
    "%s · %s · %d lines": "%s · %s · %d سطراً",
    "This decoded file is empty.": "معاينة هذا الملف فارغة.",
    "The preview was shortened to fit.": "اختُصرت أسطر المعاينة الطويلة.",
    "This location is outside the available preview.": "هذا الموضع خارج المعاينة المتاحة.",
    "Decoded from package": "مفكوك من الحزمة",
    "Recovered Dart source": "كود Dart مستعاد",
    "Decompiled by JADX": "مفكوك باستخدام JADX",
    "Strings from binary": "سلاسل مستخرجة من ملف ثنائي",
    "Analysis summary": "ملخص التحليل",
    "Binary file placeholder": "عنصر يمثّل ملفاً ثنائياً",
    "Key location in decoded files": "موضع المفتاح في الملفات المفكوكة",
    "Open decoded location": "افتح الموضع في الملف المفكوك",
    "Demo APK": "حزمة APK تجريبية",
    "File preview": "معاينة الملف",
    "Credential match · %s": "نمط بيانات الاعتماد المطابق · %s",
    "The highlighted line is the recorded location. The preview uses "
    "`[redacted]` or `…` to hide text values, including credentials.":
        "السطر المميّز هو الموضع المسجّل. تعرض المعاينة `[redacted]` أو `…` مكان القيم النصية، بما فيها المفاتيح.",
    "Credential": "بيانات اعتماد",
    "Hard-coded credential": "بيانات اعتماد مكتوبة في الملف",
    "Google Maps Android client key": "مفتاح عميل خرائط Google لأندرويد",
    "The packaged manifest declares a Google Maps Android client key. "
    "Its Google Cloud application and API restrictions require verification by the project owner.":
        "يعرّف ملف البيان في الحزمة مفتاح عميل خرائط Google لأندرويد. يستطيع مالك المشروع التحقق "
        "من قيود التطبيقات وواجهات API لهذا المفتاح في Google Cloud.",
    "In Google Cloud, restrict the key to the Android package and signing certificate "
    "and to the required Maps APIs.":
        "في Google Cloud، قيّد المفتاح باسم حزمة أندرويد وشهادة توقيعها وبواجهات الخرائط التي يحتاجها التطبيق.",
    "AWS access key ID": "معرّف مفتاح وصول AWS",
    "GitHub token": "رمز وصول GitHub",
    "Slack token": "رمز وصول Slack",
    "Stripe live key": "مفتاح Stripe لبيئة الإنتاج",
    "Private key embedded in source": "مفتاح خاص مضمن في الكود",
    "Hard-coded JSON Web Token": "رمز JWT مكتوب في الملف",
    "Credentials embedded in a connection URL": "بيانات اعتماد مضمّنة في عنوان الاتصال",
    "Slack webhook URL": "عنوان Webhook لخدمة Slack",
    "Discord webhook URL": "عنوان Webhook لخدمة Discord",
    "Telegram bot token": "رمز بوت Telegram",
    "Browse decoded files": "تصفّح الملفات المفكوكة",
    "Preview location": "عاين الموضع",
    "Select a finding to preview its location.": "اختر نتيجة لعرض موضعها في الملف.",
    "Positions refer to decoded files. Previews show the scanned text, including credential values.":
        "تشير المواضع إلى الملفات المفكوكة. تعرض المعاينة النص المفحوص بما فيه قيم المفاتيح وبيانات الاعتماد.",
    "Some files exceed the session preview limit.": "تتجاوز بعض الملفات الحد الأقصى لمعاينة الجلسة.",
    "Run the scan again to browse this package's decoded files.":
        "أعد الفحص لتصفّح الملفات المفكوكة من هذه الحزمة.",
    "1. Project or Android app": "١. مشروع أو تطبيق أندرويد",
    "Upload a source ZIP or an Android app": "ارفع ملف ZIP للمصدر أو تطبيق أندرويد",
    "Upload file": "رفع ملف",
    "Server path": "مسار على الخادم",
    "Scan input": "مصدر الفحص",
    "Enter a path inside the server project directory.":
        "أدخل مساراً داخل مجلد المشاريع المخصّص على الخادم.",
    "Choose a path inside the server project directory.":
        "اختر مساراً داخل مجلد المشاريع المخصّص على الخادم.",
    "The server path cannot be read.": "تعذّرت قراءة المسار على الخادم.",
    "Server projects cannot contain links or special files.":
        "يجب أن يخلو مشروع الخادم من الروابط والملفات الخاصة.",
    "The server project exceeds the scan size limits.": "يتجاوز مشروع الخادم حدود حجم الفحص.",
    "Choose a source file, a source ZIP or an Android package.":
        "اختر ملف كود مصدري أو ملف ZIP للمصدر أو حزمة أندرويد.",
    "Choose a source ZIP or an Android app package.":
        "اختر ملف ZIP للمصدر أو حزمة تطبيق أندرويد.",
    "Choose a project folder, source ZIP or Android app package first.":
        "اختر أولاً مجلد مشروع أو ملف ZIP للمصدر أو حزمة تطبيق أندرويد.",
    "Choose a file between 1 byte and %d MiB.": "اختر ملفاً حجمه بين بايت واحد و%d ميبيبايت.",
    "Up to %d MiB per upload. Download the report before closing this session.":
        "يمكن رفع ملف بحجم يصل إلى %d ميبيبايت. نزّل التقرير قبل إغلاق الجلسة.",
    "A source ZIP: the project is unpacked for analysis.": "يُفك ضغط ملفات المشروع لتحليلها.",
    "This file is not a readable source ZIP: %s": "هذا الملف ليس أرشيف ZIP قابلاً للقراءة: %s",
    "The source ZIP cannot be read: %s": "تعذّرت قراءة ملف ZIP للمصدر: %s",
    "The source ZIP could not be read or extracted.": "تعذّرت قراءة الملف أو فك ضغطه.",
    "The source ZIP contains an unsafe path.": "يحتوي الملف على مسار غير آمن.",
    "The source ZIP contains a link or a special file.": "يحتوي الملف على رابط أو ملف خاص.",
    "The source ZIP contains encrypted entries.": "يحتوي الملف على عناصر مشفّرة.",
    "The source ZIP must use stored or deflate compression.":
        "استخدم طريقة التخزين دون ضغط أو طريقة Deflate.",
    "The source ZIP contains duplicate or conflicting paths.":
        "يحتوي الملف على مسارات مكرّرة أو متعارضة.",
    "The source ZIP contains no project files.": "لا يحتوي الملف على ملفات مشروع.",
    "The source ZIP contains no readable source files.": "لا يحتوي الملف على كود مصدري قابل للفحص.",
    "The source ZIP directory is too large.": "فهرس الملفات في أرشيف ZIP كبير جداً.",
    "The scanner is busy. Try again when the current scan finishes.":
        "الفاحص مشغول. أعد المحاولة بعد انتهاء الفحص الجاري.",
    "The scan failed.": "فشل الفحص.",
    "%d of %d findings.": "%d من أصل %d نتيجة.",
    "Showing %d of %d findings. The filters hide %d.":
        "تظهر %d من أصل %d نتيجة. تُخفي عوامل التصفية %d من النتائج.",
    "Show all findings": "عرض كل النتائج",
    "This scan covers base.apk only. To include the adjacent split APKs, "
    "select an APKS archive containing the base and its splits.":
        "يشمل الفحص ملف base.apk وحده. لفحص ملفات APK المجزأة الموجودة بجانبه أيضاً، "
        "اختر أرشيف APKS يحتوي على الملف الأساسي وأجزائه.",
    "Choose the scan input in the sidebar and press **Run scan**.":
        "اختر مصدر الفحص من الشريط الجانبي واضغط **ابدأ الفحص**.",
    "Choose a folder, upload a source ZIP or select an Android app in the sidebar, then press "
    "**Run scan**. Try **Use sample** for an example.":
        "اختر مجلداً أو ارفع ملف ZIP للمصدر أو اختر تطبيق أندرويد من الشريط الجانبي، ثم اضغط "
        "**ابدأ الفحص**. جرّب **استخدم العيّنة** لتشاهد مثالاً.",
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
    "Select a row to see where it was found.": "اضغط على صف لعرض موضعه في الملفات.",
    "Recorded locations": "المواضع المسجّلة",
    "%d recorded locations for %d occurrences.": "عدد المواضع المسجّلة %d، وعدد مرات الظهور %d.",
    "Call site · %s": "موضع الاستدعاء · %s",
    "Target argument · %s": "موضع عنوان الاستدعاء · %s",
    "No file and line were recorded for this item.": "لم يُسجَّل ملف وسطر لهذا العنصر.",
    "Run the scan again to view the file at this location.":
        "أعد الفحص لعرض محتوى الملف عند هذا الموضع.",
    "Calls found in source or decompiled code. Some compiled apps only expose address and path strings.":
        "استدعاءات ظهرت في السورس أو في الكود المفكوك. في بعض التطبيقات المترجمة لا تظهر إلا نصوص العناوين والمسارات.",
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
    "Local or development address": "عنوان محلي أو للتطوير",
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
    "Known public SDK test private key": "مفتاح خاص علني معروف لاختبارات مكتبة SDK",
    "Known public SDK test JWT": "رمز JWT علني معروف لاختبارات مكتبة SDK",
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
    "Review whether this public SDK fixture is used only for tests or capability probes. "
    "Runtime trust or signing with it would require remediation; its presence alone is not a secret leak.":
        "راجع ما إذا كانت بيانات SDK العلنية هذه تُستخدم للاختبار أو للتحقق من الإمكانات فقط. "
        "الاعتماد عليها للتحقق من الثقة أو التوقيع الفعلي يحتاج إلى معالجة؛ وجودها وحده ليس تسريباً لسر.",
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

# Runtime observations retain their values and distinguish capture evidence from code.
AR.update({
    "Dynamic analysis": "التحليل الديناميكي",
    "Runtime URL": "رابط رُصد أثناء التشغيل",
    "Runtime host": "مضيف رُصد أثناء التشغيل",
    "Socket destination attempt": "وجهة محاولة اتصال عبر المقبس",
    "Recorded occurrences": "مرات الرصد المسجّلة",
    "Summary metadata describes the first occurrence. Select another recorded event below to inspect its own timestamp, API and call stack.":
        "معلومات الملخّص تخص أول رصد للقيمة. اختر حدثاً آخر أدناه لمعاينة وقته واستدعائه وتسلسل الدوال الخاص به.",
    "Capture mode": "وضع التسجيل",
    "Observe native DNS and TLS calls": "رصد استدعاءات DNS وTLS في الكود الأصلي",
    "Disable to compare Java hooks alone when native compatibility issues occur. This reduces visibility into native DNS, socket and TLS calls.":
        "ألغِ التفعيل لمقارنة الرصد عبر Java وحدها عند حدوث مشكلات توافق في الكود الأصلي. يقلّل ذلك رصد استدعاءات DNS والمقابس وTLS الأصلية.",
    "Requested hook mode": "وضع الرصد المطلوب",
    "Java and native observation requested": "طلب رصد Java والكود الأصلي",
    "Java-only observation requested": "طلب الرصد عبر Java فقط",
    "Native DNS, socket and TLS observation was disabled for this capture.":
        "عُطّل رصد DNS والمقابس وTLS في الكود الأصلي لهذا التسجيل.",
    "Native DNS/socket/TLS observation hooks were explicitly disabled for this compatibility capture. Java observation remains enabled; the Frida Java bridge itself still uses native internals. This setting does not establish the cause of any previous crash.":
        "عُطّلت نقاط رصد DNS والمقابس وTLS الأصلية صراحةً لاختبار التوافق. يبقى رصد Java مفعّلاً، ويظل جسر Java في Frida يستخدم مكوّناته الداخلية الأصلية. لا يثبت هذا الإعداد سبب أي انهيار سابق.",
    "Install and restart the application": "تثبيت التطبيق وإعادة تشغيله",
    "Attach to the running application": "الاتصال بالتطبيق الجاري تشغيله",
    "During capture, use the selected Android device to open the screens you want to inspect. Only the selected process and executed actions are observed.":
        "أثناء التسجيل، افتح الشاشات التي تريد فحصها على جهاز أندرويد المحدد. يُرصد فقط ما يُنفّذ داخل عملية التطبيق المحددة.",
    "Recorded event occurrence": "موضع حدث الرصد",
    "Hook available": "نقطة الرصد متاحة",
    "Hook unavailable": "نقطة الرصد غير متاحة",
    "Credential candidate": "قيمة محتملة لبيانات اعتماد",
    "Observed encryption key": "مفتاح تشفير مرصود",
    "Observed value": "القيمة المرصودة",
    "Capture completed": "اكتمل التسجيل",
    "Partial capture": "تسجيل جزئي",
    "Capture failed": "فشل التسجيل",
    "Capture running": "التسجيل جارٍ",
    "Imported capture": "تسجيل مستورد",
    "Capture status unavailable": "حالة التسجيل غير متاحة",
    "Runtime evidence": "دليل من وقت التشغيل",
    "Observed at": "وقت الرصد",
    "Observed API": "واجهة الاستدعاء المرصودة",
    "Process ID": "معرّف العملية",
    "Thread ID": "معرّف مسار التنفيذ",
    "Observation label": "وصف الرصد",
    "Observation details": "تفاصيل الرصد",
    "Observed key material or a token-shaped value does not by itself prove a credential leak or exploitability.":
        "رصد مفتاح أو قيمة تشبه رمز الوصول لا يثبت وحده تسرب بيانات اعتماد أو إمكانية الاستغلال.",
    "Exact value match in the retained files. This does not prove that this line generated the runtime value.":
        "تطابق حرفي للقيمة داخل الملفات المحفوظة. لا يثبت ذلك أن هذا السطر ولّد القيمة أثناء التشغيل.",
    "Matching file location": "موضع القيمة المطابقة في الملف",
    "No exact source line was verified for this value. Its runtime event and recorded call stack are shown below.":
        "لم يثبت سطر مصدر مطابق لهذه القيمة. يظهر أدناه حدث التشغيل وتسلسل الاستدعاءات المسجّل.",
    "Related class or method candidates": "أصناف أو دوال محتملة الصلة",
    "These are possible code associations, not verified source lines.":
        "هذه ارتباطات محتملة بالكود، وليست مواضع مصدر متحققة.",
    "Recorded call stack": "تسلسل الاستدعاءات المسجّل",
    "Class / module": "الصنف / المكتبة",
    "Method / address": "الدالة / العنوان",
    "Runtime source file": "ملف المصدر في معلومات التشغيل",
    "Runtime line": "السطر في معلومات التشغيل",
    "Runtime stack line numbers are debug metadata; they are not JADX line numbers.":
        "أرقام أسطر تسلسل الاستدعاءات تأتي من معلومات التصحيح وقت التشغيل؛ وليست أرقام أسطر JADX.",
    "No call stack was recorded for this event.": "لم يُسجّل تسلسل استدعاءات لهذا الحدث.",
    "Capture record: %s · line %d": "سجل الرصد: %s · السطر %d",
    "This line belongs to the capture log, not to the application's source code.":
        "هذا السطر من سجل الرصد، وليس من الكود المصدري للتطبيق.",
    "The referenced runtime event is unavailable in this capture.": "حدث التشغيل المشار إليه غير متاح في هذا التسجيل.",
    "Target package": "حزمة التطبيق المستهدف",
    "Device: %s · started: %s · ended: %s": "الجهاز: %s · البداية: %s · النهاية: %s",
    "Imported evidence: this dashboard did not independently witness the capture.":
        "دليل مستورد: لم تشهد هذه المنصة عملية التسجيل بصورة مستقلة.",
    "Recorded events": "الأحداث المسجّلة",
    "Observed addresses": "العناوين المرصودة",
    "Key / token observations": "قيم المفاتيح والرموز المرصودة",
    "Capture coverage and diagnostics": "تغطية التسجيل والتشخيص",
    "Capture profile": "نمط الرصد",
    "Startup instrumentation": "رصد بدء التشغيل",
    "Attached running process": "رصد عملية جارية",
    "Attached after launch": "رصد بعد بدء التطبيق",
    "Observed duration (seconds)": "مدة الرصد الفعلية بالثواني",
    "Requested duration (seconds)": "مدة الرصد المطلوبة بالثواني",
    "Not recorded": "غير مسجّل",
    "Observed duration is recording time, not a measure of screen or code coverage.":
        "المدة الفعلية هي زمن التسجيل؛ وليست مقياساً لتغطية الشاشات أو الكود.",
    "No automated screen exploration was recorded for this session.": "لم يُسجّل تصفّح آلي للشاشات في هذه الجلسة.",
    "Capture timing and profile metadata were not recorded.": "لم تُسجّل معلومات مدة الرصد ونمطه.",
    "Only code executed during this capture is covered; startup alone does not exercise login or other screens.":
        "تشمل التغطية الكود الذي نُفّذ أثناء التسجيل فقط؛ بدء التطبيق وحده لا يختبر تسجيل الدخول أو بقية الشاشات.",
    "An observed key, token or endpoint is evidence of runtime use, not a vulnerability or proof of exploitability.":
        "رصد مفتاح أو رمز أو عنوان اتصال دليل على استخدامه أثناء التشغيل؛ ولا يثبت وجود ثغرة أو إمكانية استغلاله.",
    "Values are complete within the explicit event/value/journal budgets; omitted evidence is reported, never silently shortened.":
        "تُحفظ القيم كاملة ضمن الحدود المعلنة للأحداث والقيم والسجل؛ ويُبلّغ عن الأدلة التي تعذّر حفظها دون اقتطاع صامت.",
    "TLS validation and application integrity checks are unchanged. No pinning or root-detection bypass is performed.":
        "تبقى فحوص التحقق من TLS وسلامة التطبيق كما هي. لا تُتجاوز آليات تثبيت الشهادات أو اكتشاف صلاحيات الجذر.",
    "Flutter/native DNS and socket destinations may be visible without full URLs. Stripped or inlined TLS, QUIC and HTTP/2 header decoding are not covered.":
        "قد تظهر أسماء DNS ووجهات المقابس في Flutter والكود الأصلي دون الروابط الكاملة. لا تشمل التغطية TLS منزوع الرموز أو المدمج، ولا QUIC أو فك ترويسات HTTP/2.",
    "Only the selected process is instrumented; child processes and WebView renderer processes are outside this session.":
        "تُرصد العملية المحددة فقط؛ العمليات الفرعية وعمليات عرض WebView خارج هذه الجلسة.",
    "Native hooks cover the process architecture only; ARM translation on x86 does not guarantee access to translated native TLS or Dart code.":
        "تشمل نقاط رصد الكود الأصلي معمارية العملية فقط؛ ترجمة ARM على x86 لا تضمن الوصول إلى كود TLS أو Dart المترجَم.",
    "Only readable complete decoded outputs and TLS chunks are classified; binary payloads and values split across chunks may not be reconstructed.":
        "تُصنّف فقط المخرجات المفكوكة ومقاطع TLS الكاملة القابلة للقراءة؛ قد لا يُعاد تركيب المحتوى الثنائي أو القيم الموزعة على مقاطع متعددة.",
    "Cipher.doFinal capture covers readable byte-array return values; output-buffer and ByteBuffer result variants are not reconstructed.":
        "يشمل رصد Cipher.doFinal القيم المعادة كمصفوفات بايت قابلة للقراءة؛ ولا يُعاد تركيب النتائج التي تُكتب في مخزن إخراج أو ByteBuffer.",
    "Generated values may have no literal source location. Stack lines are runtime debug metadata, not asserted JADX source lines.":
        "قد لا يوجد موضع حرفي للقيم المتولّدة داخل المصدر. أسطر تسلسل الاستدعاءات من معلومات التصحيح أثناء التشغيل؛ وليست مواضع مصدر مؤكدة في JADX.",
    "Frida spawn failed. Attached after an ordinary Android launch; initialization before attachment was not captured.":
        "تعذّر بدء العملية عبر Frida. جرى الاتصال بها بعد تشغيل أندرويد الاعتيادي؛ لم تُسجّل مرحلة التهيئة السابقة للاتصال.",
    "Capability": "إمكانية الرصد",
    "No hook coverage metadata was recorded.": "لم تُسجّل معلومات تغطية نقاط الرصد.",
    "No runtime values were recorded in this session. This is not evidence that the app has no network traffic or security issues.":
        "لم تُسجّل قيم أثناء هذه الجلسة. لا يثبت ذلك خلو التطبيق من الاتصالات الشبكية أو المشكلات الأمنية.",
    "Search runtime values, APIs or locations": "ابحث في القيم والاستدعاءات والمواضع المرصودة",
    "All observation types": "كل أنواع الرصد",
    "Observation type": "نوع الرصد",
    "Showing %d of %d runtime observations.": "عرض %d من أصل %d قيمة مرصودة أثناء التشغيل.",
    "No recorded values match these filters.": "لا توجد قيم مسجّلة تطابق هذه التصفية.",
    "Full observed value": "القيمة المرصودة كاملة",
    "Open recorded value": "افتح قيمة مرصودة",
    "Download runtime capture JSON": "تنزيل التسجيل بصيغة JSON",
    "Download runtime events JSONL": "تنزيل أحداث التشغيل بصيغة JSONL",
    "Record actual values while the app runs. Observed traffic, keys and call stacks are separate from static findings; unvisited screens and encrypted or unsupported paths may remain unobserved.":
        "سجّل القيم الفعلية أثناء تشغيل التطبيق. تُعرض الاتصالات والمفاتيح وتسلسلات الاستدعاء المرصودة بصورة مستقلة عن النتائج الساكنة؛ قد تبقى الشاشات التي لم تُفتح والمسارات المشفّرة أو غير المدعومة خارج الرصد.",
    "Runtime capture setup": "إعداد التسجيل أثناء التشغيل",
    "Select a scanned Android application before starting a runtime capture.":
        "اختر تطبيق أندرويد مفحوصاً قبل بدء التسجيل أثناء التشغيل.",
    "Android device": "جهاز أندرويد",
    "No Android device is available for capture.": "لا يوجد جهاز أندرويد متاح للتسجيل.",
    "Capture duration (seconds)": "مدة التسجيل بالثواني",
    "The selected Android device is not connected or authorized.": "جهاز أندرويد المحدد غير متصل أو لم يسمح بالاتصال.",
    "Runtime capture prerequisites are unavailable. Check device and instrumentation status.":
        "متطلبات التسجيل أثناء التشغيل غير متاحة. راجع حالة الجهاز وأدوات الرصد.",
    "Available capture tools": "أدوات التسجيل المتاحة",
    "Start runtime capture": "ابدأ التسجيل أثناء التشغيل",
    "Runtime capture could not finish.": "تعذّر إكمال التسجيل أثناء التشغيل.",
    "Refresh devices": "تحديث الأجهزة",
    "Reconnect lab observer": "إعادة توصيل أداة الرصد",
    "The lab observer could not be reconnected.": "تعذّرت إعادة توصيل أداة الرصد في بيئة الاختبار.",
    "Lab observer reconnected. Device status has been refreshed.": "أُعيد توصيل أداة الرصد وتحديث حالة الجهاز.",
    "Import an existing runtime capture": "استيراد تسجيل تشغيل سابق",
    "Import a capture JSON exported by this analyzer. Imported evidence remains labelled separately from a capture witnessed by this dashboard.":
        "استورد ملف JSON لتسجيل صادر من هذا المحلّل. يبقى الدليل المستورد مميّزاً عن التسجيل الذي نفذته هذه المنصة.",
    "Runtime capture JSON": "ملف تسجيل التشغيل JSON",
    "Import capture": "استيراد التسجيل",
    "The runtime capture exceeds the 64 MiB import limit.": "حجم التسجيل يتجاوز حد الاستيراد البالغ 64 ميبيبايت.",
    "The runtime capture could not be imported.": "تعذّر استيراد تسجيل التشغيل.",
    "No runtime capture has been recorded for this scan yet.": "لا يوجد تسجيل أثناء التشغيل مرتبط بهذا الفحص بعد.",
    "Recorded capture session": "جلسة التسجيل المحفوظة",
    "Runtime analysis": "التحليل أثناء التشغيل",
    "Live capture requires a connected Android lab. Import its capture JSON to inspect it here.":
        "التسجيل المباشر يحتاج إلى جهاز أندرويد مخصّص للاختبار ومتصل بالمنصة. استورد ملف التسجيل JSON لمعاينته هنا.",
    "The archived runtime capture could not be loaded.": "تعذّر تحميل تسجيل التشغيل المؤرشف.",
    "The archived runtime evidence is unavailable. Its summary is not a complete capture.":
        "دليل التشغيل المؤرشف غير متاح. الملخّص وحده ليس تسجيلاً كاملاً.",
})


# Provenance for bounded, derived literal evidence.
AR.update({
    "Base64-decoded literal": "قيمة نصية مفكوكة من Base64",
    "Decoded-literal provenance is unavailable or invalid.": "مصدر القيمة المفكوكة غير متاح أو غير صالح.",
    "Base64-decoded text. These lines are derived evidence, not original source lines.":
        "نص فُك ترميزه من Base64. هذه الأسطر دليل مشتق وليست أسطر الملف الأصلي.",
    "Encoded source: %s · line %d · columns %d–%d · decoding depth %d":
        "المصدر المرمّز: %s · السطر %d · الأعمدة %d–%d · عمق فك الترميز %d",
    "The encoded source is outside the retained preview.": "المصدر المرمّز خارج نطاق المعاينة المحفوظة.",
    "Open encoded source": "افتح المصدر المرمّز",
})
