"""Render the real APK audit as a self-contained Arabic HTML report.

Uses only an allow-list of numeric metrics and non-sensitive identifiers. Credential
values, application URL literals, snippets and untrusted free-form findings are never
embedded. Relative links retain access to the complete local evidence artifacts.
It is safe to rerun while audit phases are writing: incomplete JSON is reported as
pending instead of being silently replaced by a zero-result completed scan.
"""
from __future__ import annotations

import argparse
import html
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "data/audits/2026-11-26-phone-apps"
try:
    BAGHDAD = ZoneInfo("Asia/Baghdad")
except ZoneInfoNotFoundError:
    # Windows installations without tzdata still use Baghdad's current UTC+03:00.
    BAGHDAD = timezone(timedelta(hours=3), "Asia/Baghdad")
PHASES = ("baseline", "updated", "deep")
LABELS = {"baseline": "قبل الإصلاح", "updated": "بعد الإصلاح · إعدادات مماثلة", "deep": "الفحص الموسّع · JADX"}
SHORT = {"baseline": "قبل", "updated": "بعد", "deep": "JADX"}
COVERAGE = {
    "pattern_long_lines": "أسطر تجاوزت حد محرك الأنماط",
    "pattern_line_limit": "حد طول سطر الأنماط",
    "strings_files": "ملفات نصوص مستخرجة من ثنائيات",
    "decompiled_files": "ملفات شيفرة مفككة",
    "source_files": "ملفات مصدر",
    "files_over_limit": "ملفات تجاوزت حد القراءة",
}
URL_CATEGORIES = {
    "literal_service_or_web_address": "عناوين خدمة أو ويب حرفية",
    "runtime_address_template": "قوالب عناوين تتطلب قيماً وقت التشغيل",
    "documentation_or_namespace": "توثيق أو نطاقات أسماء",
    "documentation_or_asset_metadata": "توثيق أو بيانات أصول ومكتبات",
    "oauth_scope_identifier": "معرّفات صلاحيات OAuth",
    "local_development_address": "عناوين تطوير محلية",
    "unvalidated_address_fragment": "أجزاء عناوين غير متحققة",
}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def number(value: object, fallback: str = "—") -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else fallback


def read_json(path: Path, issues: list[str]) -> object | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        issues.append(path.name)
        return None


def safe_name(value: object) -> str:
    # App folders in this audit use short identifiers, not user-supplied free text.
    name = str(value)
    return name if re.fullmatch(r"[\w .()-]{1,100}", name) else "تطبيق غير مسمى"


def artifact(base: Path, relative: str, label: str, *, missing: bool = False) -> str:
    path = base / relative
    if not missing and not path.is_file():
        return ""
    # Always relative: the report can move together with its evidence folder.
    return f'<a class="artifact" href="{quote(relative, safe="/._-")}">{esc(label)}</a>'


def load_state(base: Path) -> dict:
    issues: list[str] = []
    reference = read_json(base / "reference.json", issues) or {}
    comparison = read_json(base / "comparison.json", issues) or {}
    review = read_json(base / "reference_review.json", issues) or {}
    manual = read_json(base / "manual_after_review.json", issues)
    reference_apps = reference.get("apps", []) if isinstance(reference, dict) else []
    comparison_apps = comparison.get("apps", []) if isinstance(comparison, dict) else []
    reviewed_apps = review.get("apps", []) if isinstance(review, dict) else []
    comparisons = {str(a.get("app")): a for a in comparison_apps if isinstance(a, dict)}
    reviews = {str(a.get("name")): a for a in reviewed_apps if isinstance(a, dict)}
    summaries: dict[str, dict] = {p: {} for p in PHASES}
    for phase in PHASES:
        grouped = read_json(base / phase / "summary.json", issues)
        if isinstance(grouped, list):
            summaries[phase].update({str(a["app"]): a for a in grouped if isinstance(a, dict) and "app" in a})
        for file in sorted((base / phase).glob("*.summary.json")):
            record = read_json(file, issues)
            if isinstance(record, dict) and "app" in record:
                summaries[phase][str(record["app"])] = record
    names = list(dict.fromkeys([str(a.get("name")) for a in reference_apps if isinstance(a, dict)] +
                              [name for phase in PHASES for name in summaries[phase]]))
    refs = {str(a.get("name")): a for a in reference_apps if isinstance(a, dict)}
    apps = []
    for name in names:
        phases = {}
        for phase in PHASES:
            summary = summaries[phase].get(name)
            report = read_json(base / phase / f"{name}.report.json", issues) if summary else None
            report = report if isinstance(report, dict) else {}
            comparison_row = comparisons.get(name, {}).get("phases", {}).get(phase)
            # A matching phase can still be stale during a rerun. Never present an
            # old exact-match score next to fresh summary totals without marking it.
            stale = bool(comparison_row and summary and any(
                comparison_row.get(c) != summary.get(s)
                for c, s in (("findings", "findings"), ("displayed_keys", "keys"),
                             ("displayed_urls", "endpoints"), ("files", "files"))))
            phases[phase] = {"summary": summary, "report": report,
                             "comparison": None if stale else comparison_row, "stale": stale}
        apps.append({"name": name, "reference": refs.get(name, {}), "review": reviews.get(name, {}),
                     "comparison": comparisons.get(name, {}), "phases": phases})
    return {"base": base, "apps": apps, "reference": reference, "manual": manual,
            "issues": issues, "review": review}


def completed(app: dict, phase: str) -> bool:
    summary = app["phases"][phase]["summary"]
    return bool(summary and summary.get("status") == "ok")


def phase_totals(apps: list[dict], phase: str) -> dict:
    rows = [a["phases"][phase]["summary"] for a in apps if completed(a, phase)]
    return {"done": len(rows), **{field: sum(r.get(field, 0) for r in rows if isinstance(r.get(field), int))
                                  for field in ("keys", "endpoints", "findings", "files", "calls", "paths")}}


def comparison_total(apps: list[dict], phase: str, field: str) -> tuple[int, int]:
    rows = [a["phases"][phase]["comparison"] for a in apps if completed(a, phase)]
    rows = [r for r in rows if isinstance(r, dict) and isinstance(r.get(field), int)]
    return sum(r[field] for r in rows), len(rows)


def reference_counts(app: dict) -> dict:
    ref = app["reference"]
    keys = ref.get("keys", [])
    urls = ref.get("urls", [])
    return {"google": sum(k.get("kind") == "google-api-key" for k in keys),
            "pem": len(ref.get("pem_blocks", [])),
            "markers": sum(k.get("status") == "header_marker_only_not_key_material" for k in keys),
            "fixtures": sum(k.get("status") == "fixture_shaped_jwt_not_production_secret_proof" for k in keys),
            "literal_urls": sum(u.get("category") == "literal_service_or_web_address" for u in urls),
            "categories": Counter(u.get("category", "") for u in urls),
            "apks": len(ref.get("apks", []))}


def match_text(apps: list[dict], phase: str, field: str, denominator: int) -> str:
    total, count = comparison_total(apps, phase, field)
    if count != len(apps):
        return f'<span class="pending">المطابقة قيد الإكمال · {count}/{len(apps)} تطبيقاً</span>'
    return f'<strong dir="ltr">{total} / {denominator}</strong>'


def metric(value: object, label: str, note: str = "") -> str:
    return f'<div class="metric"><b dir="ltr">{number(value)}</b><span>{esc(label)}</span><small>{esc(note)}</small></div>'


def compact_phase(app: dict, phase: str) -> str:
    row = app["phases"][phase]["summary"]
    if not row:
        return '<span class="pending">لم يكتمل بعد</span>'
    if row.get("status") != "ok":
        return '<span class="pending">تحتاج مراجعة</span>'
    return (f'<div class="triplet"><b>{number(row.get("keys"))}</b><i>/</i>'
            f'<b>{number(row.get("endpoints"))}</b><i>/</i><b>{number(row.get("findings"))}</b></div>')


def render_app(base: Path, app: dict) -> str:
    name = safe_name(app["name"])
    counts = reference_counts(app)
    phase_cards = []
    for phase in PHASES:
        record = app["phases"][phase]
        row = record["summary"]
        if not row:
            phase_cards.append(f'<article class="phase-card waiting"><h4>{LABELS[phase]}</h4><p>لم تصل نتيجة مكتملة بعد.</p></article>')
            continue
        success = row.get("status") == "ok"
        status = "اكتمل" if success else "لم يكتمل بنجاح"
        report = record["report"]
        scan_id = row.get("scan_id")
        archive = f'الفحص المؤرشف #{scan_id}' if isinstance(scan_id, int) else "فحص مقارنة بلا أرشفة"
        coverage = report.get("app", {}).get("analysis_coverage", {})
        coverage = coverage if isinstance(coverage, dict) else {}
        coverage_html = "".join(f'<li>{esc(label)}: <b>{number(coverage[k])}</b></li>'
                                for k, label in COVERAGE.items() if isinstance(coverage.get(k), int) and coverage[k])
        origins = row.get("origins", {})
        decompiled = origins.get("decompiled", 0) if isinstance(origins, dict) else 0
        if phase == "deep" and not decompiled:
            coverage_html += '<li>لا توجد شيفرة مفككة مسجلة؛ تشغيل مرحلة JADX وحده لا يثبت نجاح التفكيك.</li>'
        limits = row.get("inventory_limits", {})
        positive_limits = {k: v for k, v in limits.items() if isinstance(v, int) and v > 0} if isinstance(limits, dict) else {}
        if positive_limits:
            coverage_html += f'<li>عدادات حدود الجرد غير الصفرية: <b>{len(positive_limits)}</b>؛ راجع ملخص المرحلة.</li>'
        warnings = row.get("warnings", [])
        if warnings:
            coverage_html += f'<li>تنبيهات أدوات أو تغطية: <b>{len(warnings)}</b>؛ النص الكامل في التقرير.</li>'
        comparison = record["comparison"]
        matched = '<p class="muted small">المطابقة مع المرجع لم تُحدّث لهذه المرحلة بعد.</p>'
        if comparison:
            matched = ('<dl class="matches">'
                       f'<div><dt>صيغ المرجع</dt><dd>{number(comparison.get("format_matches"))} / {number(app["comparison"].get("reference_formats"))}</dd></div>'
                       f'<div><dt>مواد PEM كاملة</dt><dd>{number(comparison.get("complete_pem_material_matches"))} / {counts["pem"]}</dd></div>'
                       f'<div><dt>عناوين مرجعية مطابقة</dt><dd>{number(comparison.get("reference_url_matches"))} / {number(app["comparison"].get("reference_service_web_and_template_urls"))}</dd></div>'
                       '</dl>')
        links = "".join(artifact(base, f'{phase}/{app["name"]}.{suffix}', label)
                        for suffix, label in (("report.json", "التقرير الكامل"), ("summary.json", "ملخص القياس"),
                                              ("hits.json", "أدلة القيم"), ("sources.json.gz", "لقطة الملفات")))
        severity = report.get("summary", {})
        severity_html = "".join(f'<span class="sev {k}">{label} {number(severity[k])}</span>'
                                 for k, label in (("critical", "حرج"), ("high", "عالٍ"), ("medium", "متوسط"), ("low", "منخفض"), ("info", "معلومة"))
                                 if isinstance(severity.get(k), int) and severity[k])
        phase_cards.append(f'''<article class="phase-card"><div class="phase-title"><h4>{LABELS[phase]}</h4><span class="badge {'ok' if success else 'pending'}">{status}</span></div>
        <p class="archive">{esc(archive)}</p><div class="mini-metrics">{metric(row.get('keys'),'قيم في جرد المفاتيح')}{metric(row.get('endpoints'),'عناوين URL في الجرد')}{metric(row.get('findings'),'نتائج قواعد')}</div>
        <p class="small muted">ملفات: {number(row.get('files'))} · مواضع استدعاء API: {number(row.get('calls'))} · مسارات: {number(row.get('paths'))} · شيفرة مفككة: {number(decompiled)}</p>
        <div class="severity">{severity_html}</div>{matched}<ul class="coverage">{coverage_html}</ul><div class="artifacts">{links}</div></article>''')
    categories = "".join(f'<span>{esc(label)} <b>{number(counts["categories"].get(k, 0))}</b></span>'
                          for k, label in URL_CATEGORIES.items() if counts["categories"].get(k))
    ready = sum(completed(app, p) for p in PHASES)
    return f'''<details class="app-card" data-name="{esc(name.lower())}"><summary><span><b dir="auto">{esc(name)}</b><small>{counts['apks']} ملفات APK · {counts['google']} صيغ Google · {counts['pem']} مواد PEM كاملة</small></span><span class="badge {'ok' if ready == 3 else 'pending'}">{ready}/3 مراحل</span></summary>
    <div class="app-body"><p class="small muted">المرجع المستقل: {counts['literal_urls']} عنوان خدمة أو ويب حرفياً؛ {counts['markers']} علامة PEM بلا مادة كاملة؛ {counts['fixtures']} رموز ذات سياق اختباري. هذه أعداد دليل، وليست عدداً مؤكداً للثغرات.</p>
    <div class="category-tags">{categories}</div><div class="phase-grid">{''.join(phase_cards)}</div></div></details>'''


def render(state: dict) -> str:
    base, apps = state["base"], state["apps"]
    counts = [reference_counts(a) for a in apps]
    app_count = len(apps)
    totals = {phase: phase_totals(apps, phase) for phase in PHASES}
    complete = bool(apps) and all(totals[p]["done"] == app_count for p in PHASES)
    compare_complete = complete and all(comparison_total(apps, p, "format_matches")[1] == app_count for p in PHASES)
    google = sum(c["google"] for c in counts)
    pem = sum(c["pem"] for c in counts)
    apks = sum(c["apks"] for c in counts)
    unique_pem = len({p.get("value") for a in apps for p in a["reference"].get("pem_blocks", []) if p.get("value")})
    literal_urls = sum(c["literal_urls"] for c in counts)
    manual_ready = isinstance(state["manual"], (dict, list))
    stage = "اكتملت مراحل القياس والمطابقة" if compare_complete else "القياس جارٍ · النتائج أدناه جزئية"
    baseline_formats, baseline_count = comparison_total(apps, "baseline", "format_matches")
    google_note = (f'المقارنة السابقة طابقت {baseline_formats} من {google} صيغة مرجعية؛ ظهورها ليس اكتشافاً جديداً بسبب التوسعة.'
                   if baseline_count == app_count else 'مطابقة صيغ المرجع مع الفحص السابق لم تكتمل بعد.')
    progress = "".join(f'''<article class="progress-card"><h3>{LABELS[p]}</h3><b dir="ltr">{totals[p]['done']} / {app_count}</b><div class="progress"><span style="width:{totals[p]['done'] / max(app_count,1)*100:.1f}%"></span></div><p>{'مكتملة' if totals[p]['done'] == app_count and app_count else 'نتائج مكتملة حتى الآن'} · {number(totals[p]['files'])} ملفاً</p></article>''' for p in PHASES)
    rows = []
    for app, ref in zip(apps, counts):
        scan_id = (app["phases"]["deep"]["summary"] or {}).get("scan_id")
        archive = artifact(base, f'deep/{app["name"]}.report.json', f'#{scan_id}') if isinstance(scan_id, int) else '<span class="muted">غير مؤرشف بعد</span>'
        rows.append(f'<tr><th dir="auto">{esc(safe_name(app["name"]))}</th><td>{ref["apks"]}</td>' +
                    ''.join(f'<td>{compact_phase(app,p)}</td>' for p in PHASES) + f'<td>{archive}</td></tr>')
    artifacts = "".join(artifact(base, file, label) for file, label in (
        ("reference.json", "المرجع المستقل"), ("reference_review.json", "مراجعة الدليل"),
        ("comparison.json", "المقارنة التفصيلية"), ("manual_after_review.json", "المراجعة بعد الإصلاح"),
        ("pytest_summary.json", "ملخص الاختبارات"), ("pytest_non_ui_final.xml", "تفاصيل الاختبارات JUnit")))
    artifacts += artifact(base, "../../../docs/RULE_EXPANSION_2026_11_26.md", "توثيق القواعد")
    artifacts += artifact(base, "../../../evaluation/betterleaks_import_report.json", "قرارات استيراد القواعد")
    archive_count = sum(isinstance((a["phases"]["deep"]["summary"] or {}).get("scan_id"), int) for a in apps)
    pending_notice = '' if compare_complete else '<div class="notice">هذا تصدير أثناء العمل. الرمز «—» أو «لم يكتمل» يعني عدم توفر القياس، ولا يعني أن التطبيق خالٍ من المشكلات. لا تُقارن مجاميع مرحلتين قبل اكتمالهما على التطبيقات نفسها.</div>'
    issues_notice = f'<p class="small pending">تعذرت قراءة {len(state["issues"])} ملفات أثناء التوليد؛ قد تكون قيد الكتابة. أعد التوليد بعد اكتمال الفحص.</p>' if state["issues"] else ''
    categories = Counter()
    for c in counts:
        categories.update(c["categories"])
    category_rows = ''.join(f'<tr><td>{esc(label)}</td><td>{number(categories.get(key,0))}</td></tr>' for key,label in URL_CATEGORIES.items())
    phase_summary = ''.join(f'<tr><th>{LABELS[p]}</th><td>{totals[p]["done"]}/{app_count}</td><td>{number(totals[p]["keys"])}</td><td>{number(totals[p]["endpoints"])}</td><td>{number(totals[p]["calls"])}</td><td>{number(totals[p]["findings"])}</td></tr>' for p in PHASES)
    test_summary = state.get("pytest_summary")
    tests_html = ''
    if isinstance(test_summary, dict):
        test_metrics = ''.join(metric(test_summary.get(key), label) for key, label in (
            ('passed', 'اختبارات ناجحة'), ('failed', 'اختبارات فاشلة'),
            ('skipped', 'اختبارات متخطّاة'), ('errors', 'أخطاء تشغيل الاختبارات')))
        problems = sum(test_summary.get(key, 0) for key in ('failed', 'errors')
                       if isinstance(test_summary.get(key, 0), int))
        test_status = ('توجد حالات فشل أو أخطاء؛ لا تُعدّ الاختبارات مكتملة بنجاح.' if problems else
                       'هذه أعداد تشغيل الاختبارات الموثّق فقط، وليست مقياساً لاكتشاف جميع الثغرات.')
        scope_labels = {'full': 'نطاق التشغيل: مجموعة الاختبارات الكاملة.',
                        'non_ui': 'نطاق التشغيل: الاختبارات خارج ملفات AppTest؛ لا يشمل كل اختبارات الواجهة.',
                        'focused': 'نطاق التشغيل: اختبارات محددة مرتبطة بالتغييرات.',
                        'combined': 'نطاق التشغيل: فحوص مختارة من المحرك والواجهة.'}
        test_status += ' ' + scope_labels.get(test_summary.get('scope'), 'لم يُحدد نطاق مجموعة الاختبارات في الملف المرفق.')
        tests_html = f'<section><div class="section-title"><div class="kicker">التحقق البرمجي</div><h2>نتيجة الاختبارات المرفقة</h2><p>{test_status}</p></div><div class="metrics test-metrics">{test_metrics}</div></section>'
    timestamp = state.get('finalized_at') or datetime.now(BAGHDAD)
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=BAGHDAD)
    timestamp = timestamp.astimezone(BAGHDAD).isoformat(timespec='seconds')
    time_label = 'اعتماد التقرير' if state.get('finalized_at') and compare_complete else 'تحديث التقرير'
    return f'''<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>تقرير تدقيق تطبيقات Android — مشروع التخرج</title><style>{CSS}</style></head><body>
    <header><div class="brand"><span class="brand-icon">A</span><div>مختبر تحليل التطبيقات<small>مشروع التخرج · سجل قياس قابل للمراجعة</small></div></div><nav><a href="#results">التطبيقات</a><a href="#evidence">الدليل</a><a href="#fixes">الإصلاحات</a><a href="#limits">حدود التغطية</a><button onclick="window.print()">طباعة التقرير</button></nav></header>
    <main><section class="hero"><div class="eyebrow">ANDROID SECURITY AUDIT · 26 NOV 2026</div><h1>نتائج فعلية.<br><em>تغطية موثّقة.</em></h1><p>مراجعة مستقلة لحزم التطبيقات، ثم مقارنة الفحص قبل الإصلاح وبعده بالإعدادات نفسها، تليها مرحلة تفكيك باستخدام JADX. كل رقم يرتبط بملفات القياس المحفوظة.</p><div class="hero-meta"><span class="status-dot"></span>{stage}<span class="divider">·</span><span>{archive_count} فحوص مؤرشفة</span></div></section>
    {pending_notice}{issues_notice}<section class="metrics">{metric(app_count,'مجموعات تطبيقات','كل مجموعة تقرير مستقل')}{metric(apks,'ملفات APK','الأساس والأجزاء المرتبطة')}{metric(google,'صيغ مفاتيح Google في المرجع','وجود الصيغة لا يثبت صلاحيتها')}{metric(pem,'مواد PEM كاملة عبر التطبيقات',f'{unique_pem} قيماً مميزة بعد إزالة التكرار بين التطبيقات')}{metric(literal_urls,'عناوين خدمة أو ويب حرفية','لا تعادل عدد واجهات API')}</section>
    <section><div class="section-title"><div class="kicker">01 / مسار القياس</div><h2>ثلاث مراحل، مع فصل أثر الأدوات</h2><p>مرحلتَا «قبل» و«بعد» للمقارنة بالإعدادات نفسها دون أدوات تفكيك خارجية. مرحلة JADX أوسع، لذلك لا تُنسب كل زياداتها إلى القواعد الجديدة.</p></div><div class="progress-grid">{progress}</div></section>
    <section id="results"><div class="section-title"><div class="kicker">02 / سجل التطبيقات</div><h2>نتيجة مستقلة لكل تطبيق وأجزائه</h2><p>ترتيب الأعداد داخل كل خلية: <b>قيم المفاتيح / عناوين URL / نتائج القواعد</b>. القيم والعناوين تشمل مرشحات تحتاج مراجعة، والنتائج ليست ثغرات مؤكدة بمجرد عدّها.</p></div><div class="table-wrap"><table class="overview"><thead><tr><th>التطبيق</th><th>APK</th><th>قبل الإصلاح</th><th>بعد · الإعدادات نفسها</th><th>مع JADX</th><th>الأرشيف</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
    <div class="detail-toolbar"><h3>تفاصيل القياس والأدلة</h3><input id="app-filter" type="search" placeholder="ابحث باسم التطبيق…" aria-label="البحث باسم التطبيق"><button id="expand-all">فتح التفاصيل</button></div><div id="apps">{''.join(render_app(base,a) for a in apps)}</div></section>
    <section id="evidence"><div class="section-title"><div class="kicker">03 / ماذا تثبت المقارنة؟</div><h2>صحة القيم أهم من زيادة العدد</h2></div><div class="evidence-grid"><article class="panel"><h3>مفاتيح Google كانت مرئية سابقاً</h3><p>{google_note}</p><div class="match-row"><span>قبل</span>{match_text(apps,'baseline','format_matches',google)}</div><div class="match-row"><span>بعد</span>{match_text(apps,'updated','format_matches',google)}</div><p class="small muted">الاختبار هنا مطابقة الصيغ والقيم المرجعية، ولا يتصل بخدمات Google ولا يختبر قيود المفتاح.</p></article><article class="panel"><h3>PEM: الجسم الكامل، لا العنوان وحده</h3><p>المرجع يحتوي {pem} مواد كاملة على مستوى التطبيقات، تمثل {unique_pem} قيماً مميزة. القيمة المشتركة بين Baly وQiPhonePay مطابقة لعينة Netty العامة، والقيمتان في QiServices مطابقتان لعينات Google العامة. وجودها لا يثبت تسريب سر إنتاجي.</p><div class="match-row"><span>القيم الكاملة قبل</span>{match_text(apps,'baseline','complete_pem_material_matches',pem)}</div><div class="match-row"><span>القيم الكاملة بعد</span>{match_text(apps,'updated','complete_pem_material_matches',pem)}</div><p class="small muted">علامة BEGIN أو اسم دالة تصدير مفتاح لا يكفيان لإثبات وجود مفتاح خاص مضمن.</p></article></div>
    <div class="two-col"><article class="panel"><h3>فئات العناوين في المرجع</h3><table class="compact"><tbody>{category_rows}</tbody></table><p class="small muted">عدّ القيم داخل كل تطبيق؛ قد يتكرر العنوان بين تطبيقات مختلفة. التوثيق وبيانات الأصول لا تمثل تلقائياً اتصالات التطبيق.</p></article><article class="panel"><h3>الجرد ليس قائمة API مؤكدة</h3><p>عنوان URL حرفي يثبت وجود نص في الحزمة. موضع استدعاء API دليل مختلف: يتطلب شيفرة مقروءة وارتباطاً بطلب، ولا يثبت وحده أن المسار نُفّذ.</p><div class="table-wrap"><table class="compact"><thead><tr><th>المرحلة</th><th>مكتمل</th><th>مفاتيح</th><th>URL</th><th>استدعاءات</th><th>نتائج</th></tr></thead><tbody>{phase_summary}</tbody></table></div><p class="small muted">عدد الاستدعاءات صفر يعني أن الفحص لم يستخرج مواضع استدعاء ضمن ما استطاع قراءته؛ لا يعني أن التطبيق لا يستخدم شبكة.</p></article></div><p class="small muted">التحقق المستقل بواسطة OpenSSL أثبت أن مواد PEM الأربع صالحة حسابياً كمفاتيح RSA بطول 2048 بت وتمثل ثلاث هويات مميزة. مقارنة البصمات بالمصادر المثبتة أثبتت أن الهويات الثلاث عينات اختبار عامة من Netty وGoogle؛ ورمز JWT مطابق أيضاً لعينة GoogleTestCertificates. صلاحيتها الرياضية لا تجعلها أسرار إنتاجية مسرّبة، وتبقى القيم ومواضعها متاحة للمراجعة.</p></section>
    <section id="fixes"><div class="section-title"><div class="kicker">04 / تغييرات قابلة للتحقق</div><h2>إصلاحات التغطية والدقة</h2><p>وصف العمل المنفّذ منفصل عن نتيجته على كل تطبيق. مقاييس الإثبات تُحدّث مع اكتمال المراحل أعلاه.</p></div><div class="fix-grid">
    <article><span>01</span><h3>الحزم الكبيرة وملفات JavaScript</h3><p>معالجة فجوة ملف React Native في oodi بحجم 10,475,641 بايت. غيابه كان يسقط نصوصاً فعلية من مجال الفحص؛ وجود رابط حزمة مكتبة لا يحوّله إلى API وقت التشغيل.</p></article>
    <article><span>02</span><h3>القيم متعددة الأسطر والطويلة</h3><p>الاحتفاظ بمادة PEM الكاملة بدلاً من علامة البداية، ودعم الرمز الطويل في QiServices. ذلك الرمز مطابق لعينة GoogleTestCertificates العامة، فلا يُعرض كدليل على سر إنتاجي.</p></article>
    <article><span>03</span><h3>إشارات كاذبة أقل</h3><p>فصل ثابت رأس PEM ودوال تنسيق المفاتيح عن المادة الفعلية. كثرة عناوين BEGIN في المكتبات لا تبرر رفع عدد «المفاتيح الخاصة».</p></article>
    <article><span>04</span><h3>حدود الجرد ظاهرة</h3><p>مراجعة القطع في جرد Careem وQiPhonePay. توضح ملخصات المراحل عدادات الحدود؛ لا تُعامل قائمة مقطوعة على أنها الجرد الكامل.</p></article>
    <article><span>05</span><h3>مسارات FileProvider داخل أغلفة XML</h3><p>تصحيح قراءة root-path عندما تكون عقدة paths داخل غلاف resources في ملف XML، كما في SuperQi. كان ربط metadata بالمزوّد معروفاً؛ الفجوة في بنية الملف. المسار الواسع يحتاج مراجعة صلاحيات المشاركة والوصول.</p></article>
    <article><span>06</span><h3>88 قاعدة مضافة ومدققة</h3><p>80 صيغة مفاتيح من Betterleaks، و3 تكيفات Gitleaks، و5 فحوص Java/Kotlin مستندة إلى CodeQL. الإجمالي 629 قاعدة، منها 582 مفعّلة افتراضياً؛ تعديلات المستخدم قد تغيّر العدد النشط.</p></article>
    <article><span>07</span><h3>الموارد ذات محددات اللغة والتهيئة</h3><p>استخراج القيم المؤهلة من resources.arsc في الحزمة الأساسية والأجزاء: 43,860 قيمة ضمن 7 ملفات لغة في Careem، و5,751 قيمة ضمن 3 ملفات في Baly. تُحفظ الموارد في مسارات منفصلة، بما فيها روابط لم تكن ضمن القيم الافتراضية.</p></article>
    <article><span>08</span><h3>ملفات النص داخل res/raw</h3><p>إدخال الموارد النصية في res/raw ومجلداته المؤهلة ضمن الفحص، ومنها إعدادات JSON في Careem، مع الاحتفاظ بالمسار الأصلي وحدود القراءة. لا يُفترض أن كل ملف ثنائي محتوى نصي.</p></article>
    <article><span>09</span><h3>الإفصاح عن قطع النصوص الأصلية</h3><p>استخراج 143,023 سطراً نصياً مميزاً من SuperQi ضمن حد 500,000 سطر و64 MiB من النص. عند بلوغ حد الأسطر أو الحجم، تُحفظ الأدلة المقروءة ويُسجّل أن التغطية جزئية؛ لا يُخفى القطع خلف رسالة نجاح.</p></article>
    <article><span>10</span><h3>تفسير أدق لإشارات العناوين والمفاتيح</h3><p>مراجعة 35 عنواناً محلياً أو تطويرياً، وفصل روابط سياسة SDK عن عناوين النقل الفعلية. مفاتيح عميل Google Maps تحتاج مراجعة قيود التطبيق والشهادة وواجهات API؛ وتسميات حقول Kotlin داخل toString لا تُعدّ قيماً سرية مضمنة.</p></article>
    <article><span>11</span><h3>دقة فحوص Java المفككة</h3><p>إزالة خمس نتائج كاذبة من الحالات التي روجعت: تعبيرات SQL داخل السجلات، وتجميع مسارات دون مصدر مدخل غير موثوق، واسم التحويل RSA/ECB. تسمية RSA هذه لا تثبت استخدام نمط ECB للتشفير المتماثل. كما ضُيّقت قاعدة DevSkim المقابلة إلى إعدادات ECB المتماثلة الصريحة، مع إبقاء اختيارات تفعيل المستخدم.</p></article></div></section>
    <section id="limits" class="limits"><div class="section-title"><div class="kicker">05 / حدود الاستنتاج</div><h2>هذا التقرير لا يدّعي تغطية 100%</h2></div><div class="two-col"><div><h3>ما يمكن إثباته</h3><ul><li>وجود قيمة حرفية أو مادة مفتاح كاملة في الملفات المقروءة ومطابقتها مع المرجع.</li><li>عدد الملفات والأجزاء التي عولجت، وما سُجّل من حدود أو تنبيهات أدوات.</li><li>سلوك القواعد على الشيفرة والموارد التي أمكن استخراجها فعلياً.</li></ul></div><div><h3>ما يبقى بحاجة إلى تحليل إضافي</h3><ul><li>الروابط والقيم المنشأة وقت التشغيل أو المحمّلة أو المشفرة؛ لا يمكن ضمان استخراجها بالفحص الساكن.</li><li>الشيفرة الأصلية وFlutter AOT والتعمية؛ نجاح استخراج النصوص لا يعني استعادة منطق البرنامج كاملاً.</li><li>تكيفات CodeQL هنا تعبيرات نمطية محدودة، وليست محرك CodeQL لتحليل الأنواع وتدفق البيانات.</li><li>صلاحية المفتاح، امتيازاته وإمكانية الاستغلال؛ تطابق الصيغة ودرجة الخطورة لا يثبتان ذلك.</li></ul></div></div><p class="small">{('المراجعة بعد الإصلاح متاحة ضمن ملفات الدليل.' if manual_ready else 'ملف المراجعة بعد الإصلاح غير متاح بعد؛ لا تُعدّ المقارنة مراجعة نهائية حتى تكتمل الأدلة.')} حدود المرجع نفسه تشمل القراءة القصوى للمدخل وتحديد مواضع القيمة؛ تفاصيلها في reference.json.</p></section>
    <section><div class="section-title"><div class="kicker">06 / قابلية المراجعة</div><h2>الملفات والمصادر المثبتة</h2><p>يحتوي هذا الملخص على أعداد ونتائج مراجعة فقط. القيم الكاملة ومواضعها في ملفات الدليل المحلية المرتبطة. جميع الروابط إلى الأدلة نسبية للحفاظ على قابلية نقل المجلد.</p></div><div class="artifacts main-artifacts">{artifacts}</div><div class="sources"><a href="https://github.com/betterleaks/betterleaks/blob/702504ab4551b9a1c1837efdb6b340536aa4c761/config/betterleaks.toml">Betterleaks · 702504a</a><a href="https://github.com/gitleaks/gitleaks/blob/09242ce9c8a60d9b051fc2d166f9e849b88c7ac0/config/gitleaks.toml">Gitleaks · 09242ce</a><a href="https://github.com/github/codeql/tree/43fb30bb443c04731009218f39cba97cd93dd6fe/java/ql/src/Security/CWE">CodeQL · 43fb30b</a><a href="https://github.com/microsoft/DevSkim/compare/6997e759b48d9fed457b5399b4e89681e6a4dcd4...7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51">DevSkim · مقارنة المصدر</a><a href="https://raw.githubusercontent.com/netty/netty/7c16c1a783b7e7f45f16c4dd9e16685a5d28712d/handler/src/main/java/io/netty/handler/ssl/SslUtils.java">Netty · PROBING_KEY · 7c16c1a</a><a href="https://raw.githubusercontent.com/googleapis/google-http-java-client/cfdb6e8db0fc35148112972d0e9383f30c09b97c/google-http-client/src/main/java/com/google/api/client/testing/json/webtoken/TestCertificates.java">Google · TestCertificates · cfdb6e8</a></div></section>
    {tests_html}<footer><b>قياس موثّق، لا ضمان مطلق.</b><span>{time_label} · توقيت بغداد <span dir="ltr">(Asia/Baghdad)</span>: <time dir="ltr">{esc(timestamp)}</time></span></footer></main><script>{JS}</script></body></html>'''


CSS = r'''
:root{--ink:#122d37;--muted:#64777d;--paper:#f3f6f5;--line:#dce6e3;--teal:#087f76;--navy:#102e38;--amber:#966416}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:100px}body{margin:0;background:var(--paper);color:var(--ink);font-family:"Segoe UI",Tahoma,Arial,sans-serif;line-height:1.8}a{color:var(--teal);text-decoration:none}a:hover{text-decoration:underline}header{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:18px max(4vw,24px);background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:2}.brand{display:flex;gap:12px;align-items:center;font-weight:700}.brand-icon{display:grid;place-items:center;background:var(--navy);color:#a0e3d5;border-radius:12px;width:42px;height:42px;font-size:24px}.brand small{display:block;font-size:11px;color:var(--muted);font-weight:400}nav{display:flex;gap:23px;align-items:center;font-size:13px}nav a{color:var(--ink)}button{font:inherit;border:1px solid var(--line);background:#fff;border-radius:8px;padding:7px 13px;color:var(--ink);cursor:pointer}button:hover{background:#edf5f2}main{max-width:1440px;padding:0 48px;margin:auto}.hero{padding:72px 0 38px;max-width:920px}.eyebrow,.kicker{font-size:11px;letter-spacing:2px;color:var(--teal);font-weight:700}.eyebrow{direction:ltr;text-align:right}h1{font-size:66px;line-height:1.24;letter-spacing:-2px;margin:17px 0 24px;font-weight:750}h1 em{font-style:normal;color:var(--teal)}h2{font-size:30px;line-height:1.4;margin:9px 0 12px}h3{font-size:19px;margin:0 0 12px}h4{font-size:15px;margin:0}p{margin:0 0 14px}.hero p{font-size:18px;max-width:740px;color:#50666d}.hero-meta{display:flex;gap:9px;align-items:center;font-size:13px;color:var(--muted)}.status-dot{width:8px;height:8px;background:var(--teal);border-radius:50%}.divider{padding:0 10px}.notice{border:1px solid #ead9ad;background:#fff9e9;color:#725222;padding:14px 20px;border-radius:10px;margin-bottom:22px;font-size:13px}.metrics{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line);background:#fff;border-radius:14px;padding:25px 10px;margin:0 0 64px}.metric{padding:0 20px;border-left:1px solid var(--line)}.metric:last-child{border:0}.metric b{font-size:38px;line-height:1.25;display:block;font-weight:600;font-variant-numeric:tabular-nums}.metric span{display:block;font-size:13px;margin-top:9px}.metric small{display:block;font-size:10px;color:var(--muted);line-height:1.6;margin-top:6px}section{margin-bottom:62px}.section-title{max-width:850px;margin-bottom:24px}.section-title p{font-size:14px;color:var(--muted)}.progress-grid,.phase-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.progress-card{background:var(--navy);color:#fff;padding:24px 28px;border-radius:13px}.progress-card h3{font-size:15px;font-weight:400;color:#b7cbc9}.progress-card>b{font-size:28px;display:block}.progress-card p{font-size:11px;color:#b7cbc9;margin:12px 0 0}.progress{height:4px;background:#31505a;margin-top:16px;border-radius:4px;overflow:hidden}.progress span{display:block;background:#7cdbc1;height:100%}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:#fff}table{width:100%;border-collapse:collapse;font-size:13px;text-align:right}th,td{padding:15px 18px;border-bottom:1px solid var(--line);vertical-align:middle}thead{background:#eaf0ee;color:#63777c;font-size:11px}.overview th:first-child{min-width:200px}.overview td{text-align:center}.overview thead th:not(:first-child){text-align:center}.overview tbody th{font-weight:600;font-size:12px}tr:last-child>*{border-bottom:0}.triplet{direction:ltr;white-space:nowrap;font-variant-numeric:tabular-nums;display:flex;gap:8px;justify-content:center}.triplet b{font-weight:500}.triplet i{color:#aabbb6;font-style:normal}.pending{color:var(--amber);font-size:11px}.muted{color:var(--muted)}.small{font-size:12px}.detail-toolbar{display:flex;gap:14px;align-items:center;margin:34px 0 16px}.detail-toolbar h3{margin:0;margin-left:auto}.detail-toolbar input{font:inherit;font-size:13px;background:#fff;border:1px solid var(--line);padding:10px 14px;border-radius:9px;width:245px}.app-card{background:#fff;border:1px solid var(--line);border-radius:12px;margin-bottom:12px;overflow:hidden}.app-card summary{display:flex;justify-content:space-between;align-items:center;cursor:pointer;padding:19px 24px;gap:15px;list-style:none}.app-card summary>span:first-child:before{content:'+';display:inline-block;margin-left:15px;color:var(--teal);font-size:18px}.app-card[open] summary>span:first-child:before{content:'−'}.app-card summary b{font-size:15px}.app-card summary small{display:block;font-size:11px;color:var(--muted);margin-right:30px}.app-card[open] summary{border-bottom:1px solid var(--line);background:#f9fbfa}.badge{font-size:10px;padding:4px 9px;border-radius:20px;white-space:nowrap}.badge.ok{color:#247668;background:#e3f5ee}.badge.pending{background:#fff3da}.app-body{padding:24px}.phase-card{border:1px solid var(--line);border-radius:10px;padding:18px;background:#fff;min-width:0}.phase-title{display:flex;align-items:center;justify-content:space-between;gap:8px}.archive{font-size:10px;color:var(--muted);margin:6px 0 18px}.mini-metrics{display:grid;grid-template-columns:repeat(3,1fr);margin-bottom:14px}.mini-metrics .metric{padding:0 9px}.mini-metrics .metric b{font-size:24px}.mini-metrics .metric span{font-size:10px;line-height:1.5}.mini-metrics .metric small{display:none}.severity{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:14px}.sev{border-radius:5px;padding:3px 6px;font-size:10px;background:#edf3f4}.sev.high{color:#a95721;background:#fff0dc}.sev.critical{color:#a12b42;background:#ffe7eb}.sev.medium{color:#8e701f;background:#faf4de}.matches{border-top:1px solid var(--line);padding-top:10px;margin:0;font-size:11px}.matches>div{display:flex;justify-content:space-between}.matches dd{direction:ltr;margin:0}.coverage{padding-right:17px;font-size:10px;color:var(--muted);margin:10px 0}.artifacts{display:flex;gap:7px;flex-wrap:wrap;margin-top:16px}.artifact{border:1px solid var(--line);padding:4px 9px;border-radius:6px;font-size:10px;display:inline-block}.waiting{background:#f7f9f8;color:var(--muted)}.waiting p{font-size:12px;margin-top:20px}.category-tags{display:flex;gap:7px;flex-wrap:wrap;margin:16px 0}.category-tags span{background:#f0f5f3;border-radius:5px;padding:3px 8px;font-size:10px;color:var(--muted)}.category-tags b{color:var(--ink);margin-right:4px}.evidence-grid,.two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}.panel{background:#fff;border:1px solid var(--line);border-radius:13px;padding:27px}.panel>p{font-size:13px}.panel .small{font-size:11px;margin-top:16px}.match-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line);font-size:13px}.match-row strong{font-size:24px;color:var(--teal)}.compact td,.compact th{padding:10px 12px;font-size:11px}.compact td:last-child{font-variant-numeric:tabular-nums}.fix-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.fix-grid article{padding:24px;background:#fff;border-top:3px solid var(--teal);border-radius:0 0 10px 10px}.fix-grid article>span{color:#a0b4ac;font-size:11px;direction:ltr;display:block;margin-bottom:10px}.fix-grid h3{font-size:17px}.fix-grid p{font-size:12px;color:var(--muted);margin:0}.limits{background:#e8eeeb;padding:34px;border-radius:14px}.limits .two-col{margin:0}.limits li{font-size:13px;margin-bottom:9px}.limits ul{padding-right:20px}.limits .small{color:var(--muted);border-top:1px solid #cfddd6;padding-top:20px;margin:16px 0 0}.main-artifacts .artifact{padding:9px 14px;font-size:12px;background:#fff}.sources{display:flex;flex-wrap:wrap;gap:20px;font-size:11px;margin-top:23px;direction:ltr;justify-content:flex-end}footer{display:flex;justify-content:space-between;gap:20px;border-top:1px solid var(--line);padding:25px 0 40px;font-size:11px;color:var(--muted)}footer b{color:var(--ink)}[hidden]{display:none!important}@media(max-width:1100px){main{padding:0 24px}.phase-grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(3,1fr);gap:24px}.metrics>.metric:nth-child(3){border:0}.fix-grid{grid-template-columns:repeat(2,1fr)}.mini-metrics .metric b{font-size:28px}}@media(max-width:720px){header{position:static;display:block;padding:18px 20px}nav{margin-top:15px;gap:16px;font-size:11px;flex-wrap:wrap}nav button{margin-right:auto}main{padding:0 18px}.hero{padding:44px 0 26px}h1{font-size:48px}.hero p{font-size:15px}.hero-meta{flex-wrap:wrap}.metrics{grid-template-columns:repeat(2,1fr);padding:20px 4px;margin-bottom:42px}.metrics .metric:nth-child(3){border-left:1px solid var(--line)}.metrics .metric:nth-child(even){border:0}.metric b{font-size:32px}.progress-grid,.evidence-grid,.two-col,.fix-grid{grid-template-columns:1fr}.detail-toolbar{flex-wrap:wrap}.detail-toolbar h3{width:100%;font-size:18px}.detail-toolbar input{flex:1;min-width:120px}.app-body{padding:14px}.app-card summary{padding:16px}.app-card summary b{font-size:13px}h2{font-size:25px}.limits{padding:24px}section{margin-bottom:45px}footer{display:block}footer span{display:block;margin-top:7px}}@media print{header{position:static}nav,button,input{display:none!important}body{background:#fff}main{padding:0;max-width:none}.hero{padding:20px 0}h1{font-size:40px}.metrics,section{margin-bottom:24px}.app-card{break-inside:avoid}.phase-grid{grid-template-columns:repeat(3,1fr)}.progress-card{color:#122d37;background:#edf3f0}.progress-card h3,.progress-card p{color:#435d62}a{color:#122d37}.panel,.fix-grid article{break-inside:avoid}footer{padding-bottom:0}}
'''

CSS += '.metrics.test-metrics{grid-template-columns:repeat(4,1fr)}@media(max-width:720px){.metrics.test-metrics{grid-template-columns:repeat(2,1fr)}}'


JS = r'''
const cards=[...document.querySelectorAll('.app-card')];
document.getElementById('app-filter').addEventListener('input',event=>{const q=event.target.value.toLowerCase().trim();cards.forEach(card=>card.hidden=!card.dataset.name.includes(q));});
document.getElementById('expand-all').addEventListener('click',event=>{const open=cards.some(card=>!card.hidden&&!card.open);cards.filter(card=>!card.hidden).forEach(card=>card.open=open);event.target.textContent=open?'طي التفاصيل':'فتح التفاصيل';});
window.addEventListener('beforeprint',()=>{cards.forEach(card=>{card.dataset.wasOpen=card.open?'1':'0';card.open=true;});});
window.addEventListener('afterprint',()=>{cards.forEach(card=>card.open=card.dataset.wasOpen==='1');});
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", type=Path, default=DEFAULT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pytest-summary", type=Path,
                        help="optional JSON with numeric passed, failed, skipped, errors counts")
    parser.add_argument("--finalized-at", type=str,
                        help="optional ISO 8601 approval timestamp, displayed in Asia/Baghdad")
    args = parser.parse_args()
    base = args.audit_dir.resolve()
    if not base.is_dir():
        parser.error("audit directory does not exist")
    state = load_state(base)
    test_path = args.pytest_summary or base / "pytest_summary.json"
    state["pytest_summary"] = read_json(test_path, state["issues"])
    if args.finalized_at:
        try:
            datetime.fromisoformat(args.finalized_at.replace("Z", "+00:00"))
        except ValueError:
            parser.error("--finalized-at must be an ISO 8601 timestamp")
        state["finalized_at"] = args.finalized_at
    document = render(state)
    # Defense in depth: refuse to write if any known literal credential entered the
    # summary by accident. These values remain available in linked evidence files.
    for app in state["apps"]:
        for item in app["reference"].get("keys", []) + app["reference"].get("pem_blocks", []):
            value = item.get("value", "")
            if len(value) >= 16 and (value in document or esc(value) in document):
                raise RuntimeError("Known credential literal must not appear in the HTML summary")
    output = args.output or base / "audit.html"
    output.write_text(document, encoding="utf-8")
    print(json.dumps({"output": str(output), "apps": len(state["apps"]), "read_issues": len(state["issues"]),
                      "completed": {p: phase_totals(state["apps"], p)["done"] for p in PHASES},
                      "bytes": output.stat().st_size}, ensure_ascii=True))


if __name__ == "__main__":
    main()
