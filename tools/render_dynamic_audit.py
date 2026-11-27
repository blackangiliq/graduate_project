"""Render only recorded device evidence; empty or failed captures stay visibly empty."""
from __future__ import annotations

import argparse
from collections import Counter
import html
import json
from pathlib import Path
from urllib.parse import quote


def escaped(value) -> str:
    return html.escape(str(value), quote=True)


def json_block(value) -> str:
    return "<pre dir='ltr'>" + escaped(json.dumps(value, ensure_ascii=False, indent=2)) + "</pre>"


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def observation_html(item: dict, events: list, comparison: dict) -> str:
    source = item.get("evidence", {})
    event_line = source.get("line")
    recorded_event = (events[event_line - 1] if isinstance(event_line, int)
                      and 1 <= event_line <= len(events) else None)
    locations = []
    for location in item.get("locations", []):
        description = "تطابق ثابت موثّق" if location.get("verified") else "سياق استدعاء؛ ليس تطابقاً مؤكداً للقيمة"
        locations.append("<li><code dir='ltr'>" + escaped(location.get("file", "")) + ":"
                         + escaped(location.get("line", "?")) + "</code> — " + description
                         + " <small>(" + escaped(location.get("relation", "")) + ")</small></li>")
    static_match = {"also_in_static_inventory": "موجود أيضاً في الجرد الثابت",
                    "not_found_in_static_inventory": "لم يظهر بنفس القيمة في الجرد الثابت",
                    "not_compared": "نوع غير مشمول بالمقارنة"}.get(comparison.get("comparison"), "لم تتم المقارنة")
    event_source = ("<code dir='ltr'>" + escaped(source.get("file", "")) + ":"
                    + escaped(event_line or "?") + "</code>" if source else "لا يوجد موضع حدث مسجل")
    return ("<details class='observation'><summary><span class='pill'>" + escaped(item.get("kind", ""))
            + "</span> " + escaped(item.get("label") or item.get("api") or "ملاحظة تشغيل")
            + " <small>" + escaped(item.get("confidence", "")) + "</small></summary>"
            + "<pre class='value' dir='ltr'>" + escaped(item.get("value", "")) + "</pre>"
            + "<p>" + static_match + "</p><p>سجل التشغيل: " + event_source + "</p>"
            + ("<ul>" + "".join(locations) + "</ul>" if locations else
               "<p class='muted'>لا يوجد موضع مصدر موثّق لهذه القيمة؛ موضع سجل التشغيل أعلاه هو الدليل المتاح.</p>")
            + ("<details><summary>الحدث الفعلي</summary>" + json_block(recorded_event) + "</details>"
               if recorded_event is not None else "")
            + ("<details><summary>مسار الاستدعاء</summary>" + json_block(item.get("stack")) + "</details>"
               if item.get("stack") else "") + "</details>")


def render_report(root: Path) -> str:
    inventory = load_json(root / "input_inventory.json", {"apps": []})
    device = load_json(root / "device.json", {})
    panels, navigation, totals = [], [], Counter()
    for app in inventory.get("apps", []):
        name = app["app"]
        folder = root / name
        summary = load_json(folder / "summary.json", {})
        capture = load_json(folder / "capture.json", {})
        # A failed retry must never display an older session as that retry's evidence.
        if summary and summary.get("session_id") != capture.get("session_id"):
            capture = {}
        comparison = load_json(folder / "comparison.json", {})
        comparisons = {entry["observation_id"]: entry for entry in comparison.get("observations", [])}
        observations = capture.get("observations", [])
        events = capture.get("events", [])
        status = summary.get("status", capture.get("status", "not_captured"))
        totals[status] += 1
        totals["observations"] += len(observations)
        totals["events"] += len(events)
        navigation.append("<a href='#" + escaped(name) + "'>" + escaped(name) + "</a>")
        capture_link = ("<a href='" + quote(name) + "/capture.json'>تحميل سجل الجلسة JSON</a>"
                        if capture else "")
        notes = list(capture.get("limitations", []))
        errors = list(capture.get("errors", []))
        if summary.get("error"):
            errors.append(summary["error"])
        if summary.get("install", {}).get("errors"):
            errors.extend(summary["install"]["errors"])
        details = "".join(observation_html(item, events, comparisons.get(item.get("id"), {}))
                          for item in observations)
        coverage = capture.get("coverage", {})
        panels.append("<section id='" + escaped(name) + "'><h2 dir='ltr'>" + escaped(name) + "</h2>"
                      + "<p><code dir='ltr'>" + escaped(app.get("package", "")) + "</code></p>"
                      + "<p><span class='pill'>" + escaped(status) + "</span> "
                      + str(len(events)) + " حدث · " + str(len(observations)) + " قيمة مرصودة</p>"
                      + "<p>المدة المطلوبة: " + escaped(summary.get("duration_requested", "—"))
                      + " ثانية · مدة الرصد الفعلية: " + escaped(coverage.get("observed_seconds", "—"))
                      + " ثانية · المحفوظ في الأرشيف: " + escaped(summary.get("capture_id", "—")) + "</p>"
                      + ("<p class='warning'>سبب انتهاء اتصال العملية: <code dir='ltr'>"
                         + escaped(capture["detached_reason"]) + "</code></p>" if capture.get("detached_reason") else "")
                      + ("<div class='warning'><strong>أخطاء أو أسباب توقف</strong>" + json_block(errors) + "</div>"
                         if errors else "")
                      + ("<details><summary>حدود التغطية الفعلية</summary>" + json_block(notes) + "</details>"
                         if notes else "")
                      + "<details><summary>خطافات الرصد المتاحة وحالة الجهاز</summary>"
                      + json_block(capture.get("capabilities", {})) + "</details>"
                      + (details or "<p class='warning'>لم تُسجّل قيم في هذه الجلسة. هذا لا يعني أن التطبيق خالٍ من الروابط أو المفاتيح.</p>")
                      + "<p>" + capture_link + "</p></section>")
    return """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>تدقيق التشغيل الفعلي للتطبيقات</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#11151c;color:#e5eaf1;font:16px/1.65 system-ui,sans-serif}
main{max-width:1250px;margin:auto;padding:32px 24px}h1{font-size:30px;line-height:1.3}h2{font-size:22px;margin-top:0}a{color:#8ecbff}
.lead{max-width:1000px}.muted,small{color:#aab8cb}nav{display:flex;flex-wrap:wrap;gap:8px;margin:24px 0}nav a,.pill{border:1px solid #38475c;border-radius:8px;padding:4px 10px;text-decoration:none;font-size:14px}
section{background:#1a2230;border:1px solid #344257;border-radius:12px;padding:24px;margin:24px 0;scroll-margin-top:16px}
details{margin:12px 0;border:1px solid #344257;border-radius:8px;padding:12px}summary{cursor:pointer}.observation{background:#121923}
pre{white-space:pre-wrap;overflow-wrap:anywhere;overflow:auto;padding:14px;background:#0d121a;border-radius:6px;font:13px/1.65 Consolas,monospace;max-height:550px}
pre.value{max-height:none;color:#b8f0d4;font-size:15px;border-right:3px solid #5dcc99}code{overflow-wrap:anywhere}.warning{background:#352b19;border-radius:8px;padding:14px}.stats{font-size:18px;color:#b8f0d4}
</style></head><body><main><h1>تدقيق التشغيل الفعلي للتطبيقات</h1>
<p class="lead">هذا التقرير يعرض ما رُصد أثناء تشغيل النسخ المحددة على جهاز الاختبار. نطاق التجربة هو بدء التطبيق فقط، دون تسجيل دخول أو تفاعل مع شاشات لاحقة. القيم معروضة كاملة كما سجلها المحرك.</p>
<p class="warning">وجود قيمة أثناء التشغيل لا يثبت أنها ثغرة أو قابلة للاستغلال. وعدم ظهورها في التحليل الثابت لا يثبت أنها تولّدت وقت التشغيل. اسم المضيف المرصود عبر DNS لا يكشف بالضرورة مسار HTTPS، والمعاينة لا تدّعي تغطية جميع مسارات التطبيق أو فك جميع اتصالات TLS.</p>
""" + "<p class='stats'>" + str(len(inventory.get("apps", []))) + " تطبيقاً · " + str(totals["events"]) + " حدثاً · " + str(totals["observations"]) + " قيمة مرصودة</p><nav>" + "".join(navigation) + "</nav>" + "<details><summary>هوية جهاز الاختبار</summary>" + json_block(device) + "</details>" + "".join(panels) + "<p class='muted'>موضع الحدث هو سجل JSONL الفعلي. لا يُعد موضع المصدر موثّقاً إلا إذا تم التحقق من القيمة في الملف. سياق الدالة المعاد بناؤها يظل قرينة منفصلة.</p></main></body></html>"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.directory / "report.html"
    output.write_text(render_report(args.directory), encoding="utf-8")
    print(str(output.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
