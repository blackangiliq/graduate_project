"""Write docs/RULES.md and docs/DIAGRAMS.md from the texts the dashboard shows.

    python tools/build_docs.py

The Guide tab of the dashboard and these two documents share one source (sca/ui/texts.py and
evaluation/import_report.json), so they cannot drift apart. Run this after changing the
texts or after a new import of rules.
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sca import rulebook  # noqa: E402
from sca.engines import rules_engine  # noqa: E402
from sca.ui import texts  # noqa: E402
from sca.walker import RULE_LANGUAGE  # noqa: E402

REPORT = json.loads((ROOT / "evaluation" / "import_report.json").read_text(encoding="utf-8"))


def import_table(lang: str) -> str:
    head = ("| Source | Rules in the source | Imported, enabled | Imported, disabled | Left out |"
            if lang == "en" else
            "| المصدر | قواعد المصدر | مستوردة ومفعّلة | مستوردة ومعطّلة | مستبعدة |")
    rows = [head, "|---|---:|---:|---:|---:|"]
    for source in ("DevSkim", "Gitleaks"):
        items = [r for r in REPORT["rules"] if r["source"] == source]
        count = collections.Counter(r["status"] for r in items)
        rows.append("| %s | %d | %d | %d | %d |" % (source, len(items), count["enabled"],
                                                   count["disabled"], count["skipped"]))
    return "\n".join(rows)


def skipped_table(lang: str) -> str:
    def group(reason: str) -> str:
        for key in ("does not compile", "matches the known-safe sample", "misses its own",
                    "matches its own", "language not scanned", "outside the scope"):
            if reason.startswith(key):
                return key
        return reason
    count = collections.Counter(group(r["reason"]) for r in REPORT["rules"]
                                if r["status"] == "skipped")
    head = "| Reason a rule was left out | Rules |" if lang == "en" else \
        "| سبب استبعاد القاعدة (كما سجّله سكربت الاستيراد) | العدد |"
    return "\n".join([head, "|---|---:|"] + ["| %s | %d |" % kv for kv in count.most_common()])


def corpus_table(lang: str) -> str:
    lines = REPORT["corpus"]["lines_by_language"]
    head = "| Language | Code lines measured |" if lang == "en" else "| اللغة | أسطر الكود المقاسة |"
    rows = [head, "|---|---:|"]
    rows += ["| %s | %s |" % (k, format(v, ",")) for k, v in sorted(lines.items(),
                                                                   key=lambda kv: -kv[1])]
    rows.append("| **%s** | **%s** |" % ("total" if lang == "en" else "المجموع",
                                         format(sum(lines.values()), ",")))
    return "\n".join(rows)


def coverage_table(lang: str) -> str:
    """Active pattern rules per language and origin."""
    languages = sorted({l for r in rules_engine.all_rules(False) for l in r.languages
                        if r.kind == "pattern"} - {"any"})
    head = ("| Language | Built in | Imported, enabled | Imported, disabled |" if lang == "en"
            else "| اللغة | مدمجة | مستوردة ومفعّلة | مستوردة ومعطّلة |")
    rows = [head, "|---|---:|---:|---:|"]
    shared = {v: [k for k, w in RULE_LANGUAGE.items() if w == v] for v in RULE_LANGUAGE.values()}
    for language in languages:
        rules = [r for r in rules_engine.all_rules(False)
                 if r.kind == "pattern" and language in r.languages]
        name = language + (" (+ %s)" % ", ".join(shared[language]) if language in shared else "")
        rows.append("| %s | %d | %d | %d |" % (
            name, sum(r.origin == "builtin" for r in rules),
            sum(r.origin == "imported" and r.enabled for r in rules),
            sum(r.origin == "imported" and not r.enabled for r in rules)))
    generic = [r for r in rules_engine.all_rules(False) if r.kind == "pattern"
               and "any" in r.languages]
    rows.append("| %s | %d | %d | %d |" % (
        "any language" if lang == "en" else "كل اللغات (any)",
        sum(r.origin == "builtin" for r in generic),
        sum(r.origin == "imported" and r.enabled for r in generic),
        sum(r.origin == "imported" and not r.enabled for r in generic)))
    return "\n".join(rows)


def cli_block(lang: str) -> str:
    index = 2 if lang == "ar" else 1
    return "\n".join("%-62s # %s" % (item[0], item[index]) for item in texts.CLI
                     if " rules " in item[0] or item[0].endswith("coverage"))


def rules_md() -> str:
    counts = rulebook.summary()
    origins = counts["by_origin"]
    total_lines = sum(REPORT["corpus"]["lines_by_language"].values())
    projects = len(REPORT["corpus"]["projects"])
    numbers = {
        "total": counts["total"], "enabled": counts["enabled"],
        "builtin": origins["builtin"]["total"], "imported": origins["imported"]["total"],
        "imported_on": origins["imported"]["enabled"], "secret": counts["secret"],
        "lines": format(total_lines, ","), "projects": projects,
        "noise": REPORT["max_noise_per_10k"], "date": REPORT["date"],
    }
    en = """# Rules guide / دليل القواعد

*English first, العربية في النصف الثاني.* Generated by `tools/build_docs.py` from the texts of
the dashboard and from `evaluation/import_report.json`.

## The rule set

The tool ships **%(total)d rules, %(enabled)d of them active**: %(builtin)d built in and
%(imported)d imported from open-source rule sets (%(imported_on)d active). %(secret)d of the
imported rules are credential formats and run inside the secrets engine. Rules learned from
the AI and rules you write yourself are added on top.

![Rules tab](images/ui-rules.png)

## Imported rules

The imported rules come from two MIT-licensed projects (licence texts in
`THIRD_PARTY_NOTICES.md`):

- **Microsoft DevSkim** - regular-expression rules for many languages, each with its own
  "must match" and "must not match" examples.
- **Gitleaks** - regular expressions for the key and token formats of about 200 services.

`tools/import_rules.py` converts them (import of %(date)s). A rule is accepted only if it
converts to this engine, compiles in Python, finishes on stress lines, passes its own
examples (DevSkim) or matches a string built from its own expression (Gitleaks), and stays
silent on the known-safe sample code. Accepted rules were then run on %(lines)s code lines
of %(projects)d well-known open-source projects (Django, Flask, Redis, Laravel, Express, and
others). A DevSkim rule ships **disabled** when DevSkim itself marks it as a manual-review
rule, when it fired more than %(noise)s times per 10,000 lines, or when its matches were
read by hand and found harmless; a Gitleaks rule ships disabled when it matched any product
code. Every disabled rule carries the reason in its `note` and can be switched on.

""" % numbers + import_table("en") + "\n\n" + skipped_table("en") + """

Lines of real code the rules were measured on:

""" + corpus_table("en") + """

Active pattern rules per language after the import (Python's main engine is the AST taint
analysis, so it has no built-in pattern rules):

""" + coverage_table("en") + """

What this does **not** show: the imported rules were not each proven against real
vulnerabilities, and the generated test strings for Gitleaks formats are not real keys.
The measurement shows how quiet the rules are on mature code, not how much they find.

""" + texts.RULE_GUIDE_EN.replace("\n#### ", "\n## ") + """
## An empty rule

```yaml
""" + rulebook.TEMPLATE + """```

## In the dashboard

Rules tab → **Browse and edit**: filter by origin, language, weakness and state; choose a
rule to see every field, switch it off or on, edit it, or restore the original.

![Editing a rule](images/ui-rule-edit.png)

Rules tab → **New rule**: fill in the form, press *Check the rule*, then *Save the rule*.

![New rule](images/ui-rule-new.png)

Rules tab → **Try an expression**: paste code and see which lines an expression marks.

![Try an expression](images/ui-rule-try.png)

## On the command line

```bash
""" + cli_block("en") + """
```
"""
    ar = """
---

# دليل القواعد

## مجموعة القواعد

تأتي الأداة مع **%(total)d قاعدة، منها %(enabled)d فعّالة**: %(builtin)d مدمجة و %(imported)d
مستوردة من مجموعات قواعد مفتوحة المصدر (%(imported_on)d منها فعّالة). من المستوردة %(secret)d
صيغة مفتاح تعمل داخل محرك الأسرار. وتُضاف فوقها القواعد المتعلَّمة من الذكاء الاصطناعي
والقواعد التي تكتبها أنت.

![تبويب القواعد بالعربية](images/ui-arabic-rules.png)

## القواعد المستوردة

جاءت القواعد المستوردة من مشروعين برخصة MIT (نص الرخصة في `THIRD_PARTY_NOTICES.md`):

- **Microsoft DevSkim**: قواعد بتعابير نمطية للغات كثيرة، ومع كل قاعدة أمثلتها: ما يجب أن
  تطابقه وما يجب ألّا تطابقه.
- **Gitleaks**: تعابير نمطية لصيغ مفاتيح ورموز نحو 200 خدمة.

السكربت `tools/import_rules.py` يحوّلها (استيراد بتاريخ %(date)s). لا تُقبل القاعدة إلا إذا
أمكن تحويلها إلى هذا المحرك، وتُرجمت في بايثون، وانتهت على أسطر الإجهاد، ونجحت في أمثلتها
(DevSkim) أو طابقت نصاً مولَّداً من تعبيرها نفسه (Gitleaks)، وبقيت صامتة على الكود المعروف
أنه آمن. بعد ذلك شُغّلت القواعد المقبولة على %(lines)s سطر كود من %(projects)d مشروعاً
مفتوح المصدر معروفاً (Django و Flask و Redis و Laravel و Express وغيرها). تأتي قاعدة DevSkim
**معطَّلة** إذا كان DevSkim نفسه يصنّفها قاعدة مراجعة يدوية، أو إذا طابقت أكثر من %(noise)s
مرة لكل 10,000 سطر، أو إذا قُرئت مطابقاتها يدوياً وتبيّن أنها غير مفيدة. وتأتي قاعدة Gitleaks
معطَّلة إذا طابقت أي كود إنتاجي. كل قاعدة معطَّلة تحمل السبب في حقل `note` ويمكن تفعيلها.

""" % numbers + import_table("ar") + "\n\n" + skipped_table("ar") + """

أسطر الكود الحقيقي التي قيست عليها القواعد:

""" + corpus_table("ar") + """

قواعد الأنماط لكل لغة بعد الاستيراد (المحرك الأساسي لبايثون هو تحليل AST، ولهذا ليس لها قواعد
أنماط مدمجة):

""" + coverage_table("ar") + """

ما **لا** يثبته هذا القياس: القواعد المستوردة لم تُختبر واحدةً واحدة على ثغرات حقيقية،
والنصوص المولَّدة لاختبار صيغ Gitleaks ليست مفاتيح حقيقية. القياس يبيّن مدى هدوء القواعد على
كود ناضج، ولا يبيّن كم تكتشف.

""" + texts.RULE_GUIDE_AR.replace("\n#### ", "\n## ") + """
## من الواجهة

- تبويب القواعد ← **تصفّح وتعديل**: فلتر حسب المصدر واللغة والثغرة والحالة، ثم اختر قاعدة
  لترى كل حقولها وتعطّلها أو تفعّلها أو تعدّلها أو تسترجع أصلها.
- تبويب القواعد ← **قاعدة جديدة**: املأ النموذج واضغط *افحص القاعدة* ثم *احفظ القاعدة*.
- تبويب القواعد ← **تجربة تعبير**: الصق كوداً وشاهد أي الأسطر يعلّمها التعبير.
- تبويب القواعد ← **استيراد وتصدير**: انقل قواعدك بين الحواسيب بملف YAML.

## من سطر الأوامر

```bash
""" + cli_block("ar") + """
```
"""
    return en + ar


def diagrams_md() -> str:
    parts = ["# The diagrams, explained\n",
             "Seven diagrams explain the project from the general picture to the details. "
             "Each has an English and an Arabic version (`docs/images/<name>.png` and "
             "`<name>.ar.png`), rendered from the Mermaid sources in `docs/diagrams/`. The "
             "same explanations are shown in the Guide tab of the dashboard. The Arabic "
             "walk-through with a worked numeric example is in "
             "[DIAGRAMS_AR.md](DIAGRAMS_AR.md).\n"]
    for item in texts.DIAGRAMS:
        parts += ["## %s\n" % item["title_en"], item["text_en"] + "\n",
                  "![%s](images/%s.png)\n" % (item["title_en"], item["name"]),
                  "Arabic version: [images/%s.ar.png](images/%s.ar.png) · source: "
                  "[diagrams/%s.mmd](diagrams/%s.mmd)\n" % ((item["name"],) * 4)]
    return "\n".join(parts)


def main() -> int:
    (ROOT / "docs" / "RULES.md").write_text(rules_md(), encoding="utf-8")
    (ROOT / "docs" / "DIAGRAMS.md").write_text(diagrams_md(), encoding="utf-8")
    print("Wrote docs/RULES.md and docs/DIAGRAMS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
