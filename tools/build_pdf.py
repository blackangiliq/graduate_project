"""Render a Markdown document of docs/ as a PDF (right-to-left, with its images).

    python tools/build_pdf.py docs/SUPERVISOR_AR.md

Needs `pip install markdown playwright` and a Chromium for Playwright, plus an Arabic font
(for example Noto Sans Arabic) installed on the machine. Only used to produce the PDF that
is committed to the repository; the tool itself does not need it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import markdown
from playwright.sync_api import sync_playwright

CSS = """
@page { size: A4; margin: 16mm 15mm 18mm 15mm; }
html { direction: rtl; }
body { font-family: "Noto Sans Arabic", "Liberation Sans", sans-serif; font-size: 10.5pt;
       line-height: 1.75; color: #1c1b19; }
h1 { font-size: 21pt; margin: 0 0 4pt; }
h2 { font-size: 14.5pt; margin: 18pt 0 6pt; padding-bottom: 3pt; border-bottom: 1.5px solid #c9c7bd;
     break-after: avoid; }
h3 { font-size: 12pt; margin: 13pt 0 4pt; break-after: avoid; }
h1 + h2 { border: 0; font-size: 13pt; margin-top: 0; }
p, li { orphans: 3; widows: 3; }
em { color: #5f5e5a; }
hr { border: 0; border-top: 1px solid #dddbd3; margin: 14pt 0; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0 10pt; font-size: 9.2pt;
        line-height: 1.55; }
th, td { border: 1px solid #c9c7bd; padding: 4pt 6pt; vertical-align: top; text-align: right; }
th { background: #f1efe8; }
thead:has(th:empty) { display: none; }
tr { break-inside: avoid; }
td[style*="text-align: right"], th[style*="text-align: right"] { text-align: left !important;
        direction: ltr; white-space: nowrap; }
code { font-family: "Liberation Mono", monospace; font-size: 8.8pt; background: #f4f3ee;
       padding: 0 3pt; border-radius: 3px; direction: ltr; unicode-bidi: isolate; }
pre { direction: ltr; text-align: left; background: #f4f3ee; border: 1px solid #dddbd3;
      border-radius: 5px; padding: 7pt 9pt; break-inside: avoid; }
pre code { background: none; padding: 0; }
a { color: #1d5f8a; text-decoration: none; unicode-bidi: isolate; }
img { display: block; max-width: 100%; max-height: 225mm; margin: 8pt auto 2pt;
      border: 1px solid #dddbd3; border-radius: 4px; }
p:has(> img) { break-inside: avoid; text-align: center; }
"""


def main() -> int:
    source = Path(sys.argv[1]).resolve()
    body = markdown.markdown(source.read_text(encoding="utf-8"),
                             extensions=["tables", "fenced_code", "sane_lists"])
    html = ("<!doctype html><html lang='ar' dir='rtl'><head><meta charset='utf-8'>"
            "<base href='%s/'><style>%s</style></head><body>%s</body></html>"
            % (source.parent.as_uri(), CSS, body))
    page_html = source.with_suffix(".print.html")
    page_html.write_text(html, encoding="utf-8")
    target = source.with_suffix(".pdf")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(page_html.as_uri())
        page.wait_for_load_state("networkidle")
        page.pdf(path=str(target), format="A4", print_background=True,
                 display_header_footer=True, header_template="<span></span>",
                 footer_template="<div style='font-size:8px;width:100%;text-align:center;"
                                 "color:#888'>Secure Code Analyzer - <span class='pageNumber'>"
                                 "</span> / <span class='totalPages'></span></div>")
        browser.close()
    page_html.unlink()
    print("Wrote %s" % target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
