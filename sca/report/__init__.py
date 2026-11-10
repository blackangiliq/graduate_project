"""Report writers: HTML, JSON, SARIF and PDF."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable

from ..models import ScanResult
from .html_report import render_html
from .pdf_report import render_pdf
from .sarif import to_sarif

FORMATS = ("html", "json", "sarif", "pdf")


def write_reports(result: ScanResult, out_dir: str, formats: Iterable[str] = ("html", "json"),
                  name: str = "sca-report") -> Dict[str, str]:
    """Write the chosen report formats into ``out_dir`` and return {format: path}."""
    folder = Path(out_dir)
    folder.mkdir(parents=True, exist_ok=True)
    written: Dict[str, str] = {}
    for fmt in formats:
        fmt = fmt.strip().lower()
        if fmt == "html":
            path = folder / (name + ".html")
            path.write_text(render_html(result), encoding="utf-8")
        elif fmt == "json":
            path = folder / (name + ".json")
            path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
                            encoding="utf-8")
        elif fmt == "sarif":
            path = folder / (name + ".sarif")
            path.write_text(json.dumps(to_sarif(result), indent=2, ensure_ascii=False),
                            encoding="utf-8")
        elif fmt == "pdf":
            path = folder / (name + ".pdf")
            path.write_bytes(render_pdf(result))
        else:
            raise ValueError("Unknown report format: %s" % fmt)
        written[fmt] = str(path)
    return written
