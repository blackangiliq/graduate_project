from pathlib import Path

from sca.decoded import build_previews
from sca.walker import SourceFile


def test_short_dex_strings_after_legacy_line_cap_remain_browsable():
    lines = ["library.symbol"] * 300_000 + ["https://example.test/api/account"]
    source = SourceFile(Path("classes2.dex"), "classes2.dex", "config",
                        "\n".join(lines), lines=lines, origin="strings")
    preview = build_previews([source])[source.rel]
    assert len(preview.lines) == len(lines)
    assert preview.lines[300_000] == "https://example.test/api/account"
