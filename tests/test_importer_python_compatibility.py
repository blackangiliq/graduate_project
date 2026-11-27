"""Exercise the importer path used by Python 3.10 CI, even on newer Python."""
import builtins
from pathlib import Path
import runpy
import sys

import pytest

try:
    import tomllib as parser
except ModuleNotFoundError:
    import tomli as parser


@pytest.mark.parametrize("script", ["import_rules.py", "import_betterleaks.py", "import_contextual_secrets.py"])
def test_importers_fall_back_when_stdlib_tomllib_is_unavailable(monkeypatch, script):
    real_import = builtins.__import__
    used = []

    def without_stdlib(name, *args, **kwargs):
        if name == "tomllib":
            raise ModuleNotFoundError("Python 3.10 has no tomllib")
        if name == "tomli":
            used.append(name)
        return real_import(name, *args, **kwargs)

    # The compatibility branch can be verified without requiring the optional
    # backport on Python 3.11+. On Python 3.10 this is the real installed tomli.
    monkeypatch.setitem(sys.modules, "tomli", parser)
    monkeypatch.setattr(builtins, "__import__", without_stdlib)
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools" / script))
    assert used
    assert module["tomllib"].loads('[[rules]]\nid = "fixture"\n') == {"rules": [{"id": "fixture"}]}
