"""Runs an untrusted regular expression in a separate process.

A rule written by an LLM may contain a pattern with catastrophic backtracking: a regular
expression that needs seconds or hours on certain inputs. Python cannot interrupt a running
regular expression, so the pattern is tried in a child process that is killed after a time
limit. If the child is killed, the rule is rejected.

This file uses only the standard library and is executed by path, so the child process
starts fast and loads nothing else.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import List, Optional, Tuple

TIMEOUT_SECONDS = 6.0


def run_patterns(pattern: str, exclude: str, ignore_case: bool, lines: List[str],
                 timeout: Optional[float] = None) -> Tuple[Optional[List[int]], str]:
    """Return (indexes of the lines the rule matches, "") or (None, error message)."""
    timeout = TIMEOUT_SECONDS if timeout is None else timeout
    request = json.dumps({"pattern": pattern, "exclude": exclude or "",
                          "ignore_case": bool(ignore_case), "lines": lines})
    try:
        proc = subprocess.run([sys.executable, "-I", __file__], input=request,
                              capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None, ("the pattern is too slow: no result after %.0f seconds "
                      "(catastrophic backtracking)" % timeout)
    except OSError as exc:
        return None, "could not start the sandbox: %s" % exc
    try:
        answer = json.loads(proc.stdout)
    except ValueError:
        return None, "the sandbox failed: %s" % (proc.stderr.strip()[-200:] or "no output")
    if not answer.get("ok"):
        return None, str(answer.get("error", "unknown error"))
    return [int(i) for i in answer["matches"]], ""


def _child() -> None:
    import re

    try:
        sys.stdin.reconfigure(encoding="utf-8")       # type: ignore[attr-defined]
        sys.stdout.reconfigure(encoding="utf-8")      # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    request = json.loads(sys.stdin.read())
    flags = re.IGNORECASE if request.get("ignore_case") else 0
    try:
        pattern = re.compile(request["pattern"], flags)
        exclude = re.compile(request["exclude"], flags) if request.get("exclude") else None
    except (re.error, RecursionError, OverflowError) as exc:
        print(json.dumps({"ok": False, "error": "invalid regular expression: %s" % exc}))
        return
    matches = []
    for index, line in enumerate(request["lines"]):
        if pattern.search(line) and not (exclude and exclude.search(line)):
            matches.append(index)
    print(json.dumps({"ok": True, "matches": matches}))


if __name__ == "__main__":
    _child()
