"""Finds the source files inside the chosen project folder and detects their language."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

LANG_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php", ".phtml": "php",
    ".java": "java",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby", ".erb": "ruby", ".rake": "ruby",
    ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".swift": "swift", ".rs": "rust", ".dart": "dart",
    ".pl": "perl", ".pm": "perl", ".lua": "lua", ".ex": "elixir", ".exs": "elixir",
    ".ps1": "powershell", ".psm1": "powershell", ".sql": "sql",
    ".vue": "javascript", ".svelte": "javascript",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".html": "html", ".htm": "html",
    ".yml": "config", ".yaml": "config", ".json": "config", ".ini": "config",
    ".cfg": "config", ".conf": "config", ".toml": "config", ".xml": "config",
    ".properties": "config", ".env": "config", ".config": "config",
    ".key": "config", ".pem": "config",              # read by the secrets engine
    # server pages and templates, checked with the rules of the language they embed
    ".jsp": "java", ".jspf": "java", ".jspx": "java", ".ejs": "javascript",
    ".aspx": "csharp", ".ascx": "csharp", ".master": "csharp", ".ashx": "csharp",
    ".asmx": "csharp", ".cshtml": "csharp", ".razor": "csharp",
}
# Pages and templates can hold inline <script> code, so the JavaScript rules apply as well.
PAGE_EXTS = {".php", ".phtml", ".erb", ".jsp", ".jspf", ".jspx", ".aspx", ".ascx", ".master",
             ".cshtml", ".razor", ".html", ".htm"}
# Well-known third-party JavaScript libraries copied into a project: they are not the
# project's code, and their internals (innerHTML, eval, "token" names) flood a report.
VENDORED_JS = re.compile(                 # jquery-3.6.0.js, chart.js; not chartUtils.js
    r"^(jquery|bootstrap|angular|react|react-dom|vue|lodash|underscore|backbone|require|ace|"
    r"wysihtml5?|d3|moment|chart|highlight|codemirror|tinymce|ckeditor|three|popper|"
    r"modernizr|html5shiv|respond|handlebars|mustache|knockout|socket\.io|sockjs|"
    r"swagger-ui-bundle|marked|showdown)([.-][\w.-]*)?\.js$")
# A copy of a file under another suffix is scanned as the original: config.inc.php.dist
BACKUP_SUFFIXES = {".dist", ".bak", ".orig", ".old"}
LANG_BY_NAME = {".env": "config", "dockerfile": "config"}

# Languages that share rules with another language.
# Kotlin, Scala and Groovy call the same JVM APIs, so the Java API rules apply to them.
RULE_LANGUAGE = {"typescript": "javascript", "cpp": "c", "kotlin": "java", "scala": "java",
                 "groovy": "java"}

# Languages that hold program logic (everything except configuration and markup).
CODE_LANGUAGES = ["python", "javascript", "typescript", "php", "java", "kotlin", "scala",
                  "groovy", "c", "cpp", "csharp", "go", "ruby", "rust", "swift", "dart",
                  "shell", "powershell", "perl", "lua", "elixir", "sql"]

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", "target", "vendor", ".idea", ".vscode", ".tox", ".mypy_cache",
    ".pytest_cache", "site-packages", "bower_components", ".next", "coverage",
}
SKIP_FILES = {"package-lock.json", "yarn.lock", "poetry.lock", "pnpm-lock.yaml",
              "composer.lock", "cargo.lock", "go.sum"}
MAX_FILE_BYTES = 1_500_000

TEST_PATH = re.compile(
    r"(^|/)(tests?|testing|__tests__|specs?|fixtures|mocks?)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test|[^/]+\.(test|spec)|tests?)\.[A-Za-z0-9]+$"
    r"|(^|/)src/it/|(^|/)(?-i:[A-Za-z0-9]+(Test|Tests|IT))\.(java|kt|scala|groovy|cs)$"
    r"|(^|/)conftest\.py$", re.IGNORECASE)


def is_test_path(rel: str) -> bool:
    """True for test code. Weaknesses there are rarely exploitable (test input is written by
    the developer), so they get a lower confidence and can be skipped entirely."""
    return bool(TEST_PATH.search(rel.replace("\\", "/")))


COMMENT_PREFIXES = {
    "python": ("#",), "shell": ("#",), "config": ("#", ";", "//"), "ruby": ("#",),
    "php": ("//", "#", "*", "/*"),
    "javascript": ("//", "*", "/*"), "typescript": ("//", "*", "/*"),
    "java": ("//", "*", "/*"), "c": ("//", "*", "/*"), "cpp": ("//", "*", "/*"),
    "csharp": ("//", "*", "/*"), "go": ("//", "*", "/*"),
    "html": ("<!--",),
    "kotlin": ("//", "*", "/*"), "scala": ("//", "*", "/*"), "groovy": ("//", "*", "/*"),
    "swift": ("//", "*", "/*"), "rust": ("//", "*", "/*"), "dart": ("//", "*", "/*"),
    "perl": ("#",), "powershell": ("#",), "elixir": ("#",),
    "lua": ("--",), "sql": ("--",),
}


def mask_secret(secret: str) -> str:
    """Hide most of a secret so that reports and prompts never contain it."""
    if len(secret) <= 8:
        return secret[:1] + "*" * (len(secret) - 1)
    return secret[:4] + "*" * min(len(secret) - 6, 12) + secret[-2:]


@dataclass
class SourceFile:
    path: Path
    rel: str
    language: str
    text: str
    lines: List[str] = field(default_factory=list)
    # secrets found in this file; line_text() and context() hide them automatically
    secret_values: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.lines:
            self.lines = self.text.splitlines()

    def mask(self, text: str) -> str:
        for secret in self.secret_values:
            text = text.replace(secret, mask_secret(secret))
        return text

    @property
    def rule_language(self) -> str:
        return RULE_LANGUAGE.get(self.language, self.language)

    @property
    def rule_languages(self) -> Tuple[str, ...]:
        """The rule sets that apply: the file's own, plus JavaScript for a page or template
        (PHP, ERB, JSP, ASP.NET, HTML) that can hold inline <script> code."""
        if self.rule_language != "javascript" and self.path.suffix.lower() in PAGE_EXTS:
            return (self.rule_language, "javascript")
        return (self.rule_language,)

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.mask(self.lines[line - 1].strip())
        return ""

    def context(self, line: int, before: int = 3, after: int = 3) -> str:
        start = max(1, line - before)
        end = min(len(self.lines), line + after)
        return self.mask("\n".join("%4d | %s" % (n, self.lines[n - 1])
                                   for n in range(start, end + 1)))

    def is_comment(self, line: int) -> bool:
        stripped = self.line_text(line)
        return stripped.startswith(COMMENT_PREFIXES.get(self.language, ()))


def detect_language(path: Path) -> Optional[str]:
    name = path.name.lower()
    if name in LANG_BY_NAME:
        return LANG_BY_NAME[name]
    if name.startswith(".env"):
        return "config"
    if name.endswith(".min.js") or name.endswith(".min.css") or VENDORED_JS.match(name):
        return None
    if path.suffix.lower() in BACKUP_SUFFIXES and "." in path.stem:
        return detect_language(path.with_name(path.stem))
    return LANG_BY_EXT.get(path.suffix.lower())


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None  # binary file
    return raw.decode("utf-8", errors="replace")


def _virtualenv(folder: Path) -> bool:
    """A folder named env is skipped only when it is a Python virtual environment; in a
    Node.js project, config/env/ holds the configuration (and its secrets)."""
    return any((folder / marker).exists()
               for marker in ("pyvenv.cfg", "bin/activate", "Scripts/activate"))


def walk_project(root: str, extra_skip: Optional[List[str]] = None) -> Iterator[SourceFile]:
    """Yield every readable source file under ``root`` (a folder or a single file)."""
    root_path = Path(root).expanduser().resolve()
    skip = SKIP_DIRS | {s.strip().lower() for s in (extra_skip or []) if s.strip()}
    if root_path.is_file():
        lang = detect_language(root_path)
        text = _read_text(root_path) if lang else None
        if text is not None:
            yield SourceFile(root_path, root_path.name, lang, text)
        return
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = sorted(d for d in dirnames if d.lower() not in skip
                             or (d.lower() == "env" and not _virtualenv(Path(dirpath) / d)))
        for name in sorted(filenames):
            if name.lower() in SKIP_FILES:
                continue
            path = Path(dirpath) / name
            lang = detect_language(path)
            if not lang:
                continue
            text = _read_text(path)
            if text is None:
                continue
            rel = path.relative_to(root_path).as_posix()
            yield SourceFile(path, rel, lang, text)
