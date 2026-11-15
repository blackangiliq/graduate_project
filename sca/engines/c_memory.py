"""C/C++ memory-safety checks: the weaknesses that no single-line rule can see.

A pattern rule looks at one line, so ``free(p)`` and a later ``p[0] = 'a'`` look harmless
on their own. This engine reads each function from top to bottom and remembers what
happened to every pointer and to every value that was read from outside the program
(a file, a socket, the command line or the environment):

  CWE-415  double free            free(p) a second time, with no new value for p between
  CWE-416  use after free         p used after free(p)
  CWE-401  memory leak            p = malloc(...), then p = NULL / 0 without free(p)
  CWE-190  integer overflow       malloc(n) where n = a + b, a - b or a * b and a or b came
                                  from outside: the size can wrap around to a small value
  CWE-789  excessive allocation   malloc(n) where n came from outside and was never checked
  CWE-369  divide by zero         x / d where d came from outside and was never checked
  CWE-125  out-of-bounds read     buf[i] where i came from outside, without a bounds check
  CWE-787  out-of-bounds write    buf[i] = ... with the same condition
  CWE-674  uncontrolled recursion a function that calls itself and has no if / return

It is a heuristic in the spirit of taint_lite: one function at a time, top to bottom, no
paths. A jump (return, goto, break, continue, exit) after free(p) ends what is known about
p, so the common "free and leave" error path is not reported, and a check of a value
(``if (n > 10)``, ``if (d != 0)``) before it is used counts as validation.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..models import Finding
from ..walker import SourceFile

LANGUAGES = {"c", "cpp"}
NAME = r"[A-Za-z_]\w*"
EXPR = NAME + r"(?:(?:\.|->)\w+)*"           # a, a.b, a->b.c

# Calls that fill a variable with data from outside the program.
SOURCES = [
    re.compile(r"\bfread\s*\(\s*&?\s*(" + NAME + r")"),
    re.compile(r"\b(?:read|recv|recvfrom)\s*\(\s*[^,]+,\s*&?\s*(" + NAME + r")"),
    re.compile(r"\bfgets\s*\(\s*(" + NAME + r")"),
    re.compile(r"\bgetline\s*\(\s*&\s*(" + NAME + r")"),
]
SCANF = re.compile(r"\b(?:f|s)?scanf\s*\((.*)\)")
OUTSIDE_VALUE = re.compile(r"\bargv\b|\bgetenv\s*\(")
ASSIGN = re.compile(r"(?<![\w.>])(" + NAME + r")\s*(\[[^\]]*\]\s*)?([+\-*/]?)=(?!=)\s*([^;]+)")
ARITHMETIC = re.compile(r"[\w)\]]\s*[+\-*]\s*[\w(]")
MULTIPLY = re.compile(r"[\w)\]]\s*\*\s*[\w(]")
ALLOC_CALL = re.compile(r"\b(malloc|calloc|realloc|alloca|valloc)\s*\(([^;]*)\)")
ALLOCATES = re.compile(r"\b(malloc|calloc|realloc|strdup|strndup|valloc)\s*\(|\bnew\b")
NULLISH = re.compile(r"^\s*(\([^)]*\)\s*)?(NULL|0|nullptr)\s*$")
FREE = re.compile(r"\bfree\s*\(\s*(" + NAME + r")\s*\)|\bdelete\s*(?:\[\s*\]\s*)?(" + NAME + r")\b")
JUMP = re.compile(r"\b(return|goto|break|continue|exit|_exit|abort|longjmp)\b")
COMPARE = re.compile(r"(" + EXPR + r"|\d+)\s*(?:<=|>=|==|!=|<(?![<=])|(?<!-)>(?![>=]))\s*(" + EXPR + r"|\d+)")
BARE_TEST = re.compile(r"\b(?:if|while)\s*\(\s*!?\s*(" + EXPR + r")\s*\)")
DIVISION = re.compile(r"[\w)\]]\s*[/%]\s*(" + EXPR + r")")
INDEX = re.compile(r"(" + NAME + r")\s*\[\s*(" + NAME + r")\s*\]\s*(=(?!=)|[+\-*/|&^]=)?")
CALL = re.compile(r"\b(" + NAME + r")\s*\(([^()]*)\)")
KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "else", "do", "case"}
# Functions that read or copy a buffer but do not keep the pointer.
NON_ESCAPING = KEYWORDS | {
    "memcpy", "memmove", "memset", "memcmp", "strcpy", "strncpy", "strcat", "strncat",
    "strlen", "strcmp", "strncmp", "strchr", "strstr", "printf", "fprintf", "sprintf",
    "snprintf", "puts", "fputs", "fwrite", "fread", "fgets", "read", "write", "recv", "send",
    "atoi", "atol", "strtol", "free"}


def _base(expr: str) -> str:
    return re.split(r"\.|->", expr, maxsplit=1)[0]


def _code_lines(sf: SourceFile) -> List[Tuple[int, str]]:
    """(line number, code) without comments, with the text of string and character
    literals removed, so that free(p) inside a message is not read as code."""
    out: List[Tuple[int, str]] = []
    in_block = in_macro = False
    for number, text in enumerate(sf.lines, 1):
        # a preprocessor line, and the lines a "\" at its end continues, are not code
        macro = in_macro or (not in_block and text.lstrip().startswith("#"))
        in_macro = macro and text.rstrip().endswith("\\")
        if macro:
            out.append((number, ""))
            continue
        code: List[str] = []
        i = 0
        while i < len(text):
            if in_block:
                end = text.find("*/", i)
                if end < 0:
                    break
                in_block, i = False, end + 2
                continue
            if text.startswith("/*", i):
                in_block, i = True, i + 2
                continue
            if text.startswith("//", i):
                break
            ch = text[i]
            if ch in "\"'":
                j = i + 1
                while j < len(text) and text[j] != ch:
                    j += 2 if text[j] == "\\" else 1
                code.append(ch + ch)
                i = j + 1
                continue
            code.append(ch)
            i += 1
        out.append((number, "".join(code)))
    return out


Body = List[Tuple[int, str, int]]


def _parameters(signature: str, name: str) -> List[str]:
    """The parameter names of a function signature: f(const char *data, size_t len)."""
    match = re.search(re.escape(name) + r"\s*\(([^)]*)\)", signature)
    if not match:
        return []
    names = [re.findall(NAME, part)[-1] for part in match.group(1).split(",")
             if re.findall(NAME, part)]
    return [n for n in names if n != "void"]


def _functions(lines: List[Tuple[int, str]]) -> List[Tuple[str, List[str], Body]]:
    """Split the file into function bodies: (name, parameters, [(line, code, depth)])."""
    functions: List[Tuple[str, List[str], Body]] = []
    depth, header = 0, ""
    body: Optional[Body] = None
    name: Optional[str] = None
    params: List[str] = []
    for number, code in lines:
        if body is None and depth == 0:
            header = (header + " " + code)[-500:]
            if "{" in code:
                signature = header.split("{")[0]
                calls = [m.group(1) for m in re.finditer(r"(" + NAME + r")\s*\(", signature)]
                calls = [c for c in calls if c not in KEYWORDS]
                name = calls[-1] if calls and ")" in signature else None
                params = _parameters(signature, name) if name else []
                body = []
        start = depth
        depth = max(0, depth + code.count("{") - code.count("}"))
        if body is not None:
            body.append((number, code, max(start, 1)))
            if depth == 0:
                if name:
                    functions.append((name, params, body))
                body, name, header = None, None, ""
        elif depth == 0 and (";" in code or "}" in code):
            header = ""
    return functions


FIXED_ARRAY = re.compile(
    r"\b(?:char|wchar_t|u?int\d*_t|unsigned\s+char|signed\s+char|int|short|long|BYTE)\s+("
    + NAME + r")\s*\[\s*(\d+|[A-Z_][A-Z0-9_]*)\s*\]\s*[;=]")
BOUNDED_COPY = re.compile(r"\b(memcpy|memmove|memset|strncpy|strncat|wcsncpy)\s*\(\s*(" + NAME
                          + r")\s*,\s*[^,]+,\s*(" + EXPR + r")\s*\)")
# memcpy(dst, src, sizeof(src)): the number of bytes is the size of the source
SOURCE_SIZED = re.compile(r"\bmem(?:cpy|move)\s*\(\s*(" + NAME + r")\s*,\s*(" + EXPR
                          + r")\s*,\s*sizeof\s*\(?\s*(" + EXPR + r")\s*\)?\s*\)")


class _Function:
    def __init__(self, sf: SourceFile, name: str, params: List[str], body: Body) -> None:
        self.sf, self.name, self.body = sf, name, body
        self.params: Set[str] = set(params)            # values chosen by the caller
        self.arrays: Dict[str, str] = {}               # fixed-size local array -> its size
        self.outside: Set[str] = set()                 # names holding data from outside
        self.computed: Dict[str, int] = {}             # name -> line of + - * on outside data
        self.checked: Set[str] = set()                 # expressions compared with something
        self.freed: Dict[str, Tuple[int, int]] = {}    # pointer -> (line, depth) of free()
        self.allocated: Dict[str, int] = {}            # pointer -> line of malloc()
        self.alloc_size: Dict[str, Tuple[int, str]] = {}   # pointer -> (line, size text)
        self.findings: List[Finding] = []
        self.seen: Set[Tuple[int, str]] = set()

    def report(self, line: int, rule_id: str, cwe: str, title: str, severity: str,
               confidence: float, message: str, fix: str, traced: bool = False) -> None:
        if (line, cwe) in self.seen:
            return
        self.seen.add((line, cwe))
        self.findings.append(Finding(
            rule_id=rule_id, title=title, file=self.sf.rel, line=line, severity=severity,
            cwe=cwe, description=message, fix=fix, engines=["c-memory"],
            confidence=confidence, snippet=self.sf.line_text(line),
            context=self.sf.context(line), language=self.sf.language, tainted=traced))

    def is_outside(self, expr: str) -> bool:
        return _base(expr) in self.outside

    def run(self) -> List[Finding]:
        self.recursion()
        for number, code, depth in self.body:
            if not code.strip():
                continue
            self.sources(code)
            for match in FIXED_ARRAY.finditer(code):
                self.arrays[match.group(1)] = match.group(2)
            # a comparison guards what follows it, also on its own line: if (i < 10) b[i] = c;
            for match in COMPARE.finditer(code):
                self.checked.update((match.group(1), match.group(2)))
            for match in BARE_TEST.finditer(code):
                self.checked.add(match.group(1))
            self.fixed_copies(number, code)
            self.source_sized_copies(number, code)
            self.frees_and_uses(number, code, depth)
            self.divisions(number, code)
            self.indexes(number, code)
            self.allocations(number, code)
            self.assignments(number, code)
            self.escapes(code)
            if JUMP.search(code):
                self.freed = {p: (line, d) for p, (line, d) in self.freed.items() if d < depth}
        return self.findings

    # ---------------------------------------------------------------- the checks
    def sources(self, code: str) -> None:
        for pattern in SOURCES:
            for match in pattern.finditer(code):
                self.outside.add(match.group(1))
        for match in SCANF.finditer(code):
            self.outside.update(re.findall(r"&\s*(" + NAME + r")", match.group(1)))

    def recursion(self) -> None:
        text = "\n".join(code for _, code, _ in self.body[1:])
        if re.search(r"\b(if|return|switch|case)\b|\?", text):
            return
        for number, code, _ in self.body[1:]:
            if re.search(r"\b" + re.escape(self.name) + r"\s*\(", code):
                self.report(number, "C-MEM-RECURSION", "CWE-674",
                            "Recursion without a stopping condition", "medium", 0.6,
                            "%s() calls itself and has no if or return that ends the "
                            "recursion, so it runs until the stack is exhausted." % self.name,
                            "Add a condition that stops the recursion, or use a loop.")
                return

    @staticmethod
    def touches_memory(pointer: str, code: str) -> bool:
        """True when the line reads or writes the memory behind the pointer: p[i], p->x,
        *p, passing p to a function, or returning it. Comparing the pointer value or
        handing it to an ALL-CAPS macro (an assertion or a log line) does not count."""
        name = re.escape(pointer)
        if re.search(r"\b" + name + r"\s*(\[|->)|\*\s*" + name + r"\b|\breturn\b[^;]*\b"
                     + name + r"\b", code):
            return True
        for match in CALL.finditer(code):
            function = match.group(1)
            if function in NON_ESCAPING - {"free"} or not function.isupper():
                if function != "free" and function not in KEYWORDS and \
                        re.search(r"\b" + name + r"\b", match.group(2)):
                    return True
        return False

    def frees_and_uses(self, number: int, code: str, depth: int) -> None:
        freed_here = [m.group(1) or m.group(2) for m in FREE.finditer(code)]
        for pointer, (line, _) in list(self.freed.items()):
            if pointer in freed_here:
                continue
            rest = re.sub(r"\b" + pointer + r"\s*=(?!=)[^;]*", " ", code)
            if re.search(r"\b" + pointer + r"\s*=(?!=)", code):
                del self.freed[pointer]          # a new value: no longer the freed memory
            if self.touches_memory(pointer, rest):
                self.report(number, "C-MEM-UAF", "CWE-416", "Memory used after free()",
                            "high", 0.65,
                            "%s is used here after free(%s) on line %d. The memory may "
                            "already belong to something else." % (pointer, pointer, line),
                            "Set the pointer to NULL right after free() and do not use it "
                            "again, or move free() after the last use.")
                self.freed.pop(pointer, None)
        for pointer in freed_here:
            if pointer in self.freed:
                self.report(number, "C-MEM-DOUBLE-FREE", "CWE-415", "Memory freed twice",
                            "high", 0.7,
                            "%s was already freed on line %d and is freed again here. A "
                            "double free corrupts the heap and can be exploited."
                            % (pointer, self.freed[pointer][0]),
                            "Set the pointer to NULL after free() so that a second free() "
                            "does nothing.")
            else:
                self.freed[pointer] = (number, depth)
            self.allocated.pop(pointer, None)

    def unchecked(self, expr: str) -> bool:
        return expr not in self.checked and _base(expr) not in self.checked

    def source_sized_copies(self, number: int, code: str) -> None:
        """memcpy(dst, src, sizeof(src)) where dst was allocated in this function with a
        different size: the copy writes as many bytes as the source has, not as the
        destination can hold."""
        for match in SOURCE_SIZED.finditer(code):
            target, source, measured = match.group(1), match.group(2), match.group(3)
            if measured != source or target not in self.alloc_size:
                continue
            line, size = self.alloc_size[target]
            if re.sub(r"\s", "", size) in ("sizeof(%s)" % source, "sizeof%s" % source):
                continue
            self.report(number, "C-MEM-COPY-SOURCE-SIZE", "CWE-120",
                        "Copy size taken from the source, not the destination", "high", 0.6,
                        "%s() copies sizeof(%s) bytes into %s, which was allocated with "
                        "size %s on line %d. If that is smaller, the copy overflows the heap."
                        % (match.group(0).split("(")[0].strip(), source, target, size, line),
                        "Copy at most the allocated size of the destination, or allocate "
                        "sizeof(%s) bytes for it." % source)

    def fixed_copies(self, number: int, code: str) -> None:
        """memcpy(buf, src, len) into a fixed-size local array, where len is chosen by the
        caller or read from outside and never compared with anything first."""
        for match in BOUNDED_COPY.finditer(code):
            target, length = match.group(2), match.group(3)
            if target not in self.arrays or not self.unchecked(length):
                continue
            outside = self.is_outside(length)
            if outside or _base(length) in self.params:
                self.report(number, "C-MEM-COPY-LENGTH", "CWE-120",
                            "Copy into a fixed-size buffer with an unchecked length", "high",
                            0.55, "%s() copies %s bytes into %s[%s], and %s %s is never "
                            "checked against the size of the buffer."
                            % (match.group(1), length, target, self.arrays[target],
                               "the value" if outside else "the parameter", length),
                            "Check that the length is not larger than sizeof(%s) before "
                            "copying." % target, outside)

    def divisions(self, number: int, code: str) -> None:
        for match in DIVISION.finditer(code):
            divisor = match.group(1)
            if self.is_outside(divisor) and divisor not in self.checked \
                    and _base(divisor) not in self.checked:
                self.report(number, "C-MEM-DIV-ZERO", "CWE-369",
                            "Division by a value read from outside", "medium", 0.6,
                            "%s comes from outside the program and is not checked before "
                            "the division: a zero crashes the program." % divisor,
                            "Check that the divisor is not zero before dividing.", True)

    def indexes(self, number: int, code: str) -> None:
        for match in INDEX.finditer(code):
            array, index, write = match.group(1), match.group(2), match.group(3)
            if array in KEYWORDS or not self.is_outside(index) or index in self.checked:
                continue
            if write:
                self.report(number, "C-MEM-OOB-WRITE", "CWE-787",
                            "Out-of-bounds write with an index read from outside", "high",
                            0.6, "%s[%s] is written with an index that comes from outside "
                            "the program and is not checked against the size of %s."
                            % (array, index, array),
                            "Check 0 <= index < size of the buffer before the write.", True)
            else:
                self.report(number, "C-MEM-OOB-READ", "CWE-125",
                            "Out-of-bounds read with an index read from outside", "medium",
                            0.55, "%s[%s] is read with an index that comes from outside the "
                            "program and is not checked against the size of %s."
                            % (array, index, array),
                            "Check 0 <= index < size of the buffer before the read.", True)

    def allocations(self, number: int, code: str) -> None:
        for match in ALLOC_CALL.finditer(code):
            size = match.group(2)
            names = re.findall(EXPR, size)
            computed = [n for n in names if n in self.computed]
            if computed or (ARITHMETIC.search(size) and any(self.is_outside(n) for n in names)):
                where = (" (computed on line %d)" % self.computed[computed[0]]) if computed else ""
                self.report(number, "C-MEM-ALLOC-OVERFLOW", "CWE-190",
                            "Allocation size computed from outside data can overflow", "high",
                            0.6, "The size passed to %s()%s is computed with + - or * from "
                            "values read from outside the program. It can wrap around to a "
                            "small or negative number, and the next copy overflows the "
                            "buffer." % (match.group(1), where),
                            "Check the operands against a maximum before the arithmetic, "
                            "or use an overflow-checked helper (calloc, __builtin_mul_overflow).",
                            True)
            elif MULTIPLY.search(size) and any(_base(n) in self.params and self.unchecked(n)
                                               for n in names):
                self.report(number, "C-MEM-ALLOC-PARAM", "CWE-190",
                            "Allocation size multiplied from an unchecked parameter", "medium",
                            0.45, "The size passed to %s() multiplies a parameter that this "
                            "function never checks (count * size). A large count from the "
                            "caller wraps the size around to a small buffer." % match.group(1),
                            "Check the parameter against a maximum, or use calloc(count, "
                            "size), which detects the overflow.")
            elif any(self.is_outside(n) and n not in self.checked for n in names):
                self.report(number, "C-MEM-ALLOC-SIZE", "CWE-789",
                            "Allocation size taken from outside without a limit", "medium",
                            0.5, "The size passed to %s() comes from outside the program and "
                            "is not checked: a huge value exhausts memory, a negative one "
                            "wraps around." % match.group(1),
                            "Check the size against a sensible maximum before allocating.",
                            True)

    def assignments(self, number: int, code: str) -> None:
        for match in ASSIGN.finditer(code):
            target, element, rhs = match.group(1), match.group(2), match.group(4)
            if target in KEYWORDS or element:      # buf[i] = 0 writes an element, not buf
                continue
            names = {_base(n) for n in re.findall(EXPR, rhs)}
            if NULLISH.match(rhs) and target in self.allocated:
                self.report(number, "C-MEM-LEAK", "CWE-401", "Memory leak", "low", 0.55,
                            "%s still points to memory allocated on line %d and is "
                            "overwritten here without free(): the memory can no longer be "
                            "released." % (target, self.allocated[target]),
                            "Call free() before overwriting the pointer.")
                del self.allocated[target]
            if ALLOCATES.search(rhs):
                self.allocated[target] = number
                size = ALLOC_CALL.search(rhs)
                if size:
                    self.alloc_size[target] = (number, size.group(2).strip())
                self.outside.discard(target)
                continue
            rhs_name = rhs.strip()
            if rhs_name in self.allocated:            # the pointer is kept elsewhere
                del self.allocated[rhs_name]
            if names & self.outside or OUTSIDE_VALUE.search(rhs):
                self.outside.add(target)
                if ARITHMETIC.search(rhs):
                    self.computed[target] = number
                self.checked.discard(target)
            elif not match.group(3):                 # a plain new value, not "+="
                self.outside.discard(target)
                self.computed.pop(target, None)

    def escapes(self, code: str) -> None:
        if not self.allocated:
            return
        for match in CALL.finditer(code):
            if match.group(1) in NON_ESCAPING:
                continue
            for pointer in list(self.allocated):
                if re.search(r"\b" + pointer + r"\b", match.group(2)):
                    del self.allocated[pointer]      # handed to another function
        if re.search(r"\breturn\b", code):
            for pointer in list(self.allocated):
                if re.search(r"\b" + pointer + r"\b", code):
                    del self.allocated[pointer]


def scan_file(sf: SourceFile) -> List[Finding]:
    if sf.language not in LANGUAGES:
        return []
    out: List[Finding] = []
    for name, params, body in _functions(_code_lines(sf)):
        out.extend(_Function(sf, name, params, body).run())
    return out


def scan(files: Iterable[SourceFile]) -> List[Finding]:
    out: List[Finding] = []
    for sf in files:
        out.extend(scan_file(sf))
    return out
