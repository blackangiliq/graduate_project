"""A small XML element tree with line numbers, for manifests and XML resources.

XmlNode keeps the line of each element's start tag and of each of its attributes, so a
finding can point at the exact attribute. The tree comes from two places:
- parse_xml_text() reads XML source (android/app/src/main/AndroidManifest.xml, a network
  security config, ...) with line numbers that match str.splitlines() of the same text;
- the decoders of an app package (binary XML, protobuf XML) build the tree and then call
  render_xml(), which writes it as text with one attribute per line and records the lines
  of that text in the tree.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple
from xml.parsers import expat

XML_HEADER = '<?xml version="1.0" encoding="utf-8"?>'
INDENT = "    "

# caps against hostile documents
MAX_DEPTH = 200
MAX_NODES = 200_000
MAX_INDENT_DEPTH = 32       # deeper elements are not indented further, so lines stay short

# the start of a start tag and one attribute inside it (bytes of the UTF-8 text)
_TAG_START = re.compile(rb"<[^\s/>]*")
_ATTRIBUTE = re.compile(rb"""\s+([^\s=/>]+)\s*=\s*(?:"[^"]*"|'[^']*')""")

# characters a rendered line must not contain raw: markup, line breaks (as str.splitlines()
# counts them) and characters that XML 1.0 does not allow (those become U+FFFD)
_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "\n": "&#10;",
            "\r": "&#13;", "\x85": "&#133;", "\u2028": "&#8232;", "\u2029": "&#8233;"}
_TO_ESCAPE = re.compile('[&<>"\n\r\x85\u2028\u2029\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff'
                        '\ufffe\uffff]')
_UNSAFE_NAME_CHAR = re.compile(r"[^\w.:-]")


@dataclass
class XmlNode:
    """An XML element with its attributes, child elements and text."""

    tag: str                                              # as written: "manifest", "base-config"
    attrs: Dict[str, str] = field(default_factory=dict)   # "android:exported" -> "true"
    children: List["XmlNode"] = field(default_factory=list)
    line: int = 0                                         # 1-based line of the start tag
    attr_lines: Dict[str, int] = field(default_factory=dict)    # attribute -> 1-based line
    text: str = ""                                        # character data inside, stripped

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """The value of an attribute, or `default` when the element does not have it."""
        return self.attrs.get(name, default)

    def iter(self, tag: Optional[str] = None) -> Iterator["XmlNode"]:
        """This element and every element below it, depth first in document order; only the
        elements named `tag` when it is given."""
        stack = [self]
        while stack:
            node = stack.pop()
            if tag is None or node.tag == tag:
                yield node
            stack.extend(reversed(node.children))

    def find(self, tag: str) -> Optional["XmlNode"]:
        """The first direct child named `tag`, or None."""
        return next((child for child in self.children if child.tag == tag), None)

    def findall(self, tag: str) -> List["XmlNode"]:
        """Every direct child named `tag`."""
        return [child for child in self.children if child.tag == tag]

    def line_of(self, attr: str) -> int:
        """The line of an attribute; the line of the start tag when the attribute is absent."""
        return self.attr_lines.get(attr) or self.line


class _Stop(Exception):
    """Ends parsing early: a cap was reached or the document declares entities."""


def parse_xml_text(text: str) -> Tuple[Optional[XmlNode], str]:
    """Parse XML source into a tree: (root, "") or (None, error message).

    Namespace processing is off, so names keep their prefixes as written ("android:exported")
    and xmlns declarations stay in `attrs`. Lines count the way str.splitlines() does, like
    the lines of a scanned file. Entity declarations and external entities are refused (no
    entity expansion, nothing is fetched); nesting deeper than MAX_DEPTH or more than
    MAX_NODES elements also give an error.
    """
    data = text.encode("utf-8", "replace")
    starts = _line_starts(text)
    parser = expat.ParserCreate(encoding="utf-8")
    parser.ordered_attributes = True
    parser.buffer_text = True
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    roots: List[XmlNode] = []
    stack: List[XmlNode] = []
    texts: List[List[str]] = []
    count = 0

    def start(name: str, attributes: List[str]) -> None:
        nonlocal count
        count += 1
        if count > MAX_NODES:
            raise _Stop(f"more than {MAX_NODES} elements")
        if len(stack) >= MAX_DEPTH:
            raise _Stop(f"elements nested deeper than {MAX_DEPTH} levels")
        offset = parser.CurrentByteIndex
        node = XmlNode(name, line=bisect.bisect_right(starts, offset))
        positions = _attribute_offsets(data, offset)
        for i in range(0, len(attributes) - 1, 2):
            key = attributes[i]
            node.attrs[key] = attributes[i + 1]
            node.attr_lines[key] = (bisect.bisect_right(starts, positions[key])
                                    if key in positions else node.line)
        (stack[-1].children if stack else roots).append(node)
        stack.append(node)
        texts.append([])

    def end(name: str) -> None:
        stack.pop().text = "".join(texts.pop()).strip()

    def characters(chunk: str) -> None:
        if texts:
            texts[-1].append(chunk)

    def refuse(*args: object) -> None:
        raise _Stop("entity declarations and external entities are not allowed")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    parser.EntityDeclHandler = refuse
    parser.UnparsedEntityDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse
    try:
        parser.Parse(data, True)
    except _Stop as exc:
        return None, str(exc)
    except expat.ExpatError as exc:
        return None, f"line {exc.lineno}: {expat.ErrorString(exc.code)}"
    if not roots:
        return None, "no root element"
    return roots[0], ""


def _line_starts(text: str) -> List[int]:
    """UTF-8 byte offset of the start of every line, lines as str.splitlines() counts them."""
    starts = [0]
    for line in text.splitlines(keepends=True):
        starts.append(starts[-1] + len(line.encode("utf-8", "replace")))
    return starts


def _attribute_offsets(data: bytes, start: int) -> Dict[str, int]:
    """Byte offset of every attribute name in the start tag that begins at `start`."""
    match = _TAG_START.match(data, start)
    if not match:
        return {}
    offsets: Dict[str, int] = {}
    pos = match.end()
    while True:
        match = _ATTRIBUTE.match(data, pos)
        if not match:
            return offsets
        offsets.setdefault(match.group(1).decode("utf-8", "replace"), match.start(1))
        pos = match.end()


def render_xml(root: XmlNode, namespaces: Optional[Dict[str, str]] = None) -> str:
    """Write a tree as XML text and set `line` and `attr_lines` of every node to that text.

    Layout: the XML declaration on line 1, then every start tag on its own line with one
    attribute per line, children indented by 4 spaces, the namespace declarations
    (prefix -> URI) on the root element. Values are escaped, and line breaks and control
    characters never appear raw, so every attribute stays on one line. Names that are not
    valid XML names are made safe in the text only; the tree keeps them as they are.
    """
    lines = [XML_HEADER]
    stack: List[Tuple[XmlNode, int, bool]] = [(root, 0, False)]
    while stack:
        node, depth, closing = stack.pop()
        pad = INDENT * min(depth, MAX_INDENT_DEPTH)
        tag = _safe_name(node.tag)
        if closing:
            lines.append(f"{pad}</{tag}>")
            continue
        node.line = len(lines) + 1
        node.attr_lines = {}
        lines.append(f"{pad}<{tag}")
        inner = pad + INDENT
        if depth == 0:
            for prefix, uri in (namespaces or {}).items():
                name = f"xmlns:{_safe_name(prefix)}" if prefix else "xmlns"
                lines.append(f'{inner}{name}="{_escape(uri)}"')
        for name, value in node.attrs.items():
            node.attr_lines[name] = len(lines) + 1
            lines.append(f'{inner}{_safe_name(name)}="{_escape(value)}"')
        text = _escape(node.text)
        if not node.children:
            lines[-1] += f">{text}</{tag}>" if text else " />"
            continue
        lines[-1] += ">"
        if text:
            lines.append(inner + text)
        stack.append((node, depth, True))
        stack.extend((child, depth + 1, False) for child in reversed(node.children))
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return _TO_ESCAPE.sub(lambda m: _ESCAPES.get(m.group(), "\ufffd"), value)


def _safe_name(name: str) -> str:
    """An element or attribute name that is safe to write: invalid characters become "_"."""
    name = _UNSAFE_NAME_CHAR.sub("_", name)
    if not name or not (name[0].isalpha() or name[0] in "_:"):
        name = "_" + name
    return name
