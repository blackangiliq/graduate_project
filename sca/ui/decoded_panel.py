"""Browse scan locations and open matching source text on the local dashboard."""
from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
from pathlib import PurePosixPath
from typing import Callable, Mapping, Sequence

import streamlit as st

from ..cwe import canonical
from ..decoded import CredentialEvidence, DecodedFile, OriginalSource, validate_derivation
from ..engines.rules_engine import get_rule
from ..engines.secrets import KNOWN_FORMATS
from ..flutter.context import (
    ORIGIN_DECODED,
    ORIGIN_DECOMPILED,
    ORIGIN_DISK,
    ORIGIN_PLACEHOLDER,
    ORIGIN_RECOVERED,
    ORIGIN_STRINGS,
    ORIGIN_SUMMARY,
)
from ..flutter.inventory import FILE_LEVEL_RULES, KEY_CWES
from ..walker import strip_bidi
from ..sourceview import LINE_WINDOW, line_window
from .app_panel import plain

PAGE_LINES = 50
MAX_LINE_CHARS = 1200
CONTEXT_LINES = 8
PENDING_JUMP = "decoded_files_pending_jump"
PENDING_COLUMN = "decoded_files_pending_column"
PENDING_FOCUS = "decoded_files_pending_focus"
FORMAT_NAMES = {rule_id: title for rule_id, title, *_ in KNOWN_FORMATS}
ORIGINS = {
    ORIGIN_DISK: "Source file",
    ORIGIN_DECODED: "Decoded from package",
    ORIGIN_RECOVERED: "Recovered Dart source",
    ORIGIN_DECOMPILED: "Decompiled by JADX",
    ORIGIN_STRINGS: "Strings from binary",
    ORIGIN_SUMMARY: "Analysis summary",
    ORIGIN_PLACEHOLDER: "Binary file placeholder",
    "decoded_literal": "Base64-decoded literal",
}


@dataclass(frozen=True)
class FileInfo:
    language: str
    origin: str
    line_count: int
    source_line_count: int = 0
    member: str = ""
    original: OriginalSource | None = None
    derivation: dict = field(default_factory=dict)


def jump_to(path: str, line: int) -> None:
    """Choose a virtual file and line before the panel's widgets are rendered."""
    st.session_state[PENDING_JUMP] = (path, line)
    st.session_state[PENDING_COLUMN] = 1
    st.session_state.pop(PENDING_FOCUS, None)


def _open_location(callback, path: str, line: int, column: int, end_column: int, focus: str) -> None:
    callback(path, line)
    st.session_state[PENDING_COLUMN] = max(1, column)
    st.session_state[PENDING_FOCUS] = (max(1, column), end_column, focus)


def _render_derivation(value, t, *, key: str, on_open=None, available_files=None) -> None:
    if not value:
        return
    try:
        detail = validate_derivation(value)
    except ValueError:
        st.warning(t("Decoded-literal provenance is unavailable or invalid."))
        return
    st.info(t("Base64-decoded text. These lines are derived evidence, not original source lines."))
    st.text(t("Encoded source: %s · line %d · columns %d–%d · decoding depth %d") % (
        strip_bidi(detail["source_file"]), detail["source_line"], detail["source_column"],
        detail["source_end_column"] - 1, detail["depth"]))
    if available_files is not None and detail["source_file"] not in available_files:
        st.caption(t("The encoded source is outside the retained preview."))
    elif on_open is not None:
        st.button(t("Open encoded source"), key=key + "_encoded_source",
                  on_click=_open_location,
                  args=(on_open, detail["source_file"], detail["source_line"],
                        detail["source_column"], detail["source_end_column"], ""))


def _choose_line(key: str, line: int) -> None:
    st.session_state[key] = line


def _select_file(file_key: str, line_key: str, opened_key: str) -> None:
    st.session_state[line_key] = 1
    st.session_state[opened_key] = st.session_state[file_key]


def api_locations(item: Mapping, *, call: bool) -> list[tuple[str, int]]:
    """Keep only recorded file and line pairs, in their original order."""
    records = [item] if call else item.get("locations", ())
    if not isinstance(records, (list, tuple)):
        return []
    if call and item.get("target_line") is not None:
        records.append({"file": item.get("file"), "line": item["target_line"]})
    places = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        path, line = record.get("file"), record.get("line")
        if isinstance(path, str) and path and type(line) is int and line > 0 and (path, line) not in places:
            places.append((path, line))
    return places


def credential_kind(rule_id: str, cwe: str) -> str:
    """Describe the selected rule using scanner metadata, without reading a credential."""
    if rule_id in FILE_LEVEL_RULES or canonical(cwe) not in KEY_CWES:
        return ""
    if rule_id in FORMAT_NAMES:
        return FORMAT_NAMES[rule_id]
    if rule_id == "SECRET-HARDCODED-001":
        return "Hard-coded credential"
    rule = get_rule(rule_id)
    return rule.title if rule else "Credential"


def render_location(path: str, line: int, file: DecodedFile,
                    t: Callable[[str], str], *, on_open: Callable[[str, int], None],
                    key: str, credential: str = "", rule: str = "",
                    evidence: CredentialEvidence | None = None, member: str = "",
                    show_original: bool = False, focus: str = "", column: int = 0,
                    end_column: int = 0) -> None:
    """Show the selected location and use the verified local file when available."""
    with st.container(border=True):
        st.subheader(t("File preview"))
        # Isolate the file address so an Arabic interface keeps the line number by the path.
        address = escape(strip_bidi(f"{path}:{line}"))
        st.html(f'<div><bdi dir="ltr"><code>{address}</code></bdi></div>')
        if member:
            st.caption(t("APK containing this file: %s") % plain(strip_bidi(member)))
        st.caption(t(ORIGINS.get(file.origin, ORIGINS[ORIGIN_DECODED])))
        if file.origin == ORIGIN_STRINGS:
            st.caption(t("Line numbers index the extracted strings. The original source line "
                         "and byte offset are unavailable in this view."))
        elif file.origin == ORIGIN_DECOMPILED:
            st.caption(t("Line numbers refer to the code reconstructed by JADX."))
        _render_derivation(file.derivation, t, key=key, on_open=on_open)
        original = getattr(file, "original", None) if show_original else None
        source_lines = original.read_lines() if original is not None else None
        if original is not None and source_lines is None:
            st.warning(t("The original file changed or is unavailable. Rescan to view the current source."))
        lines = source_lines if source_lines is not None else file.lines
        if not 1 <= line <= len(lines):
            st.info(t("This location is outside the available preview."))
            return
        if credential:
            st.markdown("**%s**" % (t("Credential match · %s") % plain(strip_bidi(t(credential)))))
        selected_view = line_window(lines[line - 1], focus=focus, column=column,
                                    end_column=end_column)
        jump_column = column or (lines[line - 1].find(focus) + 1 if focus else 1)
        if not selected_view.complete:
            st.caption(t("Showing columns %d–%d of %d. The selected value is complete; "
                         "open the file to navigate the rest of this line.") %
                       (selected_view.first, selected_view.last, selected_view.total))
        first, last = max(1, line - CONTEXT_LINES), min(len(lines), line + CONTEXT_LINES)
        width = len(str(last))
        excerpt = []
        for number in range(first, last + 1):
            text = strip_bidi(lines[number - 1])
            active = number == line
            if active:
                text = strip_bidi(selected_view.text)
            if len(text) > MAX_LINE_CHARS and not active:
                text = text[:MAX_LINE_CHARS] + "…"
            content = escape(f"{'›' if active else ' '} {number:>{width}}  {text}")
            if active:
                content = ('<span aria-current="location" style="display:inline-block;'
                           'min-width:100%;background:rgba(236,158,32,.20);'
                           'border-inline-start:3px solid #cf8619;font-weight:600">'
                           f'{content}</span>')
            excerpt.append(content)
        st.html('<pre dir="ltr" style="text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;'
                          'overflow:auto;padding:.65rem;'
                          'border-radius:.35rem;line-height:1.55;background:rgba(130,130,130,.09)">'
                          + "\n".join(excerpt) + "</pre>")
        if source_lines is not None or line <= len(file.lines):
            st.button(t("Browse source files") if file.origin == ORIGIN_DISK else t("Browse decoded files"),
                      key=key, on_click=_open_location,
                      args=(on_open, path, line, jump_column, end_column, focus))


def render(files: Mapping[str, FileInfo],
           read_lines: Callable[[str, int, int], Sequence[str]],
           t: Callable[[str], str], *, scan_key: str, wide: dict, source: bool = False,
           tab_open: bool = False) -> None:
    """Browse a selected original file or scan-time snapshot using 1-based coordinates."""
    state = st.session_state
    address = state.pop(PENDING_JUMP, None)
    requested_column = state.pop(PENDING_COLUMN, 1)
    requested_focus = state.pop(PENDING_FOCUS, None)
    if not files:
        st.info(t("No decoded files are available for this scan."))
        return

    prefix = f"decoded_{scan_key}"
    filter_key, file_key, line_key = (f"{prefix}_{name}" for name in ("filter", "file", "line"))
    opened_key = f"{prefix}_opened"
    if address is not None:
        path, line = address
        if path in files and 1 <= line <= (files[path].source_line_count if files[path].original
                                           else files[path].line_count):
            state[filter_key] = ""
            state[file_key] = path
            state[opened_key] = path
            state[line_key] = line
        else:
            st.info(t("This location is outside the available preview."))

    query = st.text_input(t("Filter source files") if source else t("Filter decoded files"),
                          key=filter_key).strip().casefold()
    matching = sorted(path for path in files if query in path.casefold())
    if not matching:
        st.info(t("No source files match this filter.") if source else
                t("No decoded files match this filter."))
        return
    if state.get(file_key) not in matching:
        state[file_key] = matching[0]
        state[line_key] = 1
    path = st.selectbox(t("Source file") if source else t("Decoded file"), matching,
                        key=file_key, format_func=strip_bidi,
                        on_change=_select_file, args=(file_key, line_key, opened_key))
    info = files[path]
    source_lines = None
    if info.original and (tab_open or state.get(opened_key) == path):
        source_lines = info.original.read_lines()
        if source_lines is None:
            st.warning(t("The original file changed or is unavailable. Rescan to view the current source."))
    line_count = info.line_count if source_lines is None else len(source_lines)
    if info.member:
        st.caption(t("APK containing this file: %s") % plain(strip_bidi(info.member)))
    origin = ORIGINS.get(info.origin, ORIGINS[ORIGIN_DECODED])
    st.caption(t("%s · %s · %d lines") % (
        plain(strip_bidi(info.language)), t(origin), line_count))
    _render_derivation(info.derivation, t, key=prefix + "_" + path,
                       on_open=jump_to, available_files=files)
    if not line_count:
        st.info(t("This location is outside the available preview.") if info.source_line_count else
                t("This decoded file is empty."))
        return

    if not 1 <= state.get(line_key, 1) <= line_count:
        state[line_key] = 1
    selected = st.number_input(t("Jump to line"), min_value=1, max_value=line_count,
                               step=1, key=line_key)
    selected_lines = source_lines[selected - 1:selected] if source_lines is not None else read_lines(path, selected, selected)
    selected_text = selected_lines[0] if selected_lines else ""
    column = 1
    focus_key = f"{prefix}_focus_{path}_{selected}"
    if address is not None:
        state[focus_key] = requested_focus
    if len(selected_text) > LINE_WINDOW:
        column_key = f"{prefix}_column_{path}_{selected}"
        if address is not None:
            state[column_key] = min(max(1, requested_column), len(selected_text))
        column = st.number_input(t("Jump to column"), min_value=1, max_value=len(selected_text),
                                 step=1, key=column_key)
        st.caption(t("This is a long source line. Navigate by column or download the complete file."))
    complete_lines = source_lines if source_lines is not None else read_lines(path, 1, info.line_count)
    st.download_button(t("Download this file"), "\n".join(complete_lines),
                       file_name=PurePosixPath(path).name, mime="text/plain",
                       key=f"{prefix}_download_{path}")
    first = (selected - 1) // PAGE_LINES * PAGE_LINES + 1
    last = min(first + PAGE_LINES - 1, line_count)
    previous, following, page = st.columns([1, 1, 2])
    previous.button(t("Previous page"), key=f"{prefix}_prev", disabled=first == 1,
                    on_click=_choose_line, args=(line_key, max(1, first - PAGE_LINES)), **wide)
    following.button(t("Next page"), key=f"{prefix}_next", disabled=last == line_count,
                     on_click=_choose_line, args=(line_key, min(last + 1, line_count)), **wide)
    page.caption(t("Showing lines %d–%d of %d") % (first, last, line_count))

    shortened = False
    gutter_width = len(str(last))
    preview = []
    lines = source_lines[first - 1:last] if source_lines is not None else read_lines(path, first, last)
    for number, line in enumerate(lines[:PAGE_LINES], start=first):
        if number == selected and len(line) > LINE_WINDOW:
            selected_focus = state.get(focus_key)
            view = line_window(line, column=column,
                               end_column=selected_focus[1] if selected_focus and selected_focus[0] == column else 0,
                               focus=selected_focus[2] if selected_focus and selected_focus[0] == column else "")
            st.caption(t("Columns %d–%d of %d") % (view.first, view.last, view.total))
            line = view.text
        if len(line) > MAX_LINE_CHARS and number != selected:
            shortened = True
            line = line[:MAX_LINE_CHARS] + "…"
        marker = ">" if number == selected else " "
        preview.append(f"{marker} {number:>{gutter_width}}  {strip_bidi(line)}")
    st.code("\n".join(preview), language="text")
    if shortened:
        st.caption(t("The preview was shortened to fit."))
