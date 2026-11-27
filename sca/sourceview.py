"""Navigate large logical lines without cutting a selected literal value."""
from dataclasses import dataclass


LINE_WINDOW = 8192


@dataclass(frozen=True)
class LineWindow:
    text: str
    first: int
    last: int
    total: int

    @property
    def complete(self) -> bool:
        return self.first == 1 and self.last == self.total


def line_window(text: str, *, column: int = 0, end_column: int = 0,
                focus: str = "", limit: int = LINE_WINDOW) -> LineWindow:
    """Return original text plus 1-based inclusive display bounds.

    A focus literal or an exact match span is always retained in full, even when it
    exceeds the normal viewport. Columns refer to the original logical source line.
    """
    size = len(text)
    if size <= limit:
        return LineWindow(text, 1, size, size)
    start_match = max(0, min(column - 1, size - 1)) if column > 0 else 0
    end_match = max(start_match + 1, min(end_column - 1, size))
    if focus:
        found = text.find(focus, start_match) if column > 0 else text.find(focus)
        if found < 0:
            found = text.find(focus)
        if found >= 0:
            start_match, end_match = found, found + len(focus)
    first = max(0, start_match - min(256, limit // 4))
    last = min(size, max(first + limit, end_match + 256))
    return LineWindow(text[first:last], first + 1, last, size)


def marked_window(text: str, **kwargs) -> str:
    view = line_window(text, **kwargs)
    if view.complete:
        return view.text
    return f"[columns {view.first}-{view.last} of {view.total}] " + view.text
