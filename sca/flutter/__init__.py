"""Flutter and Android app analysis: Flutter source projects and app packages (.apk, .aab).

Everything here is static: an app is decoded and read, never installed or run.

    load_app(path)                   an app package -> MobileContext with virtual files and facts
    load_project(root, files)        a Flutter or Android project folder -> MobileContext or None
    analyze(ctx, by_rel)             the structural checks (engine "flutter") -> findings, note
    refine(findings, by_rel, ctx)    adjust findings of other engines that need app context

The decoders of the formats inside an app package are in the other modules of this package
(zipread, axml, aabproto, arsc, dex, signing, kernel, snapshot, pubspec).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Tuple

from .apk import APP_SUFFIXES, AppError, is_app_package, load_app
from .context import MobileContext
from .project import load_project

if TYPE_CHECKING:  # imported for type hints only
    from ..models import Finding
    from ..walker import SourceFile

__all__ = ["APP_SUFFIXES", "AppError", "MobileContext", "analyze", "is_app_package",
           "load_app", "load_project", "refine"]


def analyze(ctx: MobileContext, by_rel: Dict[str, "SourceFile"]) -> Tuple[List["Finding"], str]:
    """The structural checks of sca/flutter/checks.py: (findings, engine note)."""
    from .checks import analyze as run_checks
    return run_checks(ctx, by_rel)


def refine(findings: List["Finding"], by_rel: Dict[str, "SourceFile"], ctx: MobileContext) -> int:
    """Adjust findings of the other engines with what the app context tells (see
    sca/flutter/checks.py); returns how many were changed."""
    from .checks import refine as run_refine
    return run_refine(findings, by_rel, ctx)
