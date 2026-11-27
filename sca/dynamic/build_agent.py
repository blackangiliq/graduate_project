"""Rebuild the pinned Frida 17 Java bridge agent after `npm ci` in agent/."""
from pathlib import Path


def main() -> None:
    import frida
    root = Path(__file__).parent / "agent"
    bundle = frida.Compiler().build("observer.js", project_root=str(root))
    (root / "observer.bundle.js").write_text(bundle, encoding="utf-8", newline="\n")
    print("Built observer.bundle.js with Frida", frida.__version__)


if __name__ == "__main__":
    main()
