"""Launch the PySide6 + Qt WebEngine VulnWatch desktop application."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_DIRECTORY = PROJECT_ROOT / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from vulnwatch.qt_desktop import launch_qt_desktop


if __name__ == "__main__":
    raise SystemExit(launch_qt_desktop())
