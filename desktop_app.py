"""Launch the VulnWatch Tkinter desktop application."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_DIRECTORY = PROJECT_ROOT / "src"
if str(SOURCE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIRECTORY))

from vulnwatch.desktop import launch_desktop


if __name__ == "__main__":
    launch_desktop()
