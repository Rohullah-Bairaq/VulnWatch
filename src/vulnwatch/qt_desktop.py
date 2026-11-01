"""PySide6 desktop shell for the existing local VulnWatch dashboard."""

from __future__ import annotations

import socket
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen

import uvicorn
from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QVBoxLayout, QWidget
from PySide6.QtWebEngineWidgets import QWebEngineView

from vulnwatch.main import app


class LocalApiServer:
    """Run the existing FastAPI app on an ephemeral loopback port."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(128)
        self.socket.set_inheritable(True)
        self.port = self.socket.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.socket]}, name="vulnwatch-api", daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self.thread.start()

    def is_ready(self) -> bool:
        try:
            with urlopen(f"{self.url}/api/health", timeout=0.4) as response:
                return response.status == 200
        except (OSError, URLError):
            return False

    def stop(self) -> None:
        if self.thread.is_alive():
            self.server.should_exit = True
            self.thread.join(timeout=5)
        if self.thread.is_alive():
            self.server.force_exit = True
            self.thread.join(timeout=1)
        if not self.thread.is_alive():
            self.socket.close()


class VulnWatchWindow(QMainWindow):
    """Window hosting the existing responsive dashboard in Qt WebEngine."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VulnWatch | Security Operations")
        self.resize(1440, 940)
        self.setMinimumSize(900, 650)
        self.setStyleSheet("QMainWindow { background: #101722; } QLabel { color: #dce5f0; font: 14px 'DejaVu Sans'; }")

        self.server = LocalApiServer()
        self.started_at = time.monotonic()
        self.browser = QWebEngineView(self)
        self.loading_label = QLabel("Starting VulnWatch local workspace…")
        self.loading_label.setStyleSheet("color:#c8d5e5; font-size:15px; padding:24px;")
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.loading_label)
        layout.addWidget(self.browser)
        self.browser.hide()
        self.setCentralWidget(container)

        self.server.start()
        self.ready_timer = QTimer(self)
        self.ready_timer.timeout.connect(self._check_server)
        self.ready_timer.start(100)

    def _check_server(self) -> None:
        if self.server.is_ready():
            self.ready_timer.stop()
            self.loading_label.hide()
            self.browser.show()
            self.browser.setUrl(QUrl(self.server.url))
        elif time.monotonic() - self.started_at > 15:
            self.ready_timer.stop()
            self.loading_label.setText("VulnWatch could not start its local API server. Close this window and check the terminal for details.")
            self.server.stop()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.ready_timer.stop()
        self.browser.stop()
        self.server.stop()
        event.accept()


def launch_qt_desktop() -> int:
    """Start the Qt application and return its process exit code."""
    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName("VulnWatch")
    window = VulnWatchWindow()
    window.show()
    return application.exec()
