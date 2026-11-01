"""Headless checks for the Qt launcher's local server socket setup."""

import unittest
from unittest.mock import patch

from vulnwatch.qt_desktop import LocalApiServer


class QtDesktopTests(unittest.TestCase):
    def test_server_requests_ephemeral_loopback_socket(self) -> None:
        class FakeSocket:
            def __init__(self, *_args):
                self.closed = False

            def setsockopt(self, *_args): pass
            def bind(self, address): self.address = address
            def listen(self, _backlog): pass
            def set_inheritable(self, _value): pass
            def getsockname(self): return (self.address[0], 43210)
            def close(self): self.closed = True

        fake_socket = FakeSocket()
        with patch("vulnwatch.qt_desktop.socket.socket", return_value=fake_socket) as make_socket:
            server = LocalApiServer()
        make_socket.assert_called_once()
        self.assertEqual(fake_socket.address, ("127.0.0.1", 0))
        self.assertEqual(server.port, 43210)
        self.assertEqual(server.url, "http://127.0.0.1:43210")
        server.stop()
        self.assertTrue(fake_socket.closed)


if __name__ == "__main__":
    unittest.main()
