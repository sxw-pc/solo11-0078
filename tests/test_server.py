from __future__ import annotations

import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from charorder.artifacts import execute
from charorder.config import load_config
from charorder.errors import VerificationError
from charorder.server import make_server

from tests.support import DEMO_CONFIG


class ReadOnlyServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        config = load_config(DEMO_CONFIG)
        cls.result, cls.manifest, cls.output = execute(config, cls.root / "run")
        cls.server = make_server(cls.output, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def _request(self, method: str, path: str):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path)
            return connection.getresponse()
        finally:
            connection.close()

    def test_root_serves_self_contained_report(self) -> None:
        response = self._request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.getheader("Content-Type"))
        self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))
        body = response.read().decode("utf-8")
        self.assertIn("字序迁核台", body)
        self.assertNotIn("http://", body)
        self.assertNotIn("https://", body)

    def test_json_artifact_is_served(self) -> None:
        response = self._request("GET", "/manifest.json")
        self.assertEqual(response.status, 200)
        self.assertIn("application/json", response.getheader("Content-Type"))
        body = response.read()
        self.assertIn(b'"run_id"', body)

    def test_head_has_headers_without_body(self) -> None:
        response = self._request("HEAD", "/report.html")
        self.assertEqual(response.status, 200)
        self.assertGreater(int(response.getheader("Content-Length")), 0)
        self.assertEqual(response.read(), b"")

    def test_write_methods_are_rejected(self) -> None:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            response = self._request(method, "/manifest.json")
            self.assertEqual(response.status, 405)
            self.assertEqual(response.getheader("Allow"), "GET, HEAD")
            response.read()

    def test_unknown_and_traversal_paths_are_404(self) -> None:
        for path in ("/README.md", "/../manifest.json", "/%2e%2e/secret.txt"):
            response = self._request("GET", path)
            self.assertEqual(response.status, 404)
            response.read()

    def test_non_loopback_bind_is_rejected(self) -> None:
        with self.assertRaisesRegex(VerificationError, "回环"):
            make_server(self.output, "0.0.0.0", 0)


if __name__ == "__main__":
    unittest.main()
