"""A tiny read-only HTTP server for reviewing one generated run."""

from __future__ import annotations

import http.server
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .errors import VerificationError
from .verify import verify_run

_ALLOWED_FILES = {
    "report.html": "text/html; charset=utf-8",
    "report.md": "text/markdown; charset=utf-8",
    "plan.json": "application/json; charset=utf-8",
    "plan.md": "text/markdown; charset=utf-8",
    "findings.json": "application/json; charset=utf-8",
    "collisions.json": "application/json; charset=utf-8",
    "certificates.json": "application/json; charset=utf-8",
    "keys.jsonl": "application/x-ndjson; charset=utf-8",
    "ledger.sqlite": "application/vnd.sqlite3",
    "manifest.json": "application/json; charset=utf-8",
}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class _ReadOnlyHandler(http.server.BaseHTTPRequestHandler):
    server_version = "charorder-readonly"
    sys_version = ""
    run_dir: Path  # injected by make_server via subclass

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._serve(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        self._serve(send_body=False)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def _serve(self, *, send_body: bool) -> None:
        path = unquote(urlsplit(self.path).path)
        if path in {"/", ""}:
            path = "/report.html"
        name = path.lstrip("/")
        if name not in _ALLOWED_FILES:
            self._plain(404, "未找到。只读服务器仅公开本次运行产物。", send_body=send_body)
            return
        file_path = self.run_dir / name
        if not file_path.is_file():
            self._plain(404, "该产物不存在。", send_body=send_body)
            return
        try:
            data = file_path.read_bytes()
        except OSError:
            self._plain(500, "无法读取产物。", send_body=send_body)
            return
        self.send_response(200)
        self.send_header("Content-Type", _ALLOWED_FILES[name])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    def _method_not_allowed(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        body = "只读复核服务器不接受写入方法。\n".encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _plain(self, status: int, message: str, *, send_body: bool) -> None:
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        # Keep the console legible; access logs are not audit evidence.
        return


def make_server(
    run_dir: str | Path, host: str = "127.0.0.1", port: int = 8765
) -> http.server.ThreadingHTTPServer:
    if host not in _LOOPBACK_HOSTS:
        raise VerificationError("只读复核服务器仅允许绑定回环地址。")
    if not (0 <= int(port) <= 65535):
        raise VerificationError("端口必须在 0..65535 之间。")
    root = Path(run_dir).expanduser().resolve()
    # Verify before exposing files. A reviewer should never open a tampered run.
    verify_run(root)
    handler = type(
        "CharorderReadOnlyHandler",
        (_ReadOnlyHandler,),
        {"run_dir": root},
    )
    server = http.server.ThreadingHTTPServer((host, int(port)), handler)
    server.daemon_threads = True
    return server


def serve_run(
    run_dir: str | Path, host: str = "127.0.0.1", port: int = 8765
) -> None:
    server = make_server(run_dir, host, port)
    address, bound_port = server.server_address[:2]
    print(f"只读复核页：http://{address}:{bound_port}/", file=sys.stdout)
    print("仅支持 GET / HEAD；按 Ctrl+C 停止。", file=sys.stdout)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止只读复核服务器。", file=sys.stdout)
    finally:
        server.server_close()
