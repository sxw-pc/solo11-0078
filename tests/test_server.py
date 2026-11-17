from __future__ import annotations

import hashlib
import http.client
import http.server
import ipaddress
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from charorder import server as server_module
from charorder.artifacts import execute
from charorder.config import load_config
from charorder.errors import VerificationError
from charorder.server import (
    PINNED_ENDPOINT,
    PURE_LOCAL_NAME,
    _authorize_request,
    _plan_endpoint,
    make_server,
)

from tests.support import DEMO_CONFIG


# --------------------------------------------------------------------------- #
# 合成解析器：getaddrinfo 的可替换替身，支持二次解析换址（TOCTOU 场景）
# --------------------------------------------------------------------------- #
def _gai(family: int, address: str, port: int = 8765):
    return (family, socket.SOCK_STREAM, 0, "", (address, port))


class _FakeResolver:
    """按调用次序返回解析答复；每次调用只暴露当时的快照。"""

    def __init__(self, answer_sets):
        self.answer_sets = [list(answers) for answers in answer_sets]
        self.calls = 0

    def __call__(self, host, port, family=socket.AF_UNSPEC, type_=socket.SOCK_STREAM, proto=0):
        index = min(self.calls, len(self.answer_sets) - 1)
        self.calls += 1
        return [_gai(fam, addr, port) for fam, addr in self.answer_sets[index]]


# --------------------------------------------------------------------------- #
# 绑定层合同：一次性解析、混合解析、二次换址、IPv4/IPv6
# --------------------------------------------------------------------------- #
class BindingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = load_config(DEMO_CONFIG)
        _result, _manifest, self.output = execute(self.config, self.root / "run")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pinned_contract_starts_under_mixed_resolution_and_binds_loopback(self) -> None:
        # localhost 同时解析到回环与非回环本机地址。
        resolver = _FakeResolver(
            [[(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "10.0.0.7")]]
        )
        httpd = make_server(
            self.output, "localhost", 0,
            contract=PINNED_ENDPOINT, resolver=resolver,
        )
        try:
            self.assertEqual(resolver.calls, 1)  # 启动时只解析一次
            bound_ip, bound_port = httpd.bound_endpoint
            self.assertTrue(ipaddress.ip_address(bound_ip).is_loopback)
            self.assertEqual(bound_ip, "127.0.0.1")
            # pinned 合同只信任数值 authority，绝不宣传名称。
            self.assertTrue(all("localhost" not in a for a in httpd.trusted_authorities))
            self.assertIn(f"127.0.0.1:{bound_port}", httpd.trusted_authorities)
            self.assertIsNone(httpd.advertised_name)
            self.assertEqual(httpd.visibility_contract, PINNED_ENDPOINT)
            # getsockname 与保存端点一致，且确为回环 socket。
            self.assertEqual(httpd.socket.getsockname()[0], bound_ip)
        finally:
            httpd.server_close()

    def test_re_resolution_change_after_check_cannot_move_the_endpoint(self) -> None:
        # 第一次答复含回环，“检查后”第二次答复整体换成非回环地址。
        resolver = _FakeResolver(
            [
                [(socket.AF_INET, "127.0.0.1")],
                [(socket.AF_INET, "203.0.113.9")],
                [(socket.AF_INET, "198.51.100.4")],
            ]
        )
        httpd = make_server(
            self.output, "localhost", 0,
            contract=PINNED_ENDPOINT, resolver=resolver,
        )
        try:
            self.assertEqual(resolver.calls, 1)  # 后续答复永远不会被读取
            bound_ip, _port = httpd.bound_endpoint
            self.assertEqual(bound_ip, "127.0.0.1")
            self.assertEqual(httpd.socket.getsockname()[0], "127.0.0.1")
            self.assertNotIn("203.0.113.9", " ".join(httpd.trusted_authorities))
        finally:
            httpd.server_close()

    def test_pinned_contract_with_only_non_loopback_answer_refuses(self) -> None:
        resolver = _FakeResolver([[(socket.AF_INET, "10.0.0.7")]])
        with self.assertRaisesRegex(VerificationError, "回环"):
            make_server(
                self.output, "localhost", 0,
                contract=PINNED_ENDPOINT, resolver=resolver,
            )
        self.assertEqual(resolver.calls, 1)

    def test_pure_local_name_contract_requires_all_loopback_answers(self) -> None:
        mixed = _FakeResolver(
            [[(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "10.0.0.7")]]
        )
        with self.assertRaisesRegex(VerificationError, "pure_local_name"):
            make_server(
                self.output, "localhost", 0,
                contract=PURE_LOCAL_NAME, resolver=mixed,
            )

        clean = _FakeResolver(
            [[(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]]
        )
        httpd = make_server(
            self.output, "localhost", 0,
            contract=PURE_LOCAL_NAME, resolver=clean,
        )
        try:
            self.assertEqual(clean.calls, 1)
            bound_ip, bound_port = httpd.bound_endpoint
            self.assertEqual(bound_ip, "127.0.0.1")  # IPv4 优先
            self.assertEqual(httpd.advertised_name, "localhost")
            self.assertIn(f"localhost:{bound_port}", httpd.trusted_authorities)
            self.assertIn(f"127.0.0.1:{bound_port}", httpd.trusted_authorities)
            self.assertIn(f"[::1]:{bound_port}", httpd.trusted_authorities)
        finally:
            httpd.server_close()

    def test_pure_contract_re_resolution_change_still_refuses_or_pins_safe(self) -> None:
        # 第一次混合 => pure 拒绝；即使第二次“变好”也不启动。
        resolver = _FakeResolver(
            [
                [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "10.0.0.7")],
                [(socket.AF_INET, "127.0.0.1")],
            ]
        )
        with self.assertRaisesRegex(VerificationError, "pure_local_name"):
            make_server(
                self.output, "localhost", 0,
                contract=PURE_LOCAL_NAME, resolver=resolver,
            )
        self.assertEqual(resolver.calls, 1)

    def test_numeric_non_loopback_literal_is_rejected(self) -> None:
        for host in ("0.0.0.0", "10.0.0.7", "::", "2001:db8::1"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(VerificationError, "回环"):
                    make_server(self.output, host, 0)

    def test_numeric_loopback_literals_bind_without_resolution(self) -> None:
        resolver = mock.Mock(side_effect=AssertionError("数值地址不得触发解析"))
        httpd = make_server(
            self.output, "127.0.0.1", 0,
            contract=PINNED_ENDPOINT, resolver=resolver,
        )
        try:
            self.assertEqual(httpd.bound_endpoint[0], "127.0.0.1")
        finally:
            httpd.server_close()
        resolver.assert_not_called()

    def test_unknown_hostname_and_bad_port_and_unknown_contract(self) -> None:
        resolver = _FakeResolver([[(socket.AF_INET, "127.0.0.1")]])
        with self.assertRaisesRegex(VerificationError, "localhost"):
            make_server(
                self.output, "attacker.example", 0,
                contract=PINNED_ENDPOINT, resolver=resolver,
            )
        with self.assertRaisesRegex(VerificationError, "端口"):
            make_server(self.output, "127.0.0.1", 70000)
        with self.assertRaisesRegex(VerificationError, "端口"):
            make_server(self.output, "127.0.0.1", "not-a-port")
        with self.assertRaisesRegex(VerificationError, "合同"):
            make_server(
                self.output, "127.0.0.1", 0,
                contract="bogus", resolver=resolver,
            )
        with self.assertRaisesRegex(VerificationError, "非空字符串"):
            make_server(self.output, "", 0)

    def test_resolver_failure_surfaces_as_verification_error(self) -> None:
        def failing(host, port, *args):
            raise socket.gaierror("synthetic resolution failure")

        with self.assertRaisesRegex(VerificationError, "无法解析"):
            make_server(
                self.output, "localhost", 0,
                contract=PINNED_ENDPOINT, resolver=failing,
            )

    def test_non_numeric_resolver_answer_is_ignored_not_bound(self) -> None:
        class NamedResolver:
            def __call__(self, host, port, *args):
                # 首个答复是名称别名（不能 bind），其后才是数值回环。
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("localhost", port)),
                    _gai(socket.AF_INET, "127.0.0.1", port),
                ]

        httpd = make_server(
            self.output, "localhost", 0,
            contract=PINNED_ENDPOINT, resolver=NamedResolver(),
        )
        try:
            self.assertEqual(httpd.bound_endpoint[0], "127.0.0.1")
        finally:
            httpd.server_close()

    def test_resolver_without_any_numeric_answer_refuses(self) -> None:
        class OnlyNameResolver:
            def __call__(self, host, port, *args):
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("localhost", port))]

        with self.assertRaisesRegex(VerificationError, "未解析出可用的数值 IP"):
            make_server(
                self.output, "localhost", 0,
                contract=PINNED_ENDPOINT, resolver=OnlyNameResolver(),
            )

        class EmptyResolver:
            def __call__(self, host, port, *args):
                return []

        with self.assertRaisesRegex(VerificationError, "未解析出可用的数值 IP"):
            make_server(
                self.output, "localhost", 0,
                contract=PINNED_ENDPOINT, resolver=EmptyResolver(),
            )

    def test_bind_failure_is_wrapped_and_socket_closed(self) -> None:
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        busy_port = holder.getsockname()[1]
        holder.listen(1)
        try:
            with self.assertRaisesRegex(VerificationError, "无法绑定回环端点"):
                make_server(self.output, "127.0.0.1", busy_port)
        finally:
            holder.close()

    def test_post_bind_non_loopback_getsockname_guard_refuses(self) -> None:
        # 防御纵深：即便底层 bind 后 getsockname 呈现非回环地址（环境/库被
        # 篡改），绑定后的核对也必须拒绝启动并关闭 socket。
        from charorder.server import _LoopbackThreadingHTTPServer

        real_server_bind = http.server.HTTPServer.server_bind

        def rogue_server_bind(self, *args):
            real_server_bind(self)  # 真实占用一个回环端口（server_address 已就绪）
            self.server_address = ("203.0.113.66", self.server_address[1])

        plan = {
            "family": socket.AF_INET,
            "numeric_address": "127.0.0.1",
            "port": 0,
            "trusted_authorities": frozenset({"127.0.0.1:0"}),
            "advertised_name": None,
            "contract": PINNED_ENDPOINT,
            "requested_host": "127.0.0.1",
        }
        with mock.patch.object(
            http.server.HTTPServer, "server_bind", rogue_server_bind
        ):
            with self.assertRaisesRegex(VerificationError, "不是回环地址"):
                _LoopbackThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    http.server.BaseHTTPRequestHandler,
                    plan,
                )
    def test_plan_endpoint_is_pure_and_deterministic(self) -> None:
        resolver = _FakeResolver(
            [[(socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")]]
        )
        plan = _plan_endpoint("localhost", 8765, PINNED_ENDPOINT, resolver)
        self.assertEqual(plan["family"], socket.AF_INET)  # IPv4 优先
        self.assertEqual(plan["numeric_address"], "127.0.0.1")
        self.assertNotIn("localhost", " ".join(plan["trusted_authorities"]))
        self.assertEqual(resolver.calls, 1)

    def test_default_system_resolver_matches_getaddrinfo_signature(self) -> None:
        # 回归：生产路径（无注入 resolver）必须能以五参数约定调用系统解析器。
        from charorder.server import _system_resolver

        answers = _system_resolver("localhost", 0, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM, 0)
        self.assertTrue(answers)
        for family, _type, _proto, _canon, sockaddr in answers:
            self.assertIn(family, (socket.AF_INET, socket.AF_INET6))
            ipaddress.ip_address(sockaddr[0])  # 答复均为数值地址

    def test_make_server_works_with_real_system_resolver_on_localhost(self) -> None:
        httpd = make_server(
            self.output, "localhost", 0, contract=PINNED_ENDPOINT
        )
        try:
            bound_ip, _port = httpd.bound_endpoint
            self.assertTrue(ipaddress.ip_address(bound_ip).is_loopback)
        finally:
            httpd.server_close()


# --------------------------------------------------------------------------- #
# 请求授权纯函数：RFC 9112 Host / request-target / peer 规则
# --------------------------------------------------------------------------- #
class _Headers:
    """模拟 http.client 的多值头容器。"""

    def __init__(self, host_values):
        self._values = list(host_values)

    def get_all(self, name, default=None):
        if name.lower() != "host":
            return default
        return list(self._values) if self._values else default


class RequestAuthorizationUnitTests(unittest.TestCase):
    TRUSTED = frozenset({"127.0.0.1:8765", "[::1]:8765", "localhost:8765"})

    def _check(self, target, host_values, peer="127.0.0.1", trusted=None):
        return _authorize_request(
            target, _Headers(host_values), peer, trusted or self.TRUSTED
        )

    def test_valid_origin_and_absolute_form(self) -> None:
        self.assertEqual(
            self._check("/keys.jsonl", ["127.0.0.1:8765"]), (True, 200)
        )
        self.assertEqual(
            self._check(
                "http://127.0.0.1:8765/keys.jsonl", ["127.0.0.1:8765"]
            ),
            (True, 200),
        )
        self.assertEqual(
            self._check("/", ["[::1]:8765"], peer="::1"), (True, 200)
        )
        self.assertEqual(
            self._check("/", ["localhost:8765"]), (True, 200)
        )

    def test_missing_duplicate_and_comma_host_are_400(self) -> None:
        self.assertEqual(self._check("/", []), (False, 400))
        self.assertEqual(
            self._check("/", ["127.0.0.1:8765", "127.0.0.1:8765"]), (False, 400)
        )
        self.assertEqual(
            self._check("/", ["127.0.0.1:8765, 127.0.0.1:8765"]), (False, 400)
        )

    def test_malformed_host_syntax_is_400(self) -> None:
        for bad in (
            "127.0.0.1",              # 缺端口
            "127.0.0.1:abc",          # 非数字端口
            "127.0.0.1:99999",        # 端口越界
            "127.0.0.1 :8765",        # 主机名内部空白（尾部 OWS 由头解析剥离）
            "user@127.0.0.1:8765",    # userinfo
            "http://127.0.0.1:8765",  # 带 scheme
            "[::1:8765",              # 括号不配对
            "[v1.fe80::]:8765",       # IPvFuture
            "bad%20host:8765",        # 百分号转义
        ):
            with self.subTest(bad=bad):
                self.assertEqual(self._check("/", [bad]), (False, 400))

    def test_wrong_port_and_attacker_domain_are_403(self) -> None:
        self.assertEqual(
            self._check("/", ["127.0.0.1:9999"]), (False, 403)
        )
        self.assertEqual(
            self._check("/", ["attacker.example:8765"]), (False, 403)
        )
        self.assertEqual(
            self._check("/", ["localhost:9999"]), (False, 403)
        )

    def test_non_loopback_peer_is_403(self) -> None:
        self.assertEqual(
            self._check("/", ["127.0.0.1:8765"], peer="10.0.0.7"), (False, 403)
        )
        self.assertEqual(
            self._check("/", ["127.0.0.1:8765"], peer="::ffff:10.0.0.7"),
            (False, 403),
        )

    def test_non_numeric_peer_is_400(self) -> None:
        # peer 来自 socket 层，正常恒为数值 IP；非数值属于协议级异常。
        self.assertEqual(
            self._check("/", ["127.0.0.1:8765"], peer="not-an-ip"),
            (False, 400),
        )

    def test_ipv4_mapped_loopback_peer_is_recognized(self) -> None:
        # dual-stack 套接字可能以 IPv4 映射 IPv6 形式呈现回环 peer。
        self.assertEqual(
            self._check("/", ["127.0.0.1:8765"], peer="::ffff:127.0.0.1"),
            (True, 200),
        )
        self.assertEqual(self._check("/", ["[::1]:8765"], peer="::1"), (True, 200))

    def test_absolute_form_conflicts_and_other_schemes_are_rejected(self) -> None:
        # 绝对 URI authority 与 Host 冲突
        self.assertEqual(
            self._check(
                "http://attacker.example:8765/keys.jsonl",
                ["127.0.0.1:8765"],
            ),
            (False, 400),
        )
        # 非 http/https scheme
        self.assertEqual(
            self._check(
                "ftp://127.0.0.1:8765/keys.jsonl", ["127.0.0.1:8765"]
            ),
            (False, 400),
        )
        # 绝对 URI 缺端口
        self.assertEqual(
            self._check(
                "http://127.0.0.1/keys.jsonl", ["127.0.0.1:8765"]
            ),
            (False, 400),
        )
        # 绝对 URI 端口越界
        self.assertEqual(
            self._check(
                "http://127.0.0.1:99999/keys.jsonl", ["127.0.0.1:8765"]
            ),
            (False, 400),
        )
        # 绝对 URI 主机语法无效
        self.assertEqual(
            self._check(
                "http://bad%20host:8765/keys.jsonl", ["127.0.0.1:8765"]
            ),
            (False, 400),
        )
        # authority-form / asterisk-form 不服务
        self.assertEqual(
            self._check("127.0.0.1:8765", ["127.0.0.1:8765"]), (False, 400)
        )
        self.assertEqual(self._check("*", ["127.0.0.1:8765"]), (False, 400))

    def test_non_canonical_ip_literal_in_host_is_rejected(self) -> None:
        # 前导零 IPv4 不是合法 IP 字面量也不是合法 reg-name 语义 → 400。
        self.assertEqual(
            self._check("/", ["127.0.0.001:8765"]), (False, 400)
        )
        # 完全展开（非压缩）的 IPv6 语法合法但非规范形式，往返不一致 → 400。
        self.assertEqual(
            self._check("/", ["[0:0:0:0:0:0:0:1]:8765"]), (False, 400)
        )
        # 规范的回环写法若不在信任集合内（错端口）仍是 403 而非 400。
        self.assertEqual(
            self._check("/", ["[::1]:9999"]), (False, 403)
        )

    def test_pinned_trust_set_rejects_localhost_name(self) -> None:
        pinned = frozenset({"127.0.0.1:8765"})
        self.assertEqual(
            _authorize_request("/", _Headers(["localhost:8765"]), "127.0.0.1", pinned),
            (False, 403),
        )
        self.assertEqual(
            _authorize_request(
                "/", _Headers(["127.0.0.1:8765"]), "127.0.0.1", pinned
            ),
            (True, 200),
        )


# --------------------------------------------------------------------------- #
# 实时服务器集成：真实 socket、零次产物读取断言、无请求期 DNS
# --------------------------------------------------------------------------- #
class _LiveServerHarness:
    def __init__(self, output, host="127.0.0.1", contract=PINNED_ENDPOINT, resolver=None):
        kwargs = {"contract": contract}
        if resolver is not None:
            kwargs["resolver"] = resolver
        self.httpd = make_server(output, host, 0, **kwargs)
        self.host, self.port = self.httpd.bound_endpoint
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def request(self, method, path, headers=()):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            connection.request(method, path, headers=dict(headers))
            response = connection.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def raw(self, raw_bytes: bytes):
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            sock.sendall(raw_bytes)
            chunks = []
            while True:
                block = sock.recv(65536)
                if not block:
                    break
                chunks.append(block)
        raw = b"".join(chunks)
        head, _, body = raw.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("latin1")
        status = int(status_line.split(" ", 2)[1])
        return status, head, body


class PinnedLiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        config = load_config(DEMO_CONFIG)
        _result, cls.manifest, cls.output = execute(config, cls.root / "run")
        cls.harness = _LiveServerHarness(cls.output)
        cls.run_id = cls.manifest["run_id"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.harness.stop()
        cls.temp.cleanup()

    # -- 合法 GET/HEAD ----------------------------------------------------- #
    def test_legitimate_get_and_head_return_full_artifacts(self) -> None:
        status, _headers, body = self.harness.request("GET", "/keys.jsonl")
        self.assertEqual(status, 200)
        self.assertEqual(body, (self.output / "keys.jsonl").read_bytes())
        self.assertIn(b"target_key", body)

        status, headers, body = self.harness.request("HEAD", "/report.html")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(headers["Content-Length"]), 0)

    def test_legitimate_absolute_form_get(self) -> None:
        host = f"127.0.0.1:{self.harness.port}"
        status, _headers, body = self.harness.raw(
            f"GET http://127.0.0.1:{self.harness.port}/manifest.json HTTP/1.1\r\n"
            f"Host: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        self.assertEqual(status, 200)
        self.assertIn(self.run_id.encode("utf-8"), body)

    def test_evidence_hashes_unchanged_for_authorized_requests(self) -> None:
        for name in ("report.html", "ledger.sqlite", "manifest.json"):
            status, _h, body = self.harness.request("GET", f"/{name}")
            self.assertEqual(status, 200)
            self.assertEqual(
                hashlib.sha256(body).hexdigest(),
                hashlib.sha256((self.output / name).read_bytes()).hexdigest(),
            )

    # -- Host 缺失/重复/错端口/攻击者域 ------------------------------------ #
    def test_attacker_host_is_403_with_zero_artifact_reads(self) -> None:
        with mock.patch.object(
            server_module, "_read_artifact", side_effect=AssertionError("不得读取产物")
        ) as read_mock:
            status, _h, body = self.harness.raw(
                f"GET /keys.jsonl HTTP/1.1\r\n"
                f"Host: attacker.example:{self.harness.port}\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
        self.assertEqual(status, 403)
        read_mock.assert_not_called()
        self.assertNotIn(self.run_id, body.decode("utf-8"))
        self.assertNotIn(b"target_key", body)
        self.assertNotIn(b"attacker", body)  # 不回显请求 Host

    def test_missing_host_is_400_with_zero_artifact_reads(self) -> None:
        with mock.patch.object(
            server_module, "_read_artifact", side_effect=AssertionError("不得读取产物")
        ) as read_mock:
            status, _h, body = self.harness.raw(
                b"GET /keys.jsonl HTTP/1.1\r\nConnection: close\r\n\r\n"
            )
        self.assertEqual(status, 400)
        read_mock.assert_not_called()
        self.assertNotIn(self.run_id, body.decode("utf-8"))

    def test_duplicate_host_is_400_with_zero_artifact_reads(self) -> None:
        with mock.patch.object(
            server_module, "_read_artifact", side_effect=AssertionError("不得读取产物")
        ) as read_mock:
            status, _h, body = self.harness.raw(
                f"GET /ledger.sqlite HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.harness.port}\r\n"
                f"Host: 127.0.0.1:{self.harness.port}\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
        self.assertEqual(status, 400)
        read_mock.assert_not_called()
        self.assertNotIn(b"SQLite", body)

    def test_wrong_port_host_is_403_with_zero_reads(self) -> None:
        with mock.patch.object(
            server_module, "_read_artifact", side_effect=AssertionError("不得读取产物")
        ) as read_mock:
            status, _h, body = self.harness.raw(
                f"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
        self.assertEqual(status, 403)
        read_mock.assert_not_called()
        self.assertNotIn(b"target_key", body)

    def test_localhost_name_not_trusted_under_pinned_contract(self) -> None:
        status, _h, body = self.harness.raw(
            f"GET /keys.jsonl HTTP/1.1\r\nHost: localhost:{self.harness.port}\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        self.assertEqual(status, 403)
        self.assertNotIn(b"target_key", body)

    def test_absolute_uri_host_conflict_is_400(self) -> None:
        status, _h, body = self.harness.raw(
            f"GET http://attacker.example:{self.harness.port}/keys.jsonl HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.harness.port}\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        self.assertEqual(status, 400)
        self.assertNotIn(b"target_key", body)

    def test_request_path_never_dns_resolves_host(self) -> None:
        # 即便 Host 是攻击者域名，请求处理也绝不触发名称解析；数值回环地址的
        # 内部查询由 socket 自身完成，与请求 Host 无关，因此仅拦截名称查询。
        real_getaddrinfo = socket.getaddrinfo

        def fail_name_resolution(host, *args, **kwargs):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise AssertionError(f"请求期不得解析 DNS 名称：{host}")
            return real_getaddrinfo(host, *args, **kwargs)

        with mock.patch.object(socket, "getaddrinfo", side_effect=fail_name_resolution):
            status, _h, _body = self.harness.raw(
                f"GET /keys.jsonl HTTP/1.1\r\n"
                f"Host: attacker.example:{self.harness.port}\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
        self.assertEqual(status, 403)

    def test_unknown_path_remains_404_after_authorization(self) -> None:
        status, _h, _body = self.harness.request("GET", "/README.md")
        self.assertEqual(status, 404)

    def test_write_methods_still_rejected(self) -> None:
        status, headers, _body = self.harness.request("POST", "/manifest.json")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, HEAD")


@unittest.skipUnless(
    socket.has_ipv6, "平台不支持 IPv6"
)
class IPv6LiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        config = load_config(DEMO_CONFIG)
        _result, cls.manifest, cls.output = execute(config, cls.root / "run")
        try:
            cls.harness = _LiveServerHarness(cls.output, host="::1")
        except OSError as exc:  # pragma: no cover - 环境无 ::1 时跳过
            raise unittest.SkipTest(f"无法绑定 ::1：{exc}")

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "harness"):
            cls.harness.stop()
        cls.temp.cleanup()

    def test_ipv6_socket_is_loopback_and_records_dual_stack_state(self) -> None:
        self.assertEqual(self.harness.httpd.bound_endpoint[0], "::1")
        self.assertTrue(
            ipaddress.ip_address(
                self.harness.httpd.socket.getsockname()[0]
            ).is_loopback
        )
        self.assertIsInstance(self.harness.httpd.ipv6_dual_stack, bool)
        self.assertIn(
            f"[::1]:{self.harness.port}", self.harness.httpd.trusted_authorities
        )

    def test_ipv6_legitimate_request_and_wrong_host(self) -> None:
        status, _h, body = self.harness.raw(
            f"GET /manifest.json HTTP/1.1\r\nHost: [::1]:{self.harness.port}\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        self.assertEqual(status, 200)
        self.assertIn(b"run_id", body)

        with mock.patch.object(
            server_module, "_read_artifact", side_effect=AssertionError("不得读取产物")
        ):
            status, _h, body = self.harness.raw(
                f"GET /keys.jsonl HTTP/1.1\r\nHost: [::1]:1\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
        self.assertEqual(status, 403)
        self.assertNotIn(b"target_key", body)


class PureLocalNameLiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        config = load_config(DEMO_CONFIG)
        _result, cls.manifest, cls.output = execute(config, cls.root / "run")
        # 合成解析器证明 localhost 的所有答复都是回环（IPv4+IPv6）。
        resolver = _FakeResolver(
            [[(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]]
        )
        cls.harness = _LiveServerHarness(
            cls.output, host="localhost", contract=PURE_LOCAL_NAME, resolver=resolver
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.harness.stop()
        cls.temp.cleanup()

    def test_localhost_name_authority_is_accepted(self) -> None:
        status, _h, body = self.harness.raw(
            f"GET /keys.jsonl HTTP/1.1\r\nHost: localhost:{self.harness.port}\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        self.assertEqual(status, 200)
        self.assertIn(b"target_key", body)

    def test_numeric_authority_still_accepted_and_attacker_rejected(self) -> None:
        status, _h, body = self.harness.raw(
            f"GET /manifest.json HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.harness.port}\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        self.assertEqual(status, 200)

        with mock.patch.object(
            server_module, "_read_artifact", side_effect=AssertionError("不得读取产物")
        ):
            status, _h, body = self.harness.raw(
                f"GET /keys.jsonl HTTP/1.1\r\n"
                f"Host: attacker.example:{self.harness.port}\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
        self.assertEqual(status, 403)
        self.assertNotIn(b"target_key", body)


# --------------------------------------------------------------------------- #
# 原有白名单行为回归
# --------------------------------------------------------------------------- #
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
