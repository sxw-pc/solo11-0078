"""回环专用的只读 HTTP 复核服务器与网络可见性合同。

复核页展示原始键与记录身份，keys.jsonl / ledger.sqlite 也在只读白名单中，因此
verify_run 已验证的证据只能交给真正连到本机复核台的请求方。本模块用两层合同
保证这一点：

1. 绑定层（启动时）
   - pinned_endpoint：对主机名只做一次 A/AAAA 解析，只把经验证的数值回环地址
     交给 socket 绑定，宣传内容也只有数字 URL；混合解析（含非回环答案）环境下
     仍可启动，因为名称永远不会被直接 bind，二次换址（TOCTOU）也无从影响端点。
   - pure_local_name：必须证明 localhost 的所有解析答复都是回环地址，否则拒绝
     启动；启动后在 pinned 的保证之外，额外信任并宣传 localhost 名称。
   绑定后核对 getsockname 与 IPv6 dual-stack 状态，任何非回环实际监听都拒绝。

2. 请求层（每次 GET/HEAD/报告/JSONL/SQLite 读取之前）
   - 按 RFC 9112 校验 Host：HTTP/1.1 必须有且仅有一个语法有效的 Host，缺失、
     重复（含逗号列表）、语法错误一律 400；
   - origin-form 的 Host（含端口）必须在服务器保存的可信 authority 集合内，
     absolute-form 的 request-target authority 必须与 Host 完全一致且可信，
     错端口、攻击者域返回 403；
   - TCP peer 必须是数值回环地址，非回环 peer 返回 403；
   - 请求路径上绝不以 Host 做任何 DNS 解析。
   授权失败时返回固定文案，不含 run_id、Host、路径或任何产物原文，且不触碰
   run_dir 中的任何文件。

键计算、碰撞组与迁移门禁均在其他模块内，本模块不改变任何产物内容或哈希。
"""

from __future__ import annotations

import http.server
import ipaddress
import re
import socket
import sys
from pathlib import Path
from typing import Any, Callable
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
    "keys.jsonl": "application/x-ndjson; charset=utf-8",
    "ledger.sqlite": "application/vnd.sqlite3",
    "manifest.json": "application/json; charset=utf-8",
}

#: 只把已验证的数值回环地址交给 bind；名称合同额外信任的本机名称。
PINNED_ENDPOINT = "pinned_endpoint"
PURE_LOCAL_NAME = "pure_local_name"
_CONTRACTS = frozenset({PINNED_ENDPOINT, PURE_LOCAL_NAME})
_LOCAL_NAMES = frozenset({"localhost"})

# RFC 3986 reg-name：未做百分号转义的字母数字与未保留/子分隔字符。
_REG_NAME = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=]+$")

# 固定错误文案：刻意不回显 Host、路径、run_id 或任何原文。
_BAD_REQUEST = "请求不符合 RFC 9112：Host 或 request-target 无效。\n"
_FORBIDDEN = "拒绝访问：该复核台仅接受本机回环上的可信 authority。\n"

Resolver = Callable[[str, int, int, int, int], list[tuple[int, int, int, str, tuple]]]


# --------------------------------------------------------------------------- #
# 绑定层：一次性解析、数值回环验证、绑定后核对
# --------------------------------------------------------------------------- #
def _system_resolver(
    host: str,
    port: int,
    family: int = socket.AF_UNSPEC,
    type_: int = socket.SOCK_STREAM,
    proto: int = 0,
) -> list[tuple[int, int, int, str, tuple]]:
    """默认解析器：封装 getaddrinfo，只取 STREAM 答复，便于在测试中整体替换。"""
    return socket.getaddrinfo(host, port, family, type_, proto)


def _resolve_loopback_candidates(
    host: str, port: int, resolver: Resolver
) -> list[tuple[int, str]]:
    """对主机名做一次 A/AAAA 解析，返回去重后的 (family, 数值地址)。

    只接受数值 IP 形式的答复；解析在启动时一次性完成，请求路径上永远不会再
    调用解析器（包括第二次解析），从而消除“检查后换址”的 TOCTOU 窗口。
    """
    try:
        answers = resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0)
    except socket.gaierror as exc:
        raise VerificationError(f"无法解析本机名称 {host}：{exc}") from exc
    candidates: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _type, _proto, _canon, sockaddr in answers:
        numeric = sockaddr[0]
        try:
            ipaddress.ip_address(numeric)
        except ValueError:
            # getaddrinfo 可能返回非数值别名；名称绝不进入 bind。
            continue
        key = (family, numeric)
        if key not in seen:
            seen.add(key)
            candidates.append(key)
    if not candidates:
        raise VerificationError(f"本机名称 {host} 未解析出可用的数值 IP 地址。")
    return candidates


def _all_loopback(candidates: list[tuple[int, str]]) -> bool:
    return all(ipaddress.ip_address(address).is_loopback for _family, address in candidates)


def _plan_endpoint(
    host: str,
    port: int,
    contract: str,
    resolver: Resolver,
) -> dict[str, Any]:
    """决定实际 bind 的数值端点与可信 authority，不执行任何 socket 操作。"""
    if contract not in _CONTRACTS:
        raise VerificationError(
            f"未知本机名称合同：{contract}；可选 {sorted(_CONTRACTS)}。"
        )
    if not (0 <= int(port) <= 65535):
        raise VerificationError("端口必须在 0..65535 之间。")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        # 数值地址不做解析，直接验证回环属性；名称合同对数值地址没有额外含义。
        if not literal.is_loopback:
            raise VerificationError("只读复核服务器仅允许绑定回环地址。")
        family = socket.AF_INET if isinstance(literal, ipaddress.IPv4Address) else socket.AF_INET6
        candidates = [(family, str(literal))]
        name_trusted: str | None = None
    else:
        if host.lower() not in _LOCAL_NAMES:
            raise VerificationError(
                "只读复核服务器仅接受数值回环地址或本机名称 localhost。"
            )
        candidates = _resolve_loopback_candidates(host, port, resolver)
        if not _all_loopback(candidates):
            if contract == PURE_LOCAL_NAME:
                raise VerificationError(
                    "pure_local_name 合同要求 localhost 的所有解析答复均为回环地址，"
                    "当前存在非回环答复，拒绝启动。"
                )
            # pinned_endpoint：忽略非回环答复，只挑回环候选，绝不按名称 bind。
            candidates = [
                (family, address)
                for family, address in candidates
                if ipaddress.ip_address(address).is_loopback
            ]
            if not candidates:
                raise VerificationError(
                    "localhost 的解析答复中没有任何回环地址，拒绝启动。"
                )
        name_trusted = host.lower() if contract == PURE_LOCAL_NAME else None

    # 与系统常见的 localhost 回复顺序一致：IPv4 优先，其次 IPv6，保持解析顺序。
    ordered = sorted(candidates, key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    family, numeric = ordered[0]

    verified_loopbacks = tuple(
        (fam, addr)
        for fam, addr in ordered
        if ipaddress.ip_address(addr).is_loopback
    )
    trusted = {f"[{addr}]:{port}" if fam == socket.AF_INET6 else f"{addr}:{port}"
               for fam, addr in verified_loopbacks}
    if name_trusted is not None:
        trusted.add(f"{name_trusted}:{port}")

    return {
        "family": family,
        "numeric_address": numeric,
        "port": port,
        "trusted_authorities": frozenset(trusted),
        "advertised_name": name_trusted,
        "contract": contract,
        "requested_host": host,
    }


class _LoopbackThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """绑定后强制核对实际监听地址；非回环端点直接拒绝启动。"""

    def __init__(self, server_address: Any, handler_class: Any, plan: dict[str, Any]):
        self.address_family = plan["family"]
        self.endpoint_plan = plan
        super().__init__(server_address, handler_class)
        self.daemon_threads = True
        actual_ip = ipaddress.ip_address(self.server_address[0])
        if not actual_ip.is_loopback:
            self.server_close()
            raise VerificationError(
                f"实际监听地址 {actual_ip} 不是回环地址，拒绝启动。"
            )
        if actual_ip.version == 6:
            # 记录 dual-stack 状态：dual-stack（v6only=0）会同时接收 IPv4 映射
            # 连接，复核台必须显式知道这一点而非默认。
            self.ipv6_dual_stack = bool(
                self.socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
            )
        else:
            self.ipv6_dual_stack = False
        self.bound_endpoint = (str(actual_ip), self.server_address[1])
        self.trusted_authorities = frozenset(
            self._rebase_authority(authority, self.server_address[1])
            for authority in plan["trusted_authorities"]
        )
        self.advertised_name = plan["advertised_name"]
        self.visibility_contract = plan["contract"]

    @staticmethod
    def _rebase_authority(authority: str, actual_port: int) -> str:
        """端口 0 由内核分配时，把启动前算出的可信 authority 改成实际端口。"""
        prefix, _sep, _port = authority.rpartition(":")
        return f"{prefix}:{actual_port}"


# --------------------------------------------------------------------------- #
# 请求层：RFC 9112 Host / request-target / peer 授权（不做任何 DNS 解析）
# --------------------------------------------------------------------------- #
def _parse_host_authority(value: str) -> str:
    """把单个 Host 头值解析为规范化 authority；语法错误抛 ValueError。

    要求显式端口、不允许 userinfo / 百分号转义 / IPvFuture；IP 字面量往返
    规范化，注册名按 RFC 3986 reg-name 校验。
    """
    if not value or any(ch.isspace() for ch in value):
        raise ValueError("空或含空白的 Host")
    parts = urlsplit("//" + value)
    if parts.scheme or parts.path or parts.query or parts.fragment:
        raise ValueError("Host 不是纯 authority")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Host 不允许 userinfo")
    hostname = parts.hostname
    port = parts.port
    if not hostname or port is None:
        raise ValueError("Host 必须同时包含主机与显式端口")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # 纯数字点分标签（如 127.0.0.001）不是合法严格 IP，但落在 reg-name
        # 文法内；浏览器对其有八进制等歧义解释，必须按 400 拒绝而非当域名。
        labels = hostname.split(".")
        looks_like_numeric_ip = (
            len(labels) == 4 and all(label.isdigit() for label in labels)
        )
        if "%" in hostname or looks_like_numeric_ip or not _REG_NAME.fullmatch(hostname):
            raise ValueError("Host 主机名语法无效")
        host_norm = hostname  # reg-name 合法字符均为大小写不敏感的 ASCII
    else:
        # 拒绝 IPvFuture、前导零等非规范字面量：拆分结果必须与标准形式
        # 严格往返一致（不同 Python 版本对宽容写法的接受度不同，显式收紧）。
        if hostname != str(ip):
            raise ValueError("IP 字面量非规范形式")
        host_norm = f"[{ip}]" if ip.version == 6 else str(ip)
    return f"{host_norm}:{port}"


def _extract_host_headers(headers: Any) -> list[str]:
    """按 RFC 9112 收集 Host 头：重复 Host 或逗号列表都算多个 authority。"""
    combined = headers.get_all("Host")
    if not combined:
        return []
    values: list[str] = []
    for raw in combined:
        values.extend(piece.strip() for piece in raw.split(","))
    return values


def _is_loopback_peer(
    peer: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """回环 peer 判定，覆盖 dual-stack 套接字上的 IPv4 映射 IPv6 地址。"""
    if peer.is_loopback:
        return True
    mapped = getattr(peer, "ipv4_mapped", None)
    return mapped is not None and mapped.is_loopback


def _authorize_request(
    request_target: str, headers: Any, peer_address: str, trusted: frozenset[str]
) -> tuple[bool, int]:
    """授权一次请求。返回 (是否放行, 状态码)；全程不做 DNS 解析。

    400 表示违反 RFC 9112 语法规则（缺失/重复/无效 Host、request-target 与
    Host 冲突），403 表示语法合法但 authority 或 peer 不被信任。
    """
    try:
        peer = ipaddress.ip_address(peer_address)
    except ValueError:
        return False, 400
    if not _is_loopback_peer(peer):
        return False, 403

    host_values = _extract_host_headers(headers)
    if not host_values:
        return False, 400  # RFC 9112：HTTP/1.1 必须带 Host
    if len(host_values) != 1:
        return False, 400  # RFC 9112：重复 Host 必须拒绝
    try:
        host_authority = _parse_host_authority(host_values[0])
    except ValueError:
        return False, 400

    target = request_target
    if target.startswith("/"):
        target_authority = host_authority  # origin-form：authority 即 Host
    else:
        if target == "*" or target.startswith("//"):
            return False, 400  # asterisk-form / authority-form 不服务
        parsed = urlsplit(target)  # absolute-form
        if parsed.scheme not in ("http", "https"):
            return False, 400
        try:
            if parsed.port is None or not parsed.hostname:
                return False, 400
        except ValueError:
            return False, 400  # 端口非数字或越界
        try:
            target_authority = _parse_host_authority(parsed.netloc)
        except ValueError:
            return False, 400
        if target_authority != host_authority:
            return False, 400  # RFC 9112：absolute-form 与 Host 冲突

    if host_authority not in trusted or target_authority not in trusted:
        return False, 403
    return True, 200


def _read_artifact(file_path: Path) -> bytes:
    """唯一的产物字节读取入口，便于测试断言“未授权请求零次产物读取”。"""
    return file_path.read_bytes()


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
        # 授权必须在读任何文件之前完成；失败路径不触碰 run_dir。
        peer_address = self.client_address[0]
        allowed, status = _authorize_request(
            self.path, self.headers, peer_address, self.server.trusted_authorities
        )
        if not allowed:
            self._plain(
                status,
                _BAD_REQUEST if status == 400 else _FORBIDDEN,
                send_body=send_body,
            )
            return

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
            data = _read_artifact(file_path)
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
        body = message.encode("utf-8")
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


# --------------------------------------------------------------------------- #
# 工厂与前台入口
# --------------------------------------------------------------------------- #
def make_server(
    run_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    contract: str = PINNED_ENDPOINT,
    resolver: Resolver | None = None,
) -> http.server.ThreadingHTTPServer:
    """创建回环只读复核服务器。

    启动顺序固定：先 verify_run（启动前完整性门禁），再一次性解析/验证回环，
    最后用数值地址绑定并核对 getsockname。resolver 仅用于测试注入，生产路径
    使用 socket.getaddrinfo，请求处理路径上不存在任何解析调用。
    """
    if not isinstance(host, str) or not host:
        raise VerificationError("主机参数必须是非空字符串。")
    try:
        numeric_port = int(port)
    except (TypeError, ValueError):
        raise VerificationError("端口必须是 0..65535 的整数。") from None
    root = Path(run_dir).expanduser().resolve()
    # Verify before exposing files. A reviewer should never open a tampered run.
    verify_run(root)
    resolve = resolver or _system_resolver
    plan = _plan_endpoint(host, numeric_port, contract, resolve)

    handler = type(
        "CharorderReadOnlyHandler",
        (_ReadOnlyHandler,),
        {"run_dir": root},
    )
    if plan["family"] == socket.AF_INET6:
        bind_address = (plan["numeric_address"], plan["port"], 0, 0)
    else:
        bind_address = (plan["numeric_address"], plan["port"])
    try:
        server = _LoopbackThreadingHTTPServer(bind_address, handler, plan)
    except OSError as exc:
        raise VerificationError(f"无法绑定回环端点 {bind_address[0]}:{plan['port']}：{exc}") from exc
    return server


def serve_run(
    run_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    contract: str = PINNED_ENDPOINT,
) -> None:
    server = make_server(run_dir, host, port, contract=contract)
    address, bound_port = server.bound_endpoint
    # pinned_endpoint 只宣传数字 URL；pure_local_name 额外宣传已证明为本机的名称。
    print(f"只读复核页（{server.visibility_contract}）：http://{address}:{bound_port}/",
          file=sys.stdout)
    if server.advertised_name is not None:
        print(
            f"本机名称入口（已验证全部解析为回环）："
            f"http://{server.advertised_name}:{bound_port}/",
            file=sys.stdout,
        )
    print("仅支持 GET / HEAD；按 Ctrl+C 停止。", file=sys.stdout)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止只读复核服务器。", file=sys.stdout)
    finally:
        server.server_close()
