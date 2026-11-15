"""Command line interface for 字序迁核台 / charorder."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import APP_NAME, APP_SLUG, APP_TAGLINE, __version__
from .artifacts import execute
from .config import load_config
from .errors import CharorderError
from .models import SEVERITY_RANK, SEVERITIES
from .server import serve_run
from .verify import verify_run

_FAIL_ON_CHOICES = ("none", "low", "medium", "high")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="charorder",
        description=f"{APP_NAME}（{APP_SLUG}）— {APP_TAGLINE}。完全离线、源文件只读。",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = subparsers.add_parser("run", help="执行一次预检并生成报告与台账")
    run.add_argument("--config", required=True, help="配置 JSON 路径")
    run.add_argument("--out", help="输出目录；默认 charorder-runs/<run-id>")
    run.add_argument("--force", action="store_true", help="允许覆盖非空输出目录中的已知产物")
    run.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="none",
        help="按严重级别设置失败门禁；默认 none（仅生成报告）",
    )
    run.add_argument("--quiet", action="store_true", help="除错误外不输出终端摘要")

    demo = subparsers.add_parser("demo", help="对内置合成样例执行一次完整预检")
    demo.add_argument("--config", help=argparse.SUPPRESS)
    demo.add_argument("--out", default="out/charorder-demo", help="输出目录")
    demo.add_argument("--force", action="store_true", help="允许覆盖非空输出目录中的已知产物")
    demo.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="none",
        help="按严重级别设置失败门禁；样例默认 none",
    )
    demo.add_argument("--quiet", action="store_true", help="除错误外不输出终端摘要")

    verify = subparsers.add_parser("verify", help="校验一次运行的产物哈希与 SQLite 台账")
    verify.add_argument("--run", required=True, help="包含 manifest.json 的运行目录")

    serve = subparsers.add_parser("serve", help="以只读 HTTP 方式查看一次运行")
    serve.add_argument("--run", required=True, help="运行目录")
    serve.add_argument("--host", default="127.0.0.1", help="仅允许回环地址")
    serve.add_argument("--port", type=int, default=8765, help="监听端口")

    subparsers.add_parser("version", help="显示版本")
    return parser


def _demo_config_path() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / "fixtures" / "demo" / "config.json"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        if args.command == "version":
            print(f"{APP_NAME} {__version__} ({APP_SLUG})")
            return 0
        if args.command == "run":
            return _run_command(
                config_path=Path(args.config),
                out=Path(args.out) if args.out else None,
                force=args.force,
                fail_on=args.fail_on,
                quiet=args.quiet,
            )
        if args.command == "demo":
            config_path = Path(args.config) if args.config else _demo_config_path()
            return _run_command(
                config_path=config_path,
                out=Path(args.out),
                force=args.force,
                fail_on=args.fail_on,
                quiet=args.quiet,
                label="内置合成样例",
            )
        if args.command == "verify":
            report = verify_run(args.run)
            print("完整性校验通过。")
            print(f"运行：{report['run_id']} · 结论：{report['verdict']}")
            print(
                f"产物 {report['artifacts_verified']} 个 · "
                f"风险 {report['findings']} 条 · 键 {report['key_results']} 个 · "
                f"碰撞组 {report['collision_groups']}"
            )
            print("SQLite integrity_check：ok · HTML 自包含：是")
            return 0
        if args.command == "serve":
            serve_run(args.run, host=args.host, port=args.port)
            return 0
        parser.error(f"未知命令：{args.command}")
        return 2
    except CharorderError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已中断。", file=sys.stderr)
        return 130


def _run_command(
    *,
    config_path: Path,
    out: Path | None,
    force: bool,
    fail_on: str,
    quiet: bool,
    label: str | None = None,
) -> int:
    config = load_config(config_path)
    if not quiet:
        print(f"{APP_NAME} · {APP_SLUG} {__version__}")
        if label:
            print(f"模式：{label}")
        print(f"配置：{config.config_path}")
        print(f"项目：{config.project.name}")
        print(f"目标：{config.project.target}")
    result, manifest, output_dir = execute(config, out, force=force)
    summary = result.summary
    severity = summary["findings_by_severity"]
    if not quiet:
        print("-" * 64)
        print(
            f"源 {summary['source_count']} 个 · 记录 {summary['record_count']} 条 · "
            f"目标键 {summary['keys_evaluated']} 个"
        )
        print(
            f"风险：高 {severity['high']} / 中 {severity['medium']} / "
            f"低 {severity['low']} · 碰撞组 {summary['collision_groups']} · "
            f"超限键 {summary['overlength_keys']}"
        )
        print(f"结论：{result.verdict}")
        print(f"运行 ID：{result.run_id}")
        print(f"输出：{output_dir.resolve()}")
        print(f"复核页：{(output_dir / 'report.html').resolve()}")
        print(f"审计台账：{(output_dir / 'ledger.sqlite').resolve()}")
    failed = _gate_failed(severity, fail_on)
    if fail_on != "none" and not quiet:
        print(
            f"门禁 --fail-on {fail_on}："
            + ("未通过（存在达到阈值的风险）" if failed else "通过")
        )
    if failed:
        return 1
    return 0


def _gate_failed(severity: dict[str, int], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(
        severity.get(level, 0) > 0
        for level in SEVERITIES
        if SEVERITY_RANK[level] <= threshold
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
