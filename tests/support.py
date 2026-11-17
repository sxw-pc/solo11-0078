"""Shared helpers for stdlib unittest suites."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "fixtures" / "demo"
DEMO_CONFIG = DEMO_DIR / "config.json"


def demo_config() -> dict[str, Any]:
    return json.loads(DEMO_CONFIG.read_text(encoding="utf-8"))


def write_config(path: Path, config: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return path


def minimal_config(
    *,
    source: dict[str, Any],
    keys: list[dict[str, Any]],
    extra_sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "project": {
            "name": "测试项目",
            "target": "test-target-v1",
            "description": "unittest fixture",
        },
        "sources": [source, *(extra_sources or [])],
        "keys": keys,
        "reports": {"max_report_rows": 100},
    }


def ci_key(
    *,
    key_id: str,
    source_id: str,
    columns: list[str],
    unique: bool = True,
    required: bool = True,
    max_bytes: int | None = None,
    max_chars: int | None = None,
    invisible: str = "remove",
) -> dict[str, Any]:
    return {
        "id": key_id,
        "label": key_id,
        "source": source_id,
        "columns": columns,
        "destination": f"target.{key_id}",
        "transform": {
            "normalization": "NFC",
            "case": "casefold",
            "width_fold": True,
            "trim": True,
            "collapse_whitespace": True,
            "invisible": invisible,
        },
        "unique": unique,
        "required": required,
        "max_bytes": max_bytes,
        "max_chars": max_chars,
    }


def language_policy(
    *,
    contract: str,
    tag_field: str | None = None,
    default_language: str | None = None,
    supported_languages: list[str] | None = None,
) -> dict[str, Any]:
    policy: dict[str, Any] = {"contract": contract}
    if tag_field is not None:
        policy["tag_field"] = tag_field
    if default_language is not None:
        policy["default_language"] = default_language
    if supported_languages is not None:
        policy["supported_languages"] = supported_languages
    return policy


def language_key(
    *,
    key_id: str,
    source_id: str,
    columns: list[str],
    policy: dict[str, Any],
    case: str = "lower",
    normalization: str = "NFC",
    unique: bool = True,
    required: bool = True,
) -> dict[str, Any]:
    return {
        "id": key_id,
        "label": key_id,
        "source": source_id,
        "columns": columns,
        "destination": f"target.{key_id}",
        "transform": {
            "normalization": normalization,
            "case": case,
            "width_fold": False,
            "trim": True,
            "collapse_whitespace": False,
            "invisible": "keep",
            "language_policy": policy,
        },
        "unique": unique,
        "required": required,
    }
