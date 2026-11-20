"""Rebuild the fully synthetic demo fixtures deterministically.

Usage:
    python tools/build_demo_fixtures.py
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "fixtures" / "demo"


def fullwidth(text: str) -> str:
    """Convert ASCII characters to full-width forms for width-fold fixtures."""

    out = []
    for char in text:
        code = ord(char)
        if char == " ":
            out.append("　")
        elif 0x21 <= code <= 0x7E:
            out.append(chr(code + 0xFEE0))
        else:
            out.append(char)
    return "".join(out)


LONG_EMAIL = (
    "zoe.obrien+enterprise-account-with-a-very-long-tag@example-corporation.com"
)
CONTACT_LONG_EMAIL = (
    "fatima.zahra+regional-lead-account@example-corporation.com"
)

CUSTOMERS = [
    {
        "customer_id": "C-1001",
        "name": "José Álvarez",
        "email": "Jose@Example.com",
        "company": "Acme  Ltd",
        "city": "Madrid",
        "notes": "VIP",
    },
    {
        "customer_id": "C-1002",
        "name": "José Álvarez",
        "email": "jose@example.com",
        "company": "Acme Ltd",
        "city": "Madrid",
        "notes": "vip",
    },
    {
        "customer_id": "C-1003",
        "name": "ＡＢＣ　Ｃｏｍｐａｎｙ",
        "email": "ops@example.com",
        "company": "ABC Company",
        "city": "Tokyo",
        "notes": "renewal soon",
    },
    {
        "customer_id": "C-1004",
        "name": "ABC Company",
        "email": "OPS@example.com",
        "company": "ABC Company",
        "city": "Tokyo",
        "notes": "renewal soon",
    },
    {
        "customer_id": "C-1005",
        "name": "李​雷",
        "email": "li.lei@example.com",
        "company": "蓝海科技",
        "city": "Shanghai",
        "notes": "line1\nline2",
    },
    {
        "customer_id": "C-1006",
        "name": "李雷",
        "email": "li.lei@example.com",
        "company": "蓝海科技",
        "city": "Shanghai",
        "notes": "duplicate",
    },
    {
        "customer_id": "C-1007",
        "name": "Zoë O'Brien",
        "email": LONG_EMAIL,
        "company": "Zeta Works",
        "city": "London",
        "notes": "safe ‮gnp.exe",
    },
    {
        "customer_id": "C-1008",
        "name": "Ｚｏｅ̈　Ｏ'Ｂｒｉｅｎ",
        "email": fullwidth(LONG_EMAIL),
        "company": "Zeta Works",
        "city": "London",
        "notes": "mirror",
    },
    {
        "customer_id": "C-1009",
        "name": "Ravi Kapoor",
        "email": "",
        "company": "Delta LLP",
        "city": "Mumbai",
        "notes": "no email",
    },
    {
        "customer_id": "C-1010",
        "name": "Nina Petrova",
        "email": "nina@example.org",
        "company": "Echo Inc",
        "city": "Berlin",
        "notes": "decoded � byte",
    },
]

PRODUCTS = [
    {
        "sku": "SKU-001",
        "title": "Café Mug",
        "category": "kitchen",
        "description": "Ceramic 300ml",
    },
    {
        "sku": "sku-001",
        "title": "Café Mug",
        "category": "kitchen",
        "description": "lowercase duplicate SKU",
    },
    {
        "sku": "SKU-003",
        "title": "ｶﾀｶﾅ ﾏｸﾞ",
        "category": "home",
        "description": "half-width kana",
    },
    {
        "sku": "SKU-004",
        "title": "カタカナ マグ",
        "category": "home",
        "description": "full-width kana",
    },
    {
        "sku": "SKU-005",
        "title": "Soft­hyphen",
        "category": "stationery",
        "description": "soft hyphen remains visible",
    },
    {
        "sku": "SKU-006",
        "title": "Extra long product title with many descriptive words that should exceed the target key budget",
        "category": "promo",
        "description": "long key",
    },
    {
        "sku": fullwidth("SKU-007"),
        "title": "Ｆｕｌｌｗｉｄｔｈ SKU",
        "category": "ops",
        "description": "full-width SKU",
    },
    {
        "sku": "SKU-007",
        "title": "Fullwidth SKU",
        "category": "ops",
        "description": "duplicate fullwidth",
    },
    {
        "sku": "SKU-008",
        "title": "Safe ‮gnp.exe",
        "category": "security",
        "description": "bidi control",
    },
    {
        "sku": "SKU-009",
        "title": "MÃ¼ller Mug",
        "category": "home",
        "description": "mojibake without auto-fix",
    },
    {
        "sku": "SKU-010",
        "title": "Control\u0007Bell",
        "category": "ops",
        "description": "bad __INVALID_BYTE__ byte",
    },
    {
        "sku": "SKU-011",
        "title": "Replacement � in title",
        "category": "ops",
        "description": "literal replacement character",
    },
    {
        "title": "Missing SKU",
        "category": "unknown",
        "description": "record id intentionally absent",
    },
]

CONTACTS = [
    ("CT-01", "Mia Chen", "Acme Ltd", "mia@acme.example", "East\tOffice"),
    ("CT-02", "MIA CHEN", "ACME LTD", "MIA@acme.example", "East Office"),
    ("CT-03", "Noor Al-Sayed", "βeta Works", "noor@beta.example", "soft­hyphen"),
    ("CT-04", "No​or Al-Sayed", "βeta Works", "noor@beta.example", "duplicate"),
    ("CT-05", "Fatima Zahra", "Gamma LLC", CONTACT_LONG_EMAIL, "long email"),
    ("CT-06", "Renée Dubois", "Delta LLP", "renee@delta.example", " trailing "),
    ("CT-07", "Renée Dubois", "Delta LLP", "RENEE@delta.example", "leading "),
    ("CT-08", "Li‮ Lei", "Blue Harbor", "li@blue.example", "bidi name"),
]


def build() -> None:
    DEMO.mkdir(parents=True, exist_ok=True)
    _build_customers()
    _build_products()
    _build_contacts()
    _build_config()
    _build_readme()
    print(f"Rebuilt demo fixtures in {DEMO}")


def _build_customers() -> None:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=["customer_id", "name", "email", "company", "city", "notes"],
        lineterminator="\n",
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()
    writer.writerows(CUSTOMERS)
    (DEMO / "customers.csv").write_bytes(b"\xef\xbb\xbf" + output.getvalue().encode("utf-8"))


def _build_products() -> None:
    chunks: list[bytes] = []
    for row in PRODUCTS:
        line = json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        encoded = line.encode("utf-8").replace(b"__INVALID_BYTE__", b"\xff")
        chunks.append(encoded + b"\n")
    (DEMO / "products.jsonl").write_bytes(b"".join(chunks))


def _build_contacts() -> None:
    path = DEMO / "contacts.sqlite"
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            """
            CREATE TABLE contacts (
                contact_id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                company TEXT NOT NULL,
                email TEXT NOT NULL,
                notes TEXT
            )
            """
        )
        connection.executemany(
            "INSERT INTO contacts (contact_id, full_name, company, email, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            CONTACTS,
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()


def _build_config() -> None:
    transform_ci = {
        "normalization": "NFC",
        "case": "casefold",
        "width_fold": True,
        "trim": True,
        "collapse_whitespace": True,
        "invisible": "remove",
    }
    transform_name = {
        "normalization": "NFC",
        "case": "casefold",
        "width_fold": True,
        "trim": True,
        "collapse_whitespace": True,
        "invisible": "remove",
    }
    transform_title = {
        "normalization": "NFC",
        "case": "casefold",
        "width_fold": True,
        "trim": True,
        "collapse_whitespace": True,
        "invisible": "keep",
    }
    config = {
        "version": 1,
        "project": {
            "name": "销售主数据 · 排序键切换预检",
            "target": "commerce-core-v2 / utf8mb4 / binary utf8 key",
            "description": (
                "合成演示：在客户、商品与旧联系人数据切换到新排序键和唯一索引之前，"
                "定位归一化碰撞、字节超限、不可见字符、异常空白和解码风险。"
            ),
        },
        "sources": [
            {
                "id": "customers",
                "type": "csv",
                "path": "customers.csv",
                "encoding": "utf-8-sig",
                "encoding_errors": "replace",
                "record_id_field": "customer_id",
                "delimiter": ",",
            },
            {
                "id": "products",
                "type": "jsonl",
                "path": "products.jsonl",
                "encoding": "utf-8",
                "encoding_errors": "replace",
                "record_id_field": "sku",
            },
            {
                "id": "legacy_contacts",
                "type": "sqlite",
                "path": "contacts.sqlite",
                "encoding": "utf-8",
                "record_id_field": "contact_id",
                "table": "contacts",
            },
        ],
        "keys": [
            {
                "id": "customer_email_ci",
                "label": "客户邮箱 · 归一化唯一键",
                "source": "customers",
                "columns": ["email"],
                "destination": "crm_v2.customer.email_sort_key",
                "description": "大小写不敏感、宽度折叠后仍需保持唯一的客户邮箱。",
                "transform": transform_ci,
                "unique": True,
                "required": True,
                "max_bytes": 64,
                "max_chars": 96,
            },
            {
                "id": "customer_name_ci",
                "label": "客户名称 · 排序键",
                "source": "customers",
                "columns": ["name"],
                "destination": "crm_v2.customer.name_sort_key",
                "description": "展示与检索用的名称排序键，不施加唯一约束。",
                "transform": transform_name,
                "unique": False,
                "required": True,
                "max_bytes": 160,
                "max_chars": 80,
            },
            {
                "id": "customer_company_city_ci",
                "label": "公司 + 城市 · 复合唯一键",
                "source": "customers",
                "columns": ["company", "city"],
                "destination": "crm_v2.customer.company_city_key",
                "description": "演示复合键使用 U+001F 连接并检测跨列碰撞。",
                "transform": transform_ci,
                "unique": True,
                "required": True,
                "max_bytes": 120,
            },
            {
                "id": "product_sku_unique",
                "label": "商品 SKU · 宽度/大小写折叠唯一键",
                "source": "products",
                "columns": ["sku"],
                "destination": "catalog_v2.product.sku_key",
                "description": "全角与大小写变体折叠后必须保持唯一。",
                "transform": {
                    "normalization": "NFC",
                    "case": "upper",
                    "width_fold": True,
                    "trim": True,
                    "collapse_whitespace": False,
                    "invisible": "remove",
                },
                "unique": True,
                "required": True,
                "max_bytes": 32,
            },
            {
                "id": "product_title_sort",
                "label": "商品标题 · 排序键",
                "source": "products",
                "columns": ["title"],
                "destination": "catalog_v2.product.title_sort_key",
                "description": "保留不可见字符用于风险展示，但生成稳定排序键。",
                "transform": transform_title,
                "unique": False,
                "required": False,
                "max_bytes": 64,
                "max_chars": 64,
            },
            {
                "id": "contact_email_ci",
                "label": "联系人邮箱 · 归一化唯一键",
                "source": "legacy_contacts",
                "columns": ["email"],
                "destination": "contact_v2.contact.email_key",
                "description": "旧联系人的邮箱唯一候选键。",
                "transform": transform_ci,
                "unique": True,
                "required": True,
                "max_bytes": 64,
            },
            {
                "id": "contact_name_company_ci",
                "label": "姓名 + 公司 · 复合唯一键",
                "source": "legacy_contacts",
                "columns": ["full_name", "company"],
                "destination": "contact_v2.contact.name_company_key",
                "description": "复合键碰撞演示。",
                "transform": transform_ci,
                "unique": True,
                "required": True,
                "max_bytes": 120,
            },
        ],
        "severity_overrides": {
            "MOJIBAKE_SUSPECT": "medium",
            "ABNORMAL_WHITESPACE": "low",
        },
        "reports": {"max_report_rows": 500},
    }
    (DEMO / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _build_readme() -> None:
    readme = """# 合成演示数据

本目录中的客户、商品、联系人名称、邮箱、公司和文本均为合成 fixture，不对应任何真实个人或组织。

- `customers.csv`：带 UTF-8 BOM 的客户 CSV；包含大小写、NFD/NFC、全角、零宽字符、NBSP、超长邮箱与空邮箱。
- `products.jsonl`：包含一行业务字节流中故意放置的非法 UTF-8 字节（位于 `description` 列，不参与任何键规则；受影响字段被标为不确定，其余键保持确定）、全角 SKU、半角假名、软连字符、双向控制符、控制字符、疑似乱码与超长标题。
- `contacts.sqlite`：只读 SQLite 演示，包含大小写碰撞、归一化碰撞、超长邮箱和双向控制符姓名。
- `config.json`：声明三个源与七条目标键规则。`reports.max_report_rows` 仅控制页面展示条数，不截断 JSON 或 SQLite 台账。

这些文件由 `tools/build_demo_fixtures.py` 确定性重建。请只把该目录用于离线演示和测试。
"""
    (DEMO / "README.md").write_text(readme, encoding="utf-8")


if __name__ == "__main__":
    build()
