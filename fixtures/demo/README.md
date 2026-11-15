# 合成演示数据

本目录中的客户、商品、联系人名称、邮箱、公司和文本均为合成 fixture，不对应任何真实个人或组织。

- `customers.csv`：带 UTF-8 BOM 的客户 CSV；包含大小写、NFD/NFC、全角、零宽字符、NBSP、超长邮箱与空邮箱。
- `products.jsonl`：包含一行业务字节流中故意放置的非法 UTF-8 字节、全角 SKU、半角假名、软连字符、双向控制符、控制字符、疑似乱码与超长标题。
- `contacts.sqlite`：只读 SQLite 演示，包含大小写碰撞、归一化碰撞、超长邮箱和双向控制符姓名。
- `config.json`：声明三个源与七条目标键规则。`reports.max_report_rows` 仅控制页面展示条数，不截断 JSON 或 SQLite 台账。

这些文件由 `tools/build_demo_fixtures.py` 确定性重建。请只把该目录用于离线演示和测试。
