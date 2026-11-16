# 字序迁核台 · charorder

**文本编码、Unicode 规范化与目标排序键迁移前的离线预检工具。**

字序迁核台读取本地 CSV、JSONL、SQLite 中的文本列，按 JSON 中声明的目标键规则计算迁移后的排序键，并在真正修改数据库之前定位：

- 归一化、大小写折叠、宽度折叠之后的**唯一键碰撞**；
- 目标索引键的 **UTF-8 字节数 / 字符数超限**；
- 零宽字符、软连字符、双向文本控制符、控制字符等**不可见字符风险**；
- NBSP、全角空格、制表符、连续空白、首尾空白等**异常空白**；
- 非法字节序列、`U+FFFD` 替换字符、疑似乱码等**解码风险**；
- 缺失必需值、空键、复合键分隔符歧义、非文本值强制转写等结构问题。

输出风险清单、逐键结果、碰撞组、迁移计划、SQLite 审计台账、JSON / Markdown 报告和**自包含只读 HTML 复核页**。

工具完全离线，只依赖 Python 3.10+ 标准库。

---

## 1. 快速开始

不需要安装第三方运行期依赖。在项目根目录执行：

```bash
# 生成完整演示（合成数据，内置 3 个源、7 条键规则）
python -m charorder demo --out out/charorder-demo --force

# 校验产物哈希、SQLite 台账与 HTML 自包含性
python -m charorder verify --run out/charorder-demo

# 中断的整批发布恢复：前滚已验证新版本，或回退保留旧版本
python -m charorder recover --run out/charorder-demo --policy rollback

# 启动只读复核页（仅 GET/HEAD，仅回环地址）
python -m charorder serve --run out/charorder-demo
```

打开 `out/charorder-demo/report.html` 也可以直接离线查看，页面不引用任何外部 CSS、字体、图片或脚本。

执行测试：

```bash
python -m unittest discover -s tests -v
```

可选的本地安装：

```bash
python -m pip install --no-deps -e .
charorder demo --out out/charorder-demo --force
```

`pyproject.toml` 仅用于本地安装入口；运行期不下载依赖。

---

## 2. 项目定位

**这是：**

- 纯本地、完全离线、配置驱动的文本列迁移预检工具；
- 输入本地 CSV / JSONL / SQLite 与 JSON 配置；
- 面向“旧库文本字段切换到新库 / 新排序规则 / 新唯一键之前”的只读检查；
- 对每条声明键生成可审计的目标排序键、哈希、字节长度和来源追溯；
- 输出可复核、可测试、可归档的风险证据。

**这不是：**

- 数据库迁移执行器：不执行 `UPDATE` / `INSERT` / `DELETE`，不创建生产索引；
- 通用 ICU collation 实现：业务排序语义被固定为 binary UTF-8 键，结果不依赖系统 locale；
- 编码自动嗅探器：编码必须显式声明，工具不猜测；疑似乱码只报告，不自动修复；
- 爬虫、RPA、数据湖、抽样、脱敏、血缘、指标口径、慢查询或监控系统；
- 在线协作平台：没有写接口，不提供数据编辑能力。

---

## 3. 目录结构

```text
charorder/
├── charorder/                 # 标准库实现
│   ├── config.py              # 严格配置校验与路径解析
│   ├── ingest.py              # CSV / JSONL / SQLite 只读读取
│   ├── transforms.py          # 宽度折叠、Unicode 规范化检测与文本分析
│   ├── engine.py              # 键计算、碰撞检测、风险汇总
│   ├── planner.py             # 确定性迁移计划与门禁
│   ├── ledger.py              # SQLite 审计台账（原子写与只读 run_id 查询）
│   ├── report.py              # Markdown + 自包含 HTML
│   ├── artifacts.py           # 运行编排、隔离暂存、整批发布与故障恢复
│   ├── verify.py              # 跨产物 run_id、哈希、台账、发布状态与 HTML 校验
│   ├── server.py              # 回环地址只读复核服务器
│   └── cli.py                 # 命令行入口（run / demo / verify / recover / serve）
├── fixtures/demo/             # 合成客户 / 商品 / 联系人数据
├── tools/build_demo_fixtures.py
├── tests/                     # 104 个 unittest 用例
├── pyproject.toml
└── out/                       # demo 运行产物（可重建）
```

---

## 4. 处理流水线

对每条目标键：

1. 按需移除 `Cf` 类不可见格式字符；
2. 宽度折叠：仅将 East Asian Width 为 `F` / `H` 的字符做 NFKC 宽度形式折叠；
3. 应用声明的 Unicode 规范化：`NFC` / `NFD` / `NFKC` / `NFKD` / `none`；
4. 应用大小写映射：`casefold` / `lower` / `upper` / `none`；
5. 如启用，则将全部 Unicode 空白折叠为单个 ASCII 空格；
6. 如启用，清理首尾空白；
7. 单列直接成为目标键；复合列使用 `U+001F`（unit separator）连接；
8. 计算 UTF-8 字节数、字符数、SHA-256、转义展示值，并执行碰撞与长度检查。

规范化结果、变换后的排序键和原始值都会写入 `keys.jsonl` 与 SQLite 台账。

> 排序键的字节序为 UTF-8 binary 顺序。工具不会模拟数据库 ICU/collation 的实际比较规则；目标库应按计划声明使用 binary 键语义。

### 为什么不用通用 NFKC 代替宽度折叠？

`NFKC` 同时会折叠“①”“ﬁ”等兼容字符，而宽度折叠通常只应处理全角 ASCII、全角空格、半角片假名等宽度形式。本项目对 East Asian Width 为 `F` / `H` 的连续片段做 NFKC，避免把无关的兼容字符静默改写。若业务明确需要更广的兼容折叠，可在配置中直接选择 `NFKC`。

---

## 5. 配置

完整示例见 [`fixtures/demo/config.json`](fixtures/demo/config.json)。

### 5.1 顶层

```json
{
  "version": 1,
  "project": {
    "name": "销售主数据 · 排序键切换预检",
    "target": "commerce-core-v2 / utf8mb4 / binary utf8 key",
    "description": "可选说明"
  },
  "sources": [],
  "keys": [],
  "severity_overrides": {
    "ABNORMAL_WHITESPACE": "low"
  },
  "reports": {
    "max_report_rows": 500
  }
}
```

- `version`：固定为 `1`。
- `severity_overrides`：按检查码覆盖默认级别，只接受 `high` / `medium` / `low`。
- `reports.max_report_rows`：仅限制 HTML / Markdown 页面展示条数；`findings.json`、`keys.jsonl` 与 SQLite 台账始终保留全量结果。

### 5.2 源

```json
{
  "id": "customers",
  "type": "csv",
  "path": "customers.csv",
  "encoding": "utf-8-sig",
  "encoding_errors": "replace",
  "record_id_field": "customer_id",
  "delimiter": ","
}
```

```json
{
  "id": "products",
  "type": "jsonl",
  "path": "products.jsonl",
  "encoding": "utf-8",
  "encoding_errors": "replace",
  "record_id_field": "sku"
}
```

```json
{
  "id": "legacy_contacts",
  "type": "sqlite",
  "path": "contacts.sqlite",
  "record_id_field": "contact_id",
  "table": "contacts"
}
```

- 路径相对配置文件所在目录解析，也支持绝对路径；路径必须指向现有普通文件。
- `record_id_field`：CSV 列名、JSONL 顶层字段名、SQLite 列名。缺失时仍保留记录并按行号审计，同时产生 `MISSING_RECORD_ID`。
- `encoding_errors`：`replace`（默认，替代为 `U+FFFD` 后继续）或 `strict`（遇到非法字节直接报错退出）。
- CSV 支持 `delimiter` / `quotechar`；JSONL 每行必须是顶层 JSON 对象。
- SQLite 只读打开：URI `mode=ro` + `PRAGMA query_only=ON`，只查询规则引用的列；`TEXT` 按 UTF-8 解码。
- 工具不写回任何源文件；源文件 SHA-256 会写入计划与台账。

### 5.3 目标键

```json
{
  "id": "customer_email_ci",
  "label": "客户邮箱 · 归一化唯一键",
  "source": "customers",
  "columns": ["email"],
  "destination": "crm_v2.customer.email_sort_key",
  "description": "大小写不敏感的唯一候选键",
  "transform": {
    "normalization": "NFC",
    "case": "casefold",
    "width_fold": true,
    "trim": true,
    "collapse_whitespace": true,
    "invisible": "remove"
  },
  "unique": true,
  "required": true,
  "max_bytes": 64,
  "max_chars": 96
}
```

- `columns`：单列或复合列；复合键按顺序以 `U+001F` 连接。
- `normalization`：`none` / `NFC` / `NFD` / `NFKC` / `NFKD`。
- `case`：`none` / `casefold` / `lower` / `upper`。
- `width_fold`：是否对 East Asian Width `F/H` 片段做宽度折叠。
- `invisible`：`keep` 或 `remove`；无论哪种策略，原始值中的不可见字符都会产生风险项。
- `trim` / `collapse_whitespace`：首尾清理 / 将全部 Unicode 空白折叠为空格。
- `unique`：仅唯一键执行碰撞检测。
- `required`：为 `true` 时，任一分量为 `null` 即产生高等级 `REQUIRED_VALUE_MISSING`，且不参与碰撞检测。
- `max_bytes` / `max_chars`：对变换后的 UTF-8 字节数 / 字符数设置上限，可为 `null`。
- `destination`：仅供计划和报告展示的目标表 / 列说明，不会被执行。
- 空白字符串（`""` 或变换后为空）会产生 `EMPTY_KEY`，但仍然是一个可碰撞的键值。是否把空串视为非法，由业务在迁移处置中决定。

### 5.4 复合键分隔符

复合键固定使用 ASCII Unit Separator `U+001F`。若某个变换后的分量本身包含该字符，会生成高等级 `COMPOSITE_SEPARATOR` 风险，避免静默产生歧义键。

---

## 6. 输出产物

每次 `run`（或 `demo`）生成一个独立目录：

| 文件 | 内容 |
|---|---|
| `report.html` | 自包含只读复核页：摘要、源指纹、规则矩阵、碰撞组、可筛选风险清单、计划、边界声明 |
| `report.md` | 便于归档和代码评审的 Markdown 摘要 |
| `plan.json` | 确定性迁移计划、规则就绪度、门禁、禁止动作、输入哈希 |
| `plan.md` | 迁移计划的人类可读版本 |
| `findings.json` | 全量风险清单、严重级别和检查码计数 |
| `collisions.json` | 全量碰撞组及参与者 |
| `keys.jsonl` | 每条记录 × 每条规则的原始值、目标键、转义值、字节数、哈希、缺陷与碰撞组 ID |
| `ledger.sqlite` | 可查询的审计台账（含 runs / sources / rules / records / key_results / findings / collisions / collision_members 及视图） |
| `manifest.json` | 运行清单：产物哈希、计划哈希、源指纹、复跑命令 |

默认输出目录为 `charorder-runs/<run-id>/`；显式传入 `--out` 可指定位置。目录非空时默认拒绝写入，需用 `--force` 覆盖已知产物名。工具不会清理目录中的未知文件。

### 6.1 整批发布与故障恢复（`--force` 覆盖语义）

单个文件的原子替换不足以保证一次 `--force` 覆盖的整套证据同时切换。本工具把每次运行的九件产物构建在**隔离暂存目录**中，全套通过 `verify_run` 后，才经一次**符号链接原子翻转**整体发布，因此审核人员在任何时刻只能看到一套完整、自洽的版本，绝不会看到“旧 manifest 配新文件”的半版结果。

整批发布的目录布局：

```
<run-dir>/
  report.html ... manifest.json     # 根目录为不可变符号链接农场，全部指向当前版本
  .charorder/
    current                          # 原子翻转的发布指针 -> ../releases/<run-id>
    journal.json                     # 持久发布状态机（current / pending）
    events.log                       # 仅追加的审计事件日志（JSON Lines）
    publish.lock                     # 跨进程发布锁（flock）
    releases/<run-id>/               # 完整、已验证、不可变的发布版本
    staging/<s-id>/                  # 隔离的未发布产物，外部入口不可见
    quarantine/                      # 中止或未发布的证据，保留可复核
```

发布与恢复保证：

- **中断时无半版可见**：暂存阶段（部分 JSON/Markdown 已写、或普通产物写全但 SQLite 未替换）崩溃时，当前版本保持不变，未完成产物只存在于 `staging/`；恢复时只能中止并隔离，审核人员继续看到旧版本。
- **新版本失败不丢失旧版本**：全套新产物（含 SQLite 与新 manifest）已验证但尚未发布时崩溃，旧版本仍是当前版本；旧版本同时保留在 `releases/` 下可独立复核。
- **切点 3 的两种合法恢复选择**：
  - `recover --policy rollforward`（或环境变量 `CHARORDER_RECOVERY_POLICY=rollforward`）：重新验证全套新产物后前滚发布；
  - `recover --policy rollback`（默认）：保留旧版本为当前版本，把未发布的新版本隔离到 `quarantine/`。
  两种选择都会在 `journal.json` 与 `events.log` 中留下可追溯记录；前两个切点不允许前滚，只能继续展示旧版本。
- **重复 `--force` 保持同版**：相同输入派生相同 `run_id`，已验证的发布版本逐字节复用，不生成混合版或重复版本，也不会遗留看似有效的旧 manifest 配新文件。
- 每次 `run` 启动时会先在发布锁内完成恢复，再处理新事务；`verify` 检测到未完成的整批发布时照常校验当前版本并给出告警（退出码 `3`），提示先运行 `recover`。
- 旧版扁平目录（文件直接位于运行根目录）仍可被 `verify` 只读校验；首次对其 `--force` 重跑时会先经完整性验证再纳入整批发布布局，事件记录为 `adopted_legacy_layout`。

### 6.2 SQLite 台账查询示例

```bash
sqlite3 out/charorder-demo/ledger.sqlite \
  "SELECT severity, code, COUNT(*) FROM findings GROUP BY severity, code ORDER BY 1,2;"
```

```sql
-- 找出某个规则的全部碰撞参与者
SELECT k.record_ref, k.record_id, k.raw_display, k.target_key
FROM collision_members m
JOIN key_results k ON k.key_result_id = m.key_result_id
WHERE m.group_id = 'C-...';
```

台账中的 `finding_counts` 与 `collision_summary` 是只读视图。

---

## 7. 检查码

| 检查码 | 默认级别 | 含义 |
|---|---|---|
| `SOURCE_INVALID_BYTES` | high | 源文件含无法按声明编码解码的字节 |
| `SOURCE_PARSE_ERROR` | high | JSONL 行解析失败或 CSV 解析中断 |
| `SOURCE_ROW_MISMATCH` | high | CSV 行列数多于表头 |
| `MISSING_RECORD_ID` | medium | 记录标识列 / 字段为空 |
| `DUPLICATE_RECORD_ID` | high | 源内记录标识重复，碰撞归属不可靠 |
| `REQUIRED_VALUE_MISSING` | high | 必需键分量为 `null` |
| `EMPTY_KEY` | medium | 变换后的键为空 |
| `INVISIBLE_CHARACTER` | medium | `Cf` 类不可见格式符（ZWSP、软连字符、BOM 等） |
| `ABNORMAL_WHITESPACE` | medium | NBSP、全角空格、制表符、连续空白、首尾空白、全空白 |
| `CONTROL_CHARACTER` | high | 非空白 C0/C1 控制字符 |
| `BIDI_CONTROL` | high | 双向文本控制符 |
| `REPLACEMENT_CHARACTER` | high | 文本含 `U+FFFD` |
| `SURROGATE_CHARACTER` | high | 孤立 UTF-16 代理码位 |
| `MOJIBAKE_SUSPECT` | medium | UTF-8 / 拉丁编码错配的典型乱码片段，仅报告不修复 |
| `NON_TEXT_VALUE` | medium | 数字、数组、对象等非文本值被强制转写 |
| `KEY_TOO_LONG_BYTES` | high | 目标键 UTF-8 字节数超限 |
| `KEY_TOO_LONG_CHARS` | high | 目标键字符数超限 |
| `COMPOSITE_SEPARATOR` | high | 变换后的分量含保留分隔符 `U+001F` |
| `NORMALIZATION_COLLISION` | high | 不同原始值经变换后落入同一唯一键 |
| `DUPLICATE_KEY` | high | 原始值本身相同，仍形成唯一键重复 |

可在配置的 `severity_overrides` 中逐项覆盖。

---

## 8. 结论、门禁与退出码

报告结论：

- `blocked`：存在高等级风险，暂不建议迁移；
- `review`：无高等级，但存在中等级问题；
- `pass_with_notes`：仅剩低等级提醒；
- `pass`：未发现风险。

CLI 默认只生成报告，不因风险返回失败。适合 CI 的门禁方式：

```bash
python -m charorder run --config my-config.json --out out/gate --fail-on high
```

- `--fail-on high`：存在 high 风险时退出码 `1`；
- `--fail-on medium`：high 或 medium 时退出码 `1`；
- `--fail-on low`：任何风险时退出码 `1`；
- `--fail-on none`（默认）：发现风险也返回 `0`，仅配置 / 输入 / 输出错误返回 `2`。
- `verify` 校验通过返回 `0`、校验失败返回 `2`；当前版本完整但存在未完成的整批发布时返回 `3`（结论仍可复核，需运行 `recover`）。
- `recover` 成功处理（含“无待恢复事务”）返回 `0`，配置 / 输出错误返回 `2`。

建议把“高等级发现为 0”和“碰撞组为 0”作为唯一索引创建前的硬门禁。

---

## 9. 可复现性与完整性

- 运行 ID 由以下内容派生：工具版本、Unicode 数据库版本、配置 SHA-256、每个源文件的 SHA-256 与大小；相同输入得到相同运行 ID。
- `plan.json`、`plan.md`、`findings.json`、`collisions.json`、`keys.jsonl` 不写墙钟时间；同输入重复运行内容一致。`report.*`、`manifest.json` 和台账记录实际生成时间。
- 计划中登记每个源文件的 SHA-256；迁移窗口内输入或规则发生变化即失去可复现条件。
- `python -m charorder verify --run <dir>` 会校验：
  - manifest 内所有产物的大小与 SHA-256；
  - `plan.json` 哈希与 `run_id`；
  - `findings.json`、`collisions.json`、`keys.jsonl` 与 SQLite 台账的 `run_id` 全部与 manifest 一致，且 `keys.jsonl` 行数与汇总计数一致；
  - manifest 与 `plan.json` 的来源摘要（`source_fingerprints`）一致；
  - SQLite `integrity_check`、`user_version`、行数与汇总计数，且台账只含单一 `run_id`；
  - 整批发布布局下，根目录每个链接、`.charorder/current` 与 `journal.json` 登记版本三者一致（杜绝新旧拼接）；
  - HTML 为 UTF-8 自包含页面，无外部脚本 / 样式 / 图片 / `@import`；
  - manifest 声明源文件只读、无网络访问。
- 篡改任一产物、混用两个版本的文件、或让发布指针与日志登记版本不一致，`verify` 都会失败。

---

## 10. 只读复核服务器

```bash
python -m charorder serve --run out/charorder-demo --port 8765
```

- 仅允许绑定 `127.0.0.1` / `localhost` / `::1`；
- 仅支持 `GET` / `HEAD`，写方法返回 `405`；
- 仅公开运行目录白名单中的产物，路径穿越与未知文件返回 `404`；
- 启动前先执行完整性校验；
- 返回 `Content-Security-Policy`、`nosniff`、`no-referrer`、`no-store`；
- 不应把它部署到公网，也不提供任何上传或编辑入口。

---

## 11. 演示数据

`fixtures/demo/` 全部为合成数据，不对应真实个人或组织，由 `tools/build_demo_fixtures.py` 确定性生成。演示覆盖：

- CSV：UTF-8 BOM、NFC/NFD 变体、全角名称、零宽空格、NBSP、超长 / 空邮箱；
- JSONL：故意写入的非法 UTF-8 字节、全角 SKU、半角片假名、软连字符、双向控制符、响铃控制字符、疑似乱码、超长标题、缺失记录标识；
- SQLite：大小写碰撞、归一化碰撞、超长邮箱、双向控制符姓名。

重建 fixture：

```bash
python tools/build_demo_fixtures.py
```

演示运行预期结论为 `blocked`，包含高、中、低风险与多个碰撞组，因此在 `--fail-on high` 下退出码为 `1`；这是有意的负面演示。

---

## 12. 测试

```bash
python -m unittest discover -s tests -v
```

104 个标准库 `unittest` 用例覆盖：

- 宽度折叠、NFC/NFD、casefold、不可见字符策略、空白折叠与管线顺序；
- 不可见 / 双向 / 控制 / 替换 / 代理 / 乱码 / 空白检测；
- 配置字段、错误路径、重复 ID、未知检查码；
- CSV BOM、非法字节替换与严格模式、JSONL 坏行续跑、SQLite 只读与元数据解码；
- 大小写 / 全角 / 规范化碰撞、复合键碰撞、重复记录标识、空键、必需值缺失、超限；
- 计划确定性、产物哈希、源文件未被修改、SQLite 台账计数与视图；
- 自包含 HTML、无外部资源、XSS 转义；
- CLI 退出码、`verify` 篡改检测；
- 只读服务器 GET/HEAD/405/404 与绑定限制；
- 整批发布与故障恢复（`tests/test_recovery.py`，子进程注入真实进程中断）：三个切点下无半版可见、B 失败后 A 仍有效、前滚 / 回退恢复可审计、重复 `--force` 同版、提交窗口崩溃的失效安全、旧扁平布局纳管与新旧拼接检测。

测试使用临时目录，不会修改演示 fixture。

---

## 13. 已知边界

- 所有源记录会一次读入内存；本工具面向迁移前检查，不是超大表的流式扫描器。
- SQLite 源哈希基于主数据库文件；正在使用 WAL 的数据库应在稳定快照或 checkpoint 后检查，并确保 `-wal` 不会被并发写入。
- 宽度折叠只处理 East Asian Width `F/H` 片段，不是完整 NFKC；需要更广兼容折叠时显式选择 `NFKC`。
- 大小写映射基于运行时 Python 的 Unicode 数据，不使用数据库 collation 或系统 locale。运行 ID 包含 Unicode 版本。
- 碰撞检测按 UTF-8 二进制键精确分组；不提供模糊匹配、编辑距离、拼音或语音近似。
- 不自动判断哪个碰撞参与者应保留；不会自动合并、删除、修复乱码或改写源数据。
- SQLite 台账和报告会包含原始值及部分上下文，仅适合在受控本地环境处理合成或已获授权的数据。

---

## 14. 规划中的边界声明

迁移放行前建议按 `plan.json` 的顺序执行：

1. 冻结输入、配置与计划哈希；
2. 固化目标键变换与 binary UTF-8 语义；
3. 清除解码、缺失、超限阻断项；
4. 逐组人工仲裁唯一键碰撞；
5. 处理不可见字符与异常空白；
6. 在独立影子库生成键并做旧新排序对比；
7. 用 `--fail-on high` 复跑，门禁通过后再切换。

工具本身只提供证据，不执行这 7 步中的任何数据库写操作。
