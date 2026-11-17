# 视觉混淆与脚本授权 · 合成验收数据

本目录全部为合成数据，用于验证视觉混淆预检与字节级唯一碰撞是两套独立证据。

| 文件 | 覆盖 |
|---|---|
| `strict_latin.csv` | Latin/Cyrillic `a`、混合脚本、casefold 后真正 exact 碰撞（`Straße` / `STRASSE`） |
| `authorized_mixed.csv` | 同一批值，位于显式授权的 Latin/Cyrillic 命名空间 |
| `mapping_gaps.csv` | 多码位合字 `ﬁ`、Han 脚本、exact duplicate |
| `combining.csv` | 不做 NFC 时的 NFC/NFD 组合字符差异 |

`config.json` 声明四条键规则：

- `strict_latin_key`：`strict_script`，只授权 Latin；出现 Cyrillic 即 `SCRIPT_NOT_AUTHORIZED` 阻断。
- `authorized_mixed_key`：`authorized_mixed`，显式授权 Latin + Cyrillic；字节不同的 `a` / `а` 两个键都保留，并进入人工视觉核验。
- `mapping_gap_key`：`authorized_mixed`（Latin + Han）；用于展示映射未覆盖时的未知覆盖与 unknown 风险，不签发“无视觉风险”证书。
- `combining_key`：`strict_script`（Latin）；不应用 NFC，`Café` 与 `Café` 字节不同但骨架相同。

运行：

```bash
python -m charorder run --config fixtures/visual/config.json --out out/charorder-visual --force
python -m charorder verify --run out/charorder-visual
```

预期：结论 `blocked`；字节级碰撞只出现在 `collisions.json` / 台账 `collisions` 表，
视觉候选只出现在 `visual_confusables.json` / 台账 `visual_candidates` 表。
