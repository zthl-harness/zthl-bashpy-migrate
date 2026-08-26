# Changelog

## v0.2.0 (2026-08-26)

Changes since v0.1.0。L3 audit 从"迁移炸弹扫描"升级为**统一 bash+python 确定性静态审计引擎**。

### L3 audit 能力扩展

- **大小写敏感检测 + zizmor 式修复三件套** (`f85ecf7`): 新增 `case_sensitive`（camelCase
  值耦合，如 `= "False"` 依赖 python bool repr 大写）与 `case_sensitive_const`（ALL_CAPS
  常量/环境变量名，大小写是语义一部分，勿归一化）两类规则、分开给修复方法；`bomb_scan`
  每条 finding 升级为 **severity + risk + fix**（检测 → 分级 → 修复，对齐 zizmor 模式）。
- **shellcheck TOP 子集确定性移植** (`e108315`): `shellcheck_scan()` 零外部依赖实现
  sc2086（行级引号状态机 + 命令替换跳过）/ sc2164 / sc2181 / sc2034（常量/META 契约豁免）；
  python 内联/heredoc 内容跳过（归 bomb_scan.inline_python 管）。实测 gatekeeper-cli.sh：
  sc2086 70 / sc2034 55 / sc2181 1——确定性替代外部 shellcheck binary 的 L3.5 gate1 信号源。
- **python_module_deadcode** (`097aa98`): AST 模块级未使用 import/函数（零依赖，
  无 vulture/pyflakes），吸收 gk_audit_depth 能力——插件成为统一 bash+python 静态引擎。
  28 测试全过（自 v0.1.0 的 19 → 28）。

### 版权与自述

- **MulanPSL-2.0 版权头全量** (`3a3a941`): 10 文件对齐 spz2glb 格式。
- **README 更新 + Copyright 署名** (`219784f`): 三层架构 L3 段、验收标准（+2 行新能力、
  pytest ≥28）、License 段补 `Copyright (c) 2026 Pu Junhan` 署名行。

### CI 供应链

- **release.yml 权限最小化 + action pin 修正** (`848a336`): `contents: write` 过宽→仅
  release job 授权；`download-artifact@v5` 与 `action-gh-release@v3.0.2` 改 peeled hash
  （zizmor 在线拦截 `excessive-permissions` / `ref-version-mismatch`）。

## v0.1.0 (2026-08-24)

Changes since 初始提交 (`242eb35`)。首个发布版本，tag `v0.1.0`。

### 初始版本

- **bash → Python 确定性迁移校验引擎** (`242eb35`): `analyze` / `verify` / `audit` 三命令。
  `analyze` 静态解析 bash 脚本（函数依赖/变量作用域），`verify` 做基线语义等价校验，
  `audit` 做死代码三关 + 迁移炸弹扫描（inline python / stderr swallow / dangerous command / fd redirect）。
  纯 Python 3.9+，MulanPSL-2.0 开源协议。
- **门卫式 CI 管线** (`242eb35` / `3e9061e` / `73b0ad9`): 裁剪自 spz-gatekeeper ci-pipeline-template——
  多版本 × 多 OS 测试矩阵、quality CLI 冒烟、security-audit（actionlint + zizmor + D 类 T1059 危险命令扫描）、
  encoding-defense（L1 BOM / L2 CRLF，配 `.gitattributes` 强制 LF）。

### CI 供应链加固

- **打 tag 版本更新日志机制** (`0e7d872`): 复刻 spz2glb 发布模式——`CHANGELOG.md` 结构化版本日志 +
  `scripts/changelog-check.sh` 覆盖门禁（tag 前验证自上一 tag 的每个 commit 都被 CHANGELOG 覆盖，
  squash PR 按 `(#N)` 匹配、直接 commit 回退关键词、`docs:` 自文档豁免）+
  `.github/workflows/release.yml`（tag `v*` → gate → 构建 wheel/sdist → `action-gh-release` 自动生成 release notes）。
  首个 tag `v0.1.0` 已发布。
- **release.yml 权限最小化 + action pin 修正** (`release.yml`): zizmor 在线拦截
  `excessive-permissions`（全局 `contents: write` 过宽，改为仅 release job 授权）+
  两处 `ref-version-mismatch`——`download-artifact@v5` 实为 `634f93cb`（门卫也带同错注释）、
  `action-gh-release@v3.0.2` 是 annotated tag，pin 必须用 peeled commit `3d0d9888`。
- **zizmor workflow 供应链审计** (`3b9cd7d` / `73b0ad9`): 首次 CI 即拦截 `artipacked`
  （checkout 缺 `persist-credentials: false`，4 处修复）；升级在线模式（`--gh-token`）后拦截
  `ref-version-mismatch`——checkout pin `0ad4b8fa` 注释写 v4.2.2 但实为 v4.1.4，
  升级到 v4.2.2 真实 hash `11bd7190`。离线校验不了的 hash→版本对应，在线 API 查实。
- **跨平台矩阵** (`3e9061e` / `df5cc69`): 复刻 spz2glb release.yml 的 windows/ubuntu/macos 布局，
  macOS 双 runner（`macos-latest` = 15 + `macos-14`；`macos-15`/`macos-15-intel` 不在可用标签，
  显式 15 系仅付费 xlarge/large/xl）。全矩阵 4 OS × 6 py = 24 job。

### 可观测性

- **调试 JSON 报告** (`3e9061e`): 复刻 spz2glb `wasm_hash_report.json` 模式——`report` job 生成
  `test-report.json`（每用例耗时/结果 + 环境 + 汇总）与 `cli-report.json`（analyze/audit 真实输出 + 退出码），
  upload-artifact 下载即看，无需翻 Actions 页面。pytest junit 聚合属性在 `<testsuite>` 子元素
  （根是 `<testsuites>`），本地模拟先验抓出 summary=0 的解析 bug。
- **ci-status.sh** (`3e9061e`): 复刻门卫 `ci-status.sh`——curl + python3 拉取远端 CI run 列表
  （RUN_ID/STATUS/RESULT/BRANCH/TITLE），无依赖快速巡检。

### 版本号

- **Version 0.1.0**: `pyproject.toml`（`[project] version = "0.1.0"`）。
