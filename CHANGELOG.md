# Changelog

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
