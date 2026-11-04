# Changelog

## v0.3.2 (2026-11-04)

### 新增：SARIF 2.1.0 输出

- `audit --format sarif`：把 bomb / shellcheck / py-lint / write-guard / 死代码结果转成
  SARIF 2.1.0（GitHub code scanning / GitLab SAST / VS Code SARIF Viewer 通用）。
- **确定性**：无时间戳，rules 按 ruleId、results 按 (line, column, ruleId, message) 排序；
  同输入逐字相同输出，可直接进棘轮基线。
- **分级映射**：CRITICAL/HIGH → error，MEDIUM → warning，LOW/未标注 → note；
  函数级 finding 省略 region（不伪造行号）；`inline_inventory` 是证据清单，不进 results。
- 既有 `--format json`（默认）输出逐字不变（加性变更）。

## v0.3.1 (2026-11-04)

规则集扩展：从 shellcheck / ruff 各移植两条，并按「误报为 0 才进默认集」逐条校准。

### 新增规则

| 规则 | 来源 | 分级 | 默认 | 实测（gatekeeper-cli.sh / scripts） |
|:--|:--|:--|:--|:--|
| SC2155 声明与赋值同行吞退出码 | shellcheck | MEDIUM | ✅ | 2 命中，人工复核均真实 |
| SC2046 未引号命令替换 | shellcheck | LOW | ❌ `--strict` | 4 命中里 3 条是刻意的 `for x in $(...)` ⟹ 不进默认集 |
| E722 裸 `except:` | ruff | LOW | ✅ `--py-lint` | 15（cron_jobs 8 / cron_scheduler 5 / 测试 1 等） |
| F841 未使用局部变量 | ruff | LOW | ✅ `--py-lint` | 44（跨 scripts/*.py） |

### 精度修正（顺带）

- **heredoc 内容不再参与 shell 语法扫描**：`cat <<'EOF'` 里的 markdown `$(date -Iseconds)` 曾
  被 SC2046 误报。跳过全部 heredoc 正文后，`sc2086` 119→104、`sc2034` 104→57。
- **SC2155 正则收紧**：排除 `$((`（算术）与 `$VAR`/`${VAR}`，此前会命中 247 条绝大多数是参数默认值。
- **F841 改为全模块读集合**（含嵌套作用域）：闭包/后续函数引用同一名字不算未使用，
  假阳性 221→44；`+=`（AugAssign）与 `_` 前缀豁免。

### 新增 CLI

- `audit --strict`：启用分级建议规则（当前仅 SC2046）。
- `audit --py-lint`：Python lint 子集（E722 / F841）。

## v0.3.0 (2026-11-04)

Changes since v0.2.3。新增**内联 python 载荷清单**，并修掉两处注释假阳性——针对
gatekeeper-cli.sh 实测（96 个 payload / 45 KB）暴露的「只有行级告警、无法排序」缺口。

### 新增：`inline_inventory`（analyze + audit --bomb）

- `inventory.py::scan_inline()`：把 `python3 -c` / `python3 <<TAG` 归为四类
  （`comment` / `wrapper` / `import_probe` / `payload`），逐条给出
  `line / func / kind(single|multi|heredoc) / size / sha`，并汇总
  `by_cat / by_kind / payload_bytes`。
- 身份 = `sha1(归一化载荷)[:12]`，**不含行号** ⟹ 代码搬家不算新增（可直接做棘轮基线）。
- `analyze` 输出新增 `inline_inventory` 字段；`audit --bomb` 同时输出
  `bomb_scan`（行级巡检）与 `inline_inventory`（拆解排序）。
- 实测 gatekeeper-cli.sh：`payload=96 / payload_bytes=45142`，最大块
  `cmd_audit` 行 11137 heredoc ≈16.7 KB。

### 修正：两处注释假阳性

- `analyze.side_effects()`：跳过 `#` 注释行。此前 `# ... > out.txt` 被计为
  `file redirect write`（实测首 3 条全是注释）。
- `audit.bomb_scan()`：同样跳过注释行。此前 `# 病象：… python3 -c "…"` 被计为
  `inline_python`。

### 修正：函数区间补行号

- `extract_functions()` 新增 `line_range`（1-based）。原 `range` 是**字符偏移**，
  下游若当行号用会错位。

### 性能：`shellcheck_scan` 190× 加速

- 根因：`_sc2034_unused_issues` 对**每个**定义名各编译一条正则、再全文 `findall`
  ⟹ O(定义数 × 全文)。
- 修法：改为**单遍**合并正则（`${v}` / `$v` / `v =`）计数 + 字典统计定义次数。
- 实测 gatekeeper-cli.sh（709 KB / 12,676 行）：
  `shellcheck_scan` **51.7 s → 0.27 s**，`analyze` **3.85 s → 0.56 s**，
  `audit`（bomb + shellcheck + dead_code + py_deadcode）**56.6 s → 0.7 s**；
  输出条数不变（shellcheck total 224）。峰值内存 4.4–4.9 MB，无变化。

## v0.2.3 (2026-08-26)

Changes since v0.2.2。DSH 本地红队实测修掉 npm 包装器三个真 bug（schema 严格子集 /
Windows python 平台默认 / schema 参数名与 CLI flag 漂移），并补 README 双语 DSH 集成文档。

### npm 包装器三连修（DSH 红队实测）

- **`output.schema` 显式 `additionalProperties: true`**: dsh-tools 作者侧 schema 子集强制
  object 节点必须显式声明 `additionalProperties: true|false`，缺失直接 `JsonSchemaError`
  导致插件 boot 失败（本地 `dsh --profile web` 实测抓到）。
- **engine 默认解释器按平台**: `runAudit` 默认 `python3` 在 Windows（只有 `python` 命令）
  execute 必挂——改为 `BASHPY_PYTHON` 覆盖优先、否则按平台（win32=python）。
- **`auditArgv` 统一 `py_deadcode`（蛇形）**: schema 暴露 `py_deadcode` 而 engine 解构
  `pyDeadcode`（驼峰），`execute` 透传 args 导致 `--py-deadcode` 永不触发——统一为蛇形
  并对齐 schema 参数名。
- **`toolSpec` 纯数据导出 + dsh-tools 改动态 import**: 未安装 peer 也可直接测 schema；
  `index.test.mjs` 7 用例（新增 schema 子集 / 平台默认 / 参数名零漂移回归）。

### 文档与验证

- **README 双语 DSH 集成章节**: `README.md` / `README.zh-CN.md` 新增「DSH Integration
  (npm bundle)」——本地 tarball 安装（零公共 registry 投毒面）、供应链对账
  （`config.integrity` 强制 + `npm view dist.integrity` 比对）、`bashpy_migrate_scan` 调用方式。
- **本地 DSH 全链路验证**: `dsh plugin add <tarball>` → bundle 层注入组合配置 → 真实
  dsh-tools `defineTool` 注册 → 三层扫描（bomb / shellcheck / py_deadcode）实测命中。

### 版本号

- **Version 0.2.3**: `pyproject.toml` + `__init__.py` + npm `package.json` 三处同步。

## v0.2.2 (2026-08-26)

Changes since v0.2.1。新增 DSH（DeepSeek Harness）npm 包装器 + 发布包供应链防护 +
版本同步修复。

### DSH npm 包装器

- **`@zthl-harness/dsh-bashpy-migrate` bundle**: `npm/dsh-bashpy-migrate/` —
  package.json 声明 `dsh.bundle.patch`（cordis.patch.yml 注入 `bashpy-migrate` 行），
  `index.js` 用 `defineTool` 注册 `bashpy_migrate_scan`（bomb / shellcheck / py_deadcode
  / explain），subprocess 透传插件 CLI（引擎零改动）；`engine.js` 抽离纯逻辑
  （argv 构造 + execFile + JSON 解析），无 DSH 运行时也可单测（node:test 3 用例）。
  peer 依赖 `@deepseek-ai/dsh-tools ^0.1.1-rc.2`（宿主提供，不重复安装）。

### 发布包供应链防护

- **npm-supply-chain CI job**（ci.yml）: 插件自己发 npm 包 → 自身 CI 必须检测投毒。
  `scripts/npm-bundle.sh` 构建 tarball + 计算 `sha512-` integrity（内容确定性）+
  `package-lock.json` 依赖 pin，产出 `npm-integrity.json` 资产；同时跑 node adapter
  测试 + 校验 pack 只含声明的 4 个文件。release.yml build job 把 tgz + integrity
  并入发布资产——skill 侧 `gk_plugin_manifest` 对 `url: npm:` 强制 `config.integrity`
  对账，发布后 `npm view <pkg>@<ver> dist.integrity` 与本地 hash 比对即检测 registry
  投毒（对齐 zizmor 供应链审计哲学：无对账 = 无防御）。

### 版本同步修复

- **`__version__` 同步**: `zthl_bashpy_migrate/__init__.py` 0.1.0 → 0.2.2（CLI
  `--version` 与 loader 显示与 pyproject 一致，dev loader 不再误报 0.1.0-dev）。

### 版本号

- **Version 0.2.2**: `pyproject.toml`（`[project] version = "0.2.2"`）+ npm 包装
  `package.json` version 0.2.2。

## v0.2.1 (2026-08-26)

Changes since v0.2.0。CLI audit 补齐三层聚合——本地调用（`audit --bomb --shellcheck --py-deadcode`）
真正三层全部生效；`--explain` 聚合升级覆盖 groups 嵌套 finding。

### CLI 三层聚合

- **`audit --shellcheck` / `audit --py-deadcode`**: shellcheck TOP 子集与 Python 模块级
  死代码从函数层暴露到 CLI 契约，与 `--bomb` 一次同报三层；skill 侧 `_plugin_sc_counts`
  直连 import 与 gk_audit_depth 拆分调用的现状可统一走 CLI。30 测试全过
  （自 v0.2.0 的 28 → 30）。
- **`--explain` groups 展平** (`320c4a8`): LLM 兜底清单从 candidates/issues 扩展到
  bomb/shellcheck 的 groups 嵌套 finding——原代码只收 candidates/issues，炸弹 finding
  从未进过 LLM 解释。

### 分类学与自述

- **L3 audit 检测器映射** (`521c25d`): migration-issues.md 新增「L3 audit 检测器映射」
  小节——5 检测器（bomb_scan / shellcheck_scan / python_module_deadcode / dead_code /
  write_guard_check）↔ 25 类 ↔ 业界工具（zizmor / shellcheck / vulture / pyflakes）；
  README 双语分类学章节补指引。

### 版本号

- **Version 0.2.1**: `pyproject.toml`（`[project] version = "0.2.1"`）。

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
