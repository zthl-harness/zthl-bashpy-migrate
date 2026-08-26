# bash → Python 迁移问题分类学（6 大域 25 类）

**Migration Issue Taxonomy: 25 categories of bash → Python migration problems in 6 domains.**

> 来源：ZTHL gatekeeper 迁移 Phase 7 真实实践（`cmd_advance` 801→242 行拆分为 `gk_advance.py`，
> 2026-08-23 完成）。每类"现象 → 根因 → 解法"，是 bash→Python 迁移的对照清单，
> 也是 `zthl-bashpy-migrate` 各层检测能力的工程来源。
>
> Source: real practice from ZTHL gatekeeper migration Phase 7 (cmd_advance 801→242 lines split into
> gk_advance.py). Each category: phenomenon → root cause → solution.

---

## A. 职责边界（判定/写入/副作用三层分离） — Responsibility Boundaries

**1. 函数问题 / Monolithic function**

- **现象**: bash `cmd_advance` 800 行混合判定 + 写入 + 副作用；Python 拆成三组：纯判定（`_run_*` 系列）、状态写入（`_write_state` checksum-aware）、环境副作用（保留 bash 外壳）。
- **根因**: bash 函数无职责分离约束，随演进膨胀。
- **解法**: 三层分离模式；纯判定层保持零副作用（Paperclip pre-heartbeat 契约：`--check` 零副作用 = zthl ZH2 H9）。

**2. 子函数不可见导致恒失败 / Local-variable invisibility**

- **现象**: `_collect_advance_env` 引用 `cmd_advance` 的 `local $branch` → 空值 → `ci_trigger`/`merge_check` 恒失效。
- **根因**: bash `local` 变量不跨函数；子函数引用父函数 local = 静默空值（无报错）。
- **解法**: 显式传参（第 4 参 `$br`）。

**3. 环境副作用问题 / Environment side effects**

- **现象**: `git`/`gitnexus`/`monitor`/`wslpath` 等 Windows/WSL 边界调用留 bash；audit 子命令有副作用（写 `audit_state_result`）→ 外壳"只读收集"假设错误。
- **根因**: Python subprocess 重实现 node.exe/wslpath 链高风险；副作用位置未被识别。
- **解法**: 环境边界调用留 bash；dry_run 时跳过副作用子命令。

## B. 状态与判定语义 — State & Decision Semantics

**4. 判定问题 / Decision semantics**

- **现象**: unknown transition 在 `--force` 下是 WARN（bash L2852-2858）非 FAIL；ECC→ECC 被 I6 boundary 拦截是现状语义。
- **根因**: bash 判定分支依赖运行时标志（force）；迁移时易"顺手修复"。
- **解法**: Python 判定函数显式 force 参数；迁移**复现现状语义**而非"修复"。

**5. 字段不匹配 / Output contract fork**

- **现象**: bash 输出契约分叉——standard 用 `allowed:true`、non-standard 用 `ok:true`；entropy 阻断（standard 分支）也返回 `ok:false`（L2727）非 `allowed:false`。
- **根因**: 同一输出的字段名随分支变化，无统一 schema。
- **解法**: 断言按分支写；验证器对比时按契约映射。

**6. 状态写入问题 / State write**

- **现象**: bash `_state_write` 无 dry_run 守卫（`--check` 也写 `edit_budget`/`scheduler`）；CRLF 陷阱（Windows Python 写 `\r\n` → checksum 文件错位）。
- **根因**: bash 无零副作用契约；Windows Python 文本模式默认换行。
- **解法**: Python 统一"dry_run 零副作用"契约（改进）；写盘 `newline='\n'`。

**7. 消费空转问题 / Idle consumption**

- **现象**: I9/auto-audit/achievements/context 在外壳成功路径无条件执行，`--check` 时空转写 state（audit --state 写 audit_state_result）。
- **根因**: 成功路径的"锦上添花"写入未考虑 dry_run 语义。
- **解法**: 全部加 dry_run 守卫。

## C. 结构契约 — Structural Contracts

**8. 结构断言问题 / Structural assertion**

- **现象**: bash 字符串拼接 hint（`hint_json="${hint_json},${_hint_extras}"`）→ checklist/tool_policy/current_remote/gates 是**顶层字段**非 hint 内嵌。
- **根因**: 字符串拼接产生隐式结构，测试断言跟随字符串形态。
- **解法**: `_hint_for` 返回 `(hint, extras)` 二元组，Python 对齐顶层字段。

**9. hint 字段问题 / Hint field issues**

- **现象**: `current_remote` 有 tab/空格差异（`git remote -v` 列分隔）；`doc_budget` 重复键（doc_changes 被数组覆盖）是 bash bug。
- **根因**: 字段来源（命令输出）与 JSON 拼接方式引入差异/bug。
- **解法**: Python 修正为 int（契约改进，对比中白名单注明）。

**10. 语义问题 / Semantic correctness**

- **现象**: bash JSON 拼接可产生非法 JSON（`code_changes:['.gitignore']` 单引号）。
- **根因**: 手写字符串 JSON 无类型/语法保证。
- **解法**: Python dict 天然正确；"回归 100% 语义等价"目标修正为"判定等价 + 白名单契约改进"。

## D. 测试与验证 — Testing & Verification

**11. 测试断言问题 / Test assertion**

- **现象**: hint 断言检查 CLI 文本（ECO-SCAN/current_remote）→ 迁移后断言引用失效。
- **根因**: 断言绑定实现层（CLI 文本）而非契约层（Python 函数）。
- **解法**: 迁移后改指 `gk_advance.py`（TestAdvanceHintInjection + TestF81RemoteGate 更新）。

**12. 测试分散导致失败 / Scattered assertions**

- **现象**: 一处迁移影响多个测试文件。
- **根因**: 测试断言散布，未集中管理契约。
- **解法**: 迁移前 grep 全部断言引用点。

**13. pytest 环境差异 / Environment difference**

- **现象**: Windows pytest 下 WSL `bash -n` 读 `C:\` 路径失败（`/bin/bash: C:Users... No such file`）。
- **根因**: WSL bash 无法解析 Windows 绝对路径。
- **解法**: 改 stdin 方式（`input=内容`，无路径依赖）。

**14. pytest 缓存污染 / Cache pollution**

- **现象**: `__pycache__`/`.pytest_cache` 旧 `.pyc` 干扰测试结果。
- **根因**: 迁移后旧字节码残留。
- **解法**: 迁移后清缓存重跑。

**15. 硬编码污染 / Hardcoded environment override**

- **现象**: CLI 硬编码 `STATE_FILE` 覆盖环境变量 → 基线脚本注入无效 → 操作真实 state（rejected_edits 累积污染）。
- **根因**: 硬编码优先级高于环境注入。
- **解法**: "外部 STATE_FILE 优先于 plan 指针" + 污染清理脚本（按特征删除注入条目 + checksum 重算）。

**16. 测试脚本问题 / Test script quoting**

- **现象**: PowerShell 内联 `python3 -c` 引号地狱（ParserError）。
- **根因**: 多层 shell 转义（WSL 4-layer escape）。
- **解法**: 写临时脚本到磁盘执行，禁用内联双引号嵌套。

**17. 端到端 vs 单元 / Unit vs E2E**

- **现象**: Python 直接调 `_run()`（单元，快，纯判定）vs bash CLI 调 `.py`（端到端，需 WSL + 可控 state 注入）。
- **根因**: 单元测试绕过 main() 层，main 层错误漏检（os import 缺失）。
- **解法**: 双轨验证；main() 层单独验证。

## E. 环境与工具 — Environment & Tooling

**18. 语法问题 / Syntax precheck**

- **现象**: bash -n 预检（Windows/WSL 路径失配）；Python py_compile 预检（main 未 import os 的 NameError 单元测试漏检）。
- **根因**: 预检方式与执行环境分离。
- **解法**: bash -n 走 stdin；py_compile + main() 层单独执行验证。

**19. 语法指针问题 / Stale plan pointer**

- **现象**: plan 指针 stale（batch8 2 天）持续劫持 CLI state 路由。
- **根因**: 指针无 TTL 失效机制。
- **解法**: Phase 7b TTL 待修；测试用 STATE_FILE 注入绕过。

**20. 注释缺陷 / Stale comments**

- **现象**: 迁移后注释未更新（3.5d → 3.5d+3.5i+RED）。
- **根因**: 注释与行为解耦。
- **解法**: 迁移后同步更新注释；hint 来源标注（`_hint_for` docstring）。

**21. 可调试插桩缺失 / Debug instrumentation**

- **现象**: heredoc 异常被 `2>/dev/null` 吞 → 静默空 JSON。
- **根因**: stderr 被丢弃，失败无迹可循。
- **解法**: GK_DBG_LOG 追加 stderr；bash 外壳 `|| echo '{"error":"gk_advance_py_failed"}'` 兜底 JSON。

## F. 安全网 — Safety Nets

**22. checksum 验证 / Checksum verification**

- **现象**: state 被篡改/污染后无感。
- **解法**: `STATE_FILE_TAMPERED` 阻断 + 诊断 hint（隔离 state/竞态路径/自修复步骤）。

**23. dry_run 零副作用契约 / Zero-side-effect dry_run**

- **现象**: `--check` 也写文件。
- **解法**: 统一契约——`--check` 不写任何文件（Paperclip pre-heartbeat 依赖）。

**24. bash/Python 语义等价基线 / Semantic-equivalence baseline**

- **现象**: 迁移后无法证明等价。
- **解法**: 同 state 双跑（bash 保存 → Python 对比）JSON 语义 diff（固化快照 + 白名单）。

**25. 死代码检测三关 / Dead-code three gates**

- **现象**: 迁移后旧函数残留，测试自循环掩盖死代码。
- **解法**: gitnexus context → rg 生产入口 → plan R 表（迁移后验证消费端）。

---

## 工具映射 — Tool Mapping

| 域 | 类别 | 对应工具能力 |
|:--|:--|:--|
| A | 1, 2, 3 | `analyze`：依赖图 + local 捕获检测 + 迁移边界建议 |
| B | 4-7 | `verify`：输出契约 diff + dry_run 零副作用检查 |
| C | 8-10 | `verify`：语义等价 diff + 契约改进白名单 |
| D | 11-17 | `verify`/`audit`：基线固化 + 断言迁移清单 |
| E | 18-21 | `probe`：bash -n / py_compile 预检 |
| F | 22-25 | `audit`：死代码三关 + 写入守卫审查 + checksum 验证 |

## L3 audit 检测器映射（2026-08 扩展，zizmor 模式）

25 类迁移问题之上，L3 audit 提供确定性检测器，每条 finding 带 `severity + risk + fix`（zizmor 模式：
检测 → 分级 → 修复）。检测器 ↔ 分类学类别 ↔ 业界工具对应：

| 检测器 | 检测对象 | 分类学类别 | 业界对应 |
|:--|:--|:--|:--|
| `bomb_scan` | python3 内联（含 heredoc）/ stderr 吞错 / 危险命令 / 大小写敏感耦合 | F（安全网） | zizmor |
| `shellcheck_scan` | SC2086 裸变量展开 / SC2164 `cd` 失败 / SC2181 `$?` 反模式 / SC2034 未使用变量（TOP 子集，零外部依赖确定性移植） | D/E 交叉（静默失败面） | shellcheck |
| `python_module_deadcode` | Python 模块级未使用 import/函数（AST，零依赖） | #25 死代码三关的 Python 侧扩展 | vulture / pyflakes |
| `dead_code` | bash 函数可达性三关 | #25 | gitnexus / rg |
| `write_guard_check` | 写入函数无 dry_run 守卫（AST 扫 `*_write*`） | #6 / #23 | — |

*本文件为开发知识沉淀，与工具功能一一对应。*

*This file is engineering knowledge distilled from real migration practice; each category maps to a tool capability.*
