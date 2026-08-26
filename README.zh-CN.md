# zthl-bashpy-migrate

确定性 bash → Python 迁移验证引擎（ZTHL 框架生态工具）。

> **不做代码生成。** 生成交给 LLM；本工具负责**验证语义等价、审计副作用、检测死代码**——
> 补齐 bash2py（已死）与 AI 转换（无验证闭环）共同缺失的确定性验证层。

**English README: [README.md](README.md).**

## 背景

业界现状（2026-08 调研）：

| 方案 | 缺陷 |
|:--|:--|
| bash2py (Waterloo SANER 2015) | 唯一专门 bash→Python transpiler，**已死**；90% 翻译率但需人工介入；无语义等价验证 |
| AI/LLM 转换 (CodePorting 等) | "starting draft you must verify"——**无验证闭环**；exit-code 语义 / shell=True 注入 / word-splitting 是高频坑 |
| ast-grep/comby/tree-sitter/semgrep | 通用搜索/结构转换/静态分析，非语义迁移验证 |

`zthl-bashpy-migrate` 的独特前提：迁移发生在 bash 版与 Python 版**并存期**（bash 版被替换前），
因此可以保存 bash 版输出作为**固化快照**，之后持续对比 Python 版——语义等价可被确定性验证。

> **与业界静态审计工具的系统性对比**（zizmor / shellcheck / ruff / vulture / semgrep /
> bash2py / AI 转换）：
> [docs/industry-comparison.md](docs/industry-comparison.md)。

## 与 ZTHL 框架的关系

ZTHL（零信任自引用演化治理，[ChinaXiv:202607.00158](https://chinaxiv.org/abs/202607.00158)）
的核心思想是用"确定性、自引用、可验证"的治理闭环取代信任假设。本工具是 ZTHL 生态的
**确定性工具层**："迁移验证闭环"是 ZTHL 治理闭环的一个具体工程实例。

工具**运行时完全独立**——纯 Python 标准库，不依赖任何 ZTHL 组件。它只认迁移对象的
输入→输出 JSON 契约，不绑定任何框架特有模式。

## 三层架构

```
L1 analyze（0 API，确定性）
    bash 函数 → 依赖图（local 变量捕获 → "子函数引用父函数 local"类检测）
    + 副作用清单（文件写 / 环境调用 → dry_run 守卫缺失检测）
    + 迁移边界建议（环境副作用留 bash / 纯判定转 Python）

L2 verify（0 API，确定性，核心）
    Python 输出 vs 固化基线 JSON → 语义等价 diff（json.loads 递归比较）
    + 契约改进白名单（bash bug 修正登记）
    + dry_run 零副作用检查（--check 前后 state hash 比对）

L3 audit（LLM 兜底可选）
    死代码三关（bash 函数可达性 + Python 模块级未使用 import/函数，AST）
    + 写入路径守卫审查（AST 扫 *_write* 无 dry_run 守卫）
    + 炸弹扫描：python3 内联 / stderr 吞错 / 危险命令 / 大小写敏感耦合
      （zizmor 模式：检测 → 分级 → 修复——每条 finding 带 severity + risk + fix）
    + shellcheck TOP 子集（SC2086/SC2164/SC2181/SC2034 确定性移植——零外部依赖）
    + 未覆盖隐式语义点 → LLM 解释（无 key 时降级输出"待人工审查"清单）
```

## 安装

```bash
pip install -e .
```

依赖：Python ≥3.9，标准库 only（LLM 兜底为可选）。

## 快速开始

```bash
# 1) 迁移前：固化 bash 版基线
bashpy-migrate verify baseline --cmd "bash gatekeeper-cli.sh advance STAGE_1 --check" --out baseline.json

# 2) 迁移前：分析 bash 函数结构与副作用
bashpy-migrate analyze --script gatekeeper-cli.sh

# 3) 迁移后：验证 Python 输出 vs 固化基线（语义等价）
bashpy-migrate verify --baseline baseline.json --output result.json

# 4) 迁移后：死代码 + 写入守卫审计
bashpy-migrate audit --script gatekeeper-cli.sh --entry main --write-fns "_state_write,_write_state"
```

## 迁移问题分类学

6 大域 25 类 bash→Python 迁移问题，来自真实迁移实践（ZTHL gatekeeper 迁移 Phase 7），
每类"现象 → 根因 → 解法"：**[docs/migration-issues.md](docs/migration-issues.md)**

L3 audit 确定性检测器（炸弹扫描 / shellcheck TOP 子集 / Python 模块级死代码 / 写入守卫）与
25 类的映射见 [docs/migration-issues.md](docs/migration-issues.md)「L3 audit 检测器映射」小节。

## 验收标准

量化、可自动验证的标准，映射到各层（对齐 ZTHL gatekeeper Phase 7 验收风格：
"所有阶段过渡正确 + 100% 语义等价"）：

| 层 | 标准 | 验证 |
|:--|:--|:--|
| L1 analyze | 5 组 golden fixtures（local 捕获 / 副作用 / 混合）→ 函数提取 100% 精确（name/range/locals/calls） | `pytest tests/test_analyze.py` |
| L1 analyze | 副作用清单 100% 命中（无漏报）；迁移边界建议符合预期（纯判定→migrate / 副作用→keep-bash） | golden fixture 断言 |
| L2 verify | 语义等价 diff：白名单外 0 差异（dict key / list / 类型 / 值全对齐） | `pytest tests/test_verify.py` |
| L2 verify | dry_run 零副作用：`--check` 前后 state sha256 一致 | `dry_run_check` 测试 |
| L2 verify | 契约改进白名单：登记项永不阻塞 | whitelist 测试 |
| L3 audit | 死代码三关：已知死代码样本 100% 检出 | `pytest tests/test_audit.py` |
| L3 audit | 写入守卫：无守卫写入 100% 检出，有守卫 0 误报 | fixture 断言 |
| L3 audit | 炸弹扫描 + shellcheck TOP 子集 + 大小写敏感：确定性检出，每条 finding 带 severity+risk+fix（zizmor 模式） | `bomb_scan` / `shellcheck_scan` 测试 |
| L3 audit | Python 模块级死代码：AST 未使用 import/函数（零依赖，无 vulture/pyflakes） | `python_module_deadcode` 测试 |
| L3 audit | LLM 兜底降级：无 key → "待人工审查"清单模式 | `llm_explain` 测试 |
| 跨层 | pytest ≥28 通过；真实 bash 样本 CLI smoke（analyze + audit）0 错误 | `pytest tests -q` + CI quality job |
| 跨层 | Python 3.9-3.13 × ubuntu/windows 矩阵全绿 | GitHub Actions `test` job |

某层改动只有其对应行在 CI 变绿才算完成——对齐 batch8 规则
"Phase N 完成 = 全部验收 case 通过"。

## 许可证

[MulanPSL-2.0](https://license.coscl.org.cn/MulanPSL2)

Copyright (c) 2026 Pu Junhan
