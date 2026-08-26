# 与业界同类项目的系统性差异（2026-08-26）

> 定位一句话：zthl-bashpy-migrate = **确定性 bash→Python 迁移验证引擎**（L2 verify 语义等价闭环）
> + **统一 bash+python 确定性静态审计引擎**（L3 audit，zizmor 式检测→分级→修复）。
> 业界没有任何工具同时提供"迁移验证闭环"与"双语言静态审计"，本插件是两者的交集。

## 1. 对比矩阵

| 工具 | 语言/范围 | 确定性 | 外部依赖 | 迁移验证闭环 | 修复建议 | 与插件关系 |
|:--|:--|:--|:--|:--|:--|:--|
| **zthl-bashpy-migrate** | bash+python 源码 + 迁移语义 | ✅ 纯确定性（0 API 门禁） | 零（标准库 only） | ✅ L2 verify 基线对比 | ✅ 每条 finding 带 fix | — |
| **bash2py**（Waterloo SANER 2015） | bash→Python 转译 | ❌ 90% 翻译率需人工 | — | ❌ | ❌ | 已死；插件不做转译，只验证 |
| **AI/LLM 转换**（CodePorting 等） | 通用代码转换 | ❌ 随机 | 模型服务 | ❌ "you must verify" | ❌ | 插件填补其缺失的验证闭环 |
| **zizmor**（Rust） | GitHub Actions YAML | ✅ | 无 | ❌ | ✅（severity/risk/fix） | **模式同源**：检测→分级→修复；但范围是 workflow YAML，非源码审计 |
| **shellcheck** | bash 源码 | ✅ | 外部 binary | ❌ | ✅（部分） | 插件移植其 **TOP 子集**（sc2086/2164/2181/2034）为零依赖确定性实现；全量仍是外部可选增强 |
| **ruff** | Python 源码 | ✅ | 外部 binary | ❌ | ✅ | 插件 `python_module_deadcode` 是 AST 零依赖子集；ruff 全量是 self-check 可选门禁 |
| **vulture / pyflakes** | Python 死代码 | ✅ | 外部包 | ❌ | ❌ | 插件 AST 模块级死代码是零依赖子集，且**不依赖 vulture/pyflakes 安装** |
| **ast-grep / comby / tree-sitter** | 通用结构化转换 | ✅ | 外部 | ❌ | ❌ | 通用搜索/转换，非语义迁移验证 |
| **semgrep** | 多语言规则扫描 | ✅ | 外部 | ❌ | 部分 | 规则引擎，无 bash→Python 迁移语义 |
| **actionlint** | workflow 语法 | ✅ | 外部 | ❌ | ❌ | CI 侧互补工具（本插件 CI 用它扫 workflow） |

## 2. 差异化论证（为什么不是重复造轮子）

1. **L2 verify 是独有能力**——语义等价验证闭环（bash 固化基线 vs python 输出 diff）。
   bash2py 已死、AI 转换无验证：业界在"迁移后怎么证明等价"上是空白，插件是唯一确定性方案。

2. **双语言静态审计 + 零外部依赖**——shellcheck 管 bash、ruff/vulture 管 python，各自独立；
   插件把 bash（bomb 扫描 + shellcheck TOP 子集）与 python（AST 死代码 + 写入守卫）放进
   同一个确定性引擎，Windows/WSL 通吃，不依赖任何二进制安装。

3. **zizmor 模式对齐但范围不同**——zizmor 审计 GitHub Actions YAML（检测→分级→修复）；
   插件对 bash 源码做同款三件套（severity + risk + fix），是"zizmor 之于 workflow =
   插件之于迁移源码"的平行实现。

4. **供应链与可移植性**——外部 linter（shellcheck/ruff）会引入二进制依赖与安装面；
   插件的核心规则全部原生实现（正则/AST），发布包经 SHA256 pin 校验，无运行时外部依赖。

## 3. 边界（明确不做）

- 不做代码生成（LLM 负责），只验证。
- 不替代全量 shellcheck/ruff（250+/数百规则），只移植迁移场景 TOP 高频规则；全量作为可选增强。
- 不替代 zizmor（workflow 审计在 CI 侧保留），插件专注源码审计。
