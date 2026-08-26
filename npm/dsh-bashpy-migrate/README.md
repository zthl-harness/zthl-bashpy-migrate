# @zthl-harness/dsh-bashpy-migrate

DSH（DeepSeek Harness）bundle，包装 [zthl-bashpy-migrate](../../README.zh-CN.md)
确定性 bash→Python 迁移审计引擎：`bomb_scan` / `shellcheck_scan` / `python_module_deadcode`。

薄包装：引擎全在 Python 包（`audit --bomb --shellcheck --py-deadcode`），本包只做
`defineTool` 注册 + subprocess 透传。宿主 DSH 提供 `@deepseek-ai/dsh-tools`（peerDependencies）。

## 安装（DSH profile）

```sh
# 在包含本包 checkout 的目录（或 tarball / github 引用）
dsh plugin --profile demo add ./npm/dsh-bashpy-migrate
dsh --profile demo   # cordis.patch.yml 注入 bashpy-migrate 行
```

引擎需已安装：`pip install zthl-bashpy-migrate`（≥0.2.2），或设 `BASHPY_PYTHON`
指向含引擎的解释器（如 `BASHPY_PYTHON="python3"`）。

## 模型可见工具

- `bashpy_migrate_scan`：`script`（必填）+ `bomb` / `shellcheck` / `py_deadcode` / `explain`

## 供应链防护（integrity 登记）

skill 侧加载器（`gk_plugin_manifest.py`）对 `url: npm:` 插件**强制** `config.integrity`
（投毒对账）。本仓库 CI `npm-supply-chain` job 每次构建产出
`npm-integrity.json`（npm 包 `sha512-` tarball hash + lockfile pin）作为发布资产——
登记到 skill manifest：

```python
{"id": "bashpy-migrate", "url": "npm:@zthl-harness/dsh-bashpy-migrate",
 "config": {"integrity": "<npm-integrity.json 的 integrity 值>"}}
```

发布后可用 `npm view @zthl-harness/dsh-bashpy-migrate@<ver> dist.integrity` 与本地
构建 hash 对账，检测 registry 投毒。

## 测试

```sh
node --test index.test.mjs     # argv 构造 + 真实 CLI round-trip（bomb 层）
```
