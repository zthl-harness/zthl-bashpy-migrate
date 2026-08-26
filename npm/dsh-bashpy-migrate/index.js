// Copyright (c) 2026 Pu Junhan
// SPDX-License-Identifier: MulanPSL-2.0
// Project: ZTHL-Harness
// Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

// DSH bundle entry — wraps the zthl-bashpy-migrate Python CLI as a model-facing tool.
// The npm layer is a thin adapter: engine stays in the Python package (audit --bomb
// / --shellcheck / --py-deadcode). Host DSH provides @deepseek-ai/dsh-tools via
// peerDependencies; the Python side is resolved through the same probe chain the
// spz-gatekeeper skill uses (python3 -m, BASHPY_PYTHON override).

import { runAudit } from './engine.js'

export const name = 'bashpy-migrate'
export const inject = ['tools']

// 工具定义（纯数据）: 单独导出供回归测试直接校验 schema 规则，无需安装 peer。
// dsh-tools 的作者侧 schema 子集强制: 任何 object 节点必须显式声明
// additionalProperties: true|false（见 @deepseek-ai/dsh-tools assertSupportedJsonSchema，
// 缺失直接 JsonSchemaError 导致插件 boot 失败 —— 2026-08-26 红队实测抓到的 bug）。
export const toolSpec = {
  name: 'bashpy_migrate_scan',
  description: 'Run zthl-bashpy-migrate deterministic audit on a bash or Python file: '
    + 'bomb scan (inline-python / stderr-swallow / dangerous-command) / shellcheck TOP '
    + 'subset (sc2086/sc2164/sc2181/sc2034, zero-dep) / Python module-level deadcode '
    + '(AST unused imports/functions). Every finding carries severity+risk+fix.',
  parameters: {
    script: {
      type: 'string',
      required: true,
      description: 'Absolute path to the bash or Python source to audit',
    },
    bomb: {
      type: 'boolean',
      description: 'Run bomb scan (python3 inline / stderr swallow / dangerous command / case-sensitive)',
    },
    shellcheck: {
      type: 'boolean',
      description: 'Run shellcheck TOP subset (sc2086/sc2164/sc2181/sc2034, deterministic zero-dep)',
    },
    py_deadcode: {
      type: 'boolean',
      description: 'Run Python module-level deadcode (AST unused imports/functions)',
    },
    explain: {
      type: 'boolean',
      description: 'LLM explanation fallback (degrades to a manual-review list without an API key)',
    },
  },
  output: {
    schema: { type: 'object', additionalProperties: true },
    render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
  },
  async execute(args, _exec) {
    const res = await runAudit(args)
    if (!res.ok) throw new Error(res.error)
    return res.report
  },
}

export async function apply(ctx) {
  // 动态 import peer：模块顶层不依赖 @deepseek-ai/dsh-tools，
  // 使 index.test.mjs 可在未安装 peer 的插件仓库直接 import { toolSpec }。
  const { defineTool } = await import('@deepseek-ai/dsh-tools')
  ctx.tools.register(defineTool(toolSpec))
}
