// Copyright (c) 2026 Pu Junhan
// SPDX-License-Identifier: MulanPSL-2.0
// Project: ZTHL-Harness
// Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

// DSH bundle entry — wraps the zthl-bashpy-migrate Python CLI as a model-facing tool.
// The npm layer is a thin adapter: engine stays in the Python package (audit --bomb
// / --shellcheck / --py-deadcode). Host DSH provides @deepseek-ai/dsh-tools via
// peerDependencies; the Python side is resolved through the same probe chain the
// spz-gatekeeper skill uses (python3 -m, BASHPY_PYTHON override).

import { defineTool } from '@deepseek-ai/dsh-tools'
import { runAudit } from './engine.js'

export const name = 'bashpy-migrate'
export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register(defineTool({
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
      schema: { type: 'object' },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    async execute(args, _exec) {
      const res = await runAudit(args)
      if (!res.ok) throw new Error(res.error)
      return res.report
    },
  }))
}
