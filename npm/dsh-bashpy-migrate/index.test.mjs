// Copyright (c) 2026 Pu Junhan
// SPDX-License-Identifier: MulanPSL-2.0
// Tests for the DSH npm adapter: argv construction + real CLI round-trip (bomb layer).
// Run: node --test npm/dsh-bashpy-migrate/index.test.mjs
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { auditArgv, runAudit } from './engine.js'
import { toolSpec } from './index.js'

// Windows 只有 python 命令；CI(ubuntu) 是 python3；可用 BASHPY_PYTHON 覆盖
const PY = process.env.BASHPY_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')

test('auditArgv builds the three-layer argv', () => {
  assert.deepEqual(
    auditArgv({ script: '/x.sh', bomb: true, shellcheck: true, py_deadcode: true, explain: false }),
    ['-m', 'zthl_bashpy_migrate.cli', 'audit', '--script', '/x.sh',
      '--bomb', '--shellcheck', '--py-deadcode'],
  )
  assert.deepEqual(
    auditArgv({ script: '/y.py' }),
    ['-m', 'zthl_bashpy_migrate.cli', 'audit', '--script', '/y.py'],
  )
})

test('auditArgv covers every toolSpec flag with the exact schema parameter name', () => {
  // 回归: 2026-08-26 DSH 红队实测 —— schema 暴露 py_deadcode（蛇形）而 engine 内部
  // 解构 pyDeadcode（驼峰），execute 透传 args 导致 --py-deadcode 永远不触发。
  // 锁: 每个 engine 支持的 flag 必须能在 toolSpec.parameters 找到同名参数。
  const flagFor = {
    bomb: '--bomb',
    shellcheck: '--shellcheck',
    py_deadcode: '--py-deadcode',
    explain: '--explain',
  }
  for (const [param, flag] of Object.entries(flagFor)) {
    assert.ok(toolSpec.parameters[param], `toolSpec must expose parameter '${param}'`)
    const argv = auditArgv({ script: '/x', [param]: true })
    assert.ok(argv.includes(flag), `'${param}' must map to ${flag}`)
  }
})

test('runAudit round-trips the real CLI bomb scan', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bashpy-'))
  const sample = join(dir, 'sample.sh')
  await writeFile(sample, 'f() {\n  python3 -c "print(1)"\n  grep x 2>/dev/null\n}\n')

  const res = await runAudit({ script: sample, bomb: true }, { python: PY })
  assert.equal(res.ok, true, `CLI failed: ${res.error}`)
  assert.ok(res.report.bomb_scan, 'report should carry bomb_scan section')
  assert.ok(res.report.bomb_scan.counts.inline_python >= 1)
  assert.ok(res.report.bomb_scan.counts.stderr_swallow >= 1)
})

test('runAudit surfaces a missing script as ok:false, not a throw', async () => {
  const res = await runAudit({ script: '/no/such/file.sh', bomb: true }, { python: PY })
  assert.equal(res.ok, false)
  assert.ok(res.error.length > 0)
})

test('runAudit picks the platform python by default (win32=python, else python3)', async () => {
  // 回归: 2026-08-26 DSH 本地红队实测 —— engine 默认 python3 在 Windows 必挂，
  // 必须按平台解析（BASHPY_PYTHON 仍可覆盖）。双平台（CI ubuntu + 本机 win）都须过。
  const dir = await mkdtemp(join(tmpdir(), 'bashpy-def-'))
  const sample = join(dir, 'sample.sh')
  await writeFile(sample, 'f() {\n  python3 -c "print(1)" 2>/dev/null\n}\n')
  const res = await runAudit({ script: sample, bomb: true }) // 无 python 覆盖
  assert.equal(res.ok, true, `default python failed: ${res.error}`)
})

test('toolSpec output schema declares explicit additionalProperties (dsh-tools strict subset)', () => {
  // 回归: 2026-08-26 DSH 红队实测 —— dsh-tools 作者侧 schema 子集要求 object
  // 节点显式声明 additionalProperties: true|false，缺失 JsonSchemaError 导致
  // 插件 boot 失败（output.schema 走 valueSchemaSpecToJsonSchema 严格编译）。
  const walked = []
  const walk = (node, path) => {
    if (!node || typeof node !== 'object' || Array.isArray(node)) return
    if (node.type === 'object') {
      assert.equal(typeof node.additionalProperties, 'boolean',
        `${path} must declare explicit additionalProperties true|false`)
      walked.push(path)
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === 'additionalProperties' || k === 'description' || k === 'title') continue
      walk(v, `${path}.${k}`)
    }
  }
  walk(toolSpec.output.schema, 'output.schema')
  assert.ok(walked.length >= 1, 'output.schema object root must be walked')
})

test('toolSpec parameters require script and keep scalar flags', () => {
  assert.equal(toolSpec.parameters.script.required, true)
  assert.equal(toolSpec.parameters.script.type, 'string')
  assert.equal(toolSpec.parameters.bomb.type, 'boolean')
  assert.equal(toolSpec.parameters.py_deadcode.type, 'boolean')
})
