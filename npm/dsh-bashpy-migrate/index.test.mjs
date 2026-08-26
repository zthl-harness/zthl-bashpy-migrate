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

// Windows 只有 python 命令；CI(ubuntu) 是 python3；可用 BASHPY_PYTHON 覆盖
const PY = process.env.BASHPY_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')

test('auditArgv builds the three-layer argv', () => {
  assert.deepEqual(
    auditArgv({ script: '/x.sh', bomb: true, shellcheck: true, pyDeadcode: true, explain: false }),
    ['-m', 'zthl_bashpy_migrate.cli', 'audit', '--script', '/x.sh',
      '--bomb', '--shellcheck', '--py-deadcode'],
  )
  assert.deepEqual(
    auditArgv({ script: '/y.py' }),
    ['-m', 'zthl_bashpy_migrate.cli', 'audit', '--script', '/y.py'],
  )
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
