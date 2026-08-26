// Copyright (c) 2026 Pu Junhan
// SPDX-License-Identifier: MulanPSL-2.0
// Engine-facing adapter logic, free of any DSH runtime import so it can be
// unit-tested without installing @deepseek-ai/dsh-tools (index.test.mjs).

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileP = promisify(execFile)

/** Build the plugin CLI argv for one audit invocation (pure, unit-testable). */
export function auditArgv({ script, bomb, shellcheck, py_deadcode, explain }) {
  const argv = ['-m', 'zthl_bashpy_migrate.cli', 'audit', '--script', script]
  if (bomb) argv.push('--bomb')
  if (shellcheck) argv.push('--shellcheck')
  if (py_deadcode) argv.push('--py-deadcode')
  if (explain) argv.push('--explain')
  return argv
}

/**
 * 引擎解释器默认值：BASHPY_PYTHON 显式覆盖优先，否则按平台（Windows 只有
 * python 命令；CI/linux 是 python3）—— 2026-08-26 DSH 本地红队实测抓到:
 * 直接默认 python3 在 Windows 上 execute 必挂。
 */
function defaultPython() {
  return process.env.BASHPY_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')
}

/**
 * Run the engine on one file, returning the canonical JSON report.
 * Never throws on a non-zero CLI exit — surfaces {ok:false} with stderr excerpt.
 */
export async function runAudit(opts, { python = defaultPython() } = {}) {
  const argv = auditArgv(opts)
  try {
    const { stdout } = await execFileP(python, argv, {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    })
    return { ok: true, report: JSON.parse(stdout) }
  } catch (err) {
    const detail = String(err.stderr || err.message).slice(0, 2000)
    return { ok: false, error: detail }
  }
}
