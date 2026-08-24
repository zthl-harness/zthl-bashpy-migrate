# Copyright (c) 2026 Pu Junhan
# SPDX-License-Identifier: MulanPSL-2.0
# Project: ZTHL-Harness
# Repository: https://github.com/zthl-harness/zthl-bashpy-migrate

"""conftest.py — shared fixtures for zthl_bashpy_migrate tests."""
import sys
from pathlib import Path

import pytest

# 项目根注入（避免 pip install -e；与 gatekeeper 测试同模式）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASH_SAMPLE = """#!/bin/bash
_parent() {
  local shared_var="hello"
  _child "$shared_var"
}
_child() {
  echo "$shared_var"
}
_write_state() {
  echo '{"ok":true}' > /tmp/state.json
}
cmd_main() {
  local dry_run=false
  if [ "$dry_run" = "false" ]; then
    _write_state
  fi
}
"""

PY_SAMPLE = """import json

def _write_state(path, d):
    json.dump(d, open(path, "w"))

def main(dry_run=False):
    if not dry_run:
        _write_state("/tmp/state.json", {"ok": True})
"""


@pytest.fixture
def bash_source() -> str:
    return BASH_SAMPLE


@pytest.fixture
def py_source() -> str:
    return PY_SAMPLE
