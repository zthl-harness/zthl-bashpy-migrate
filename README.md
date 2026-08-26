# zthl-bashpy-migrate

Deterministic bash → Python migration verification engine (ZTHL ecosystem tool).

> **It does not generate code.** Code generation is left to LLMs; this tool is responsible for
> **verifying semantic equivalence, auditing side effects, and detecting dead code** —
> filling the deterministic verification gap shared by bash2py (dead) and AI-based converters
> (no verification loop).

**中文自述见 [README.zh-CN.md](README.zh-CN.md).**

## Background

Industry status (2026-08 survey):

| Approach | Gap |
|:--|:--|
| bash2py (Waterloo SANER 2015) | The only dedicated bash→Python transpiler, **dead**; ~90% translation rate but needs manual intervention; no semantic-equivalence verification |
| AI/LLM conversion (CodePorting, etc.) | "starting draft you must verify" — **no verification loop**; exit-code semantics / shell=True injection / word-splitting are recurring pitfalls |
| ast-grep / comby / tree-sitter / semgrep | Generic search / structural transformation / static analysis, not semantic migration verification |

The unique premise of `zthl-bashpy-migrate`: migration happens while the bash version and the
Python version **coexist** (before the bash version is replaced). Therefore the bash output can be
captured as a **frozen baseline**, and the Python output can be continuously compared against it —
semantic equivalence becomes deterministically verifiable.

## Relationship with the ZTHL Framework

ZTHL (Zero-Trust Self-Referential Evolutionary Governance, [ChinaXiv:202607.00158](https://chinaxiv.org/abs/202607.00158))
is a governance framework whose core idea is replacing trust with deterministic, self-referential
verification loops. This tool is a **deterministic tooling layer** of the ZTHL ecosystem: the
"migration verification loop" is a concrete engineering instance of ZTHL's governance loop.

It is **fully independent at runtime** — pure Python standard library, no dependency on any ZTHL
component. The tool only recognizes the input→output JSON contract of the code under migration,
not any framework-specific pattern.

## Three-Layer Architecture

```
L1 analyze (0 API, deterministic)
    bash functions → dependency graph (local-variable capture → "child references parent's local" detection)
    + side-effect inventory (file writes / environment calls → dry_run-guard-missing detection)
    + migration boundary recommendations (environment side effects stay in bash / pure logic → Python)

L2 verify (0 API, deterministic, core)
    Python output vs frozen baseline JSON → semantic-equivalence diff (recursive json.loads comparison)
    + contract-improvement whitelist (bash bug fixes registered)
    + dry_run zero-side-effect check (state hash before/after --check)

L3 audit (LLM fallback optional)
    dead-code three gates (bash function reachability + Python module-level unused imports/functions, AST)
    + write-path guard audit (AST scan for *_write* without dry_run guard)
    + bomb scan: inline-python / stderr-swallow / dangerous-command / case-sensitive coupling
      (zizmor-style: detect → grade → fix — every finding carries severity + risk + fix recipe)
    + shellcheck TOP subset (SC2086/SC2164/SC2181/SC2034 deterministic port — zero external dependency)
    + uncovered implicit-semantics points → LLM explanation (degraded to "needs manual review" list without key)
```

## Installation

```bash
pip install -e .
```

Dependencies: Python ≥ 3.9, standard library only (LLM fallback is optional).

## Quick Start

```bash
# 1) Before migration: freeze the bash baseline
bashpy-migrate verify baseline --cmd "bash gatekeeper-cli.sh advance STAGE_1 --check" --out baseline.json

# 2) Before migration: analyze bash function structure and side effects
bashpy-migrate analyze --script gatekeeper-cli.sh

# 3) After migration: verify Python output vs frozen baseline (semantic equivalence)
bashpy-migrate verify --baseline baseline.json --output result.json

# 4) After migration: dead-code + write-guard audit
bashpy-migrate audit --script gatekeeper-cli.sh --entry main --write-fns "_state_write,_write_state"
```

## Migration Issue Taxonomy

25 categories of bash → Python migration problems in 6 domains, collected from real migration
practice (Phase 7 of the ZTHL gatekeeper migration), each with phenomenon → root cause → solution:
**[docs/migration-issues.md](docs/migration-issues.md)**

## Acceptance Criteria

Quantified, auto-verifiable criteria mapped to each layer (aligned with the ZTHL gatekeeper
Phase 7 acceptance style: "all transitions correct + 100% semantic equivalence"):

| Layer | Criterion | Verification |
|:--|:--|:--|
| L1 analyze | 5 golden fixtures (local capture / side effects / mixed) → function extraction 100% exact (name/range/locals/calls) | `pytest tests/test_analyze.py` |
| L1 analyze | Side-effect inventory 100% hit (no false negatives); boundary recommendations match expected (pure→migrate / side-effect→keep-bash) | golden fixture assertions |
| L2 verify | Semantic-equivalence diff: 0 differences outside whitelist (dict key / list / type / value aligned) | `pytest tests/test_verify.py` |
| L2 verify | dry_run zero side effects: state sha256 identical before/after `--check` | `dry_run_check` test |
| L2 verify | Contract-improvement whitelist: registered items never block | whitelist test |
| L3 audit | Dead-code three gates: 100% detection on known dead-code samples | `pytest tests/test_audit.py` |
| L3 audit | Write-guard: 100% detection of unguarded writes, 0 false positives on guarded | fixture assertions |
| L3 audit | Bomb scan + shellcheck TOP subset + case-sensitivity: deterministic findings, every one with severity+risk+fix (zizmor 模式) | `bomb_scan` / `shellcheck_scan` tests |
| L3 audit | Python module-level deadcode: unused imports/functions via AST (zero-dep, no vulture/pyflakes) | `python_module_deadcode` test |
| L3 audit | LLM fallback degraded mode (no key → "needs manual review" list) | `llm_explain` test |
| Cross-layer | `pytest` ≥ 28 passed; CLI smoke on real bash sample (analyze + audit) 0 errors | `pytest tests -q` + CI quality job |
| Cross-layer | Python 3.9-3.13 × ubuntu/windows matrix green | GitHub Actions `test` job |

A layer change is only "done" when its row above is green in CI — mirroring the batch8 rule
"Phase N done = all its acceptance cases pass".

## License

[MulanPSL-2.0](https://license.coscl.org.cn/MulanPSL2)

Copyright (c) 2026 Pu Junhan
