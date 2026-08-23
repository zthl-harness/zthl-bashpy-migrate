"""probe.py — syntax preflight for bash and Python sources.

2026-08-23 lesson (gatekeeper Phase 7): bash -n with a Windows path arg fails
under WSL bash (`/bin/bash: C:Users... No such file`). Use stdin form —
no path dependency, identical on Windows/WSL.
"""
import subprocess
from typing import Optional


def bash_n(source: str, timeout: int = 5) -> Optional[str]:
    """Run `bash -n` over the given source via stdin.

    Returns the first stderr line on syntax error, else None.
    """
    try:
        p = subprocess.run(["bash", "-n"], input=source, capture_output=True,
                           text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None  # bash unavailable or timeout → skip
    if p.returncode != 0:
        err = (p.stderr or p.stdout).strip().splitlines()
        return err[0] if err else "syntax error"
    return None


def py_compile_source(source: str, filename: str = "<migrated>") -> Optional[str]:
    """Compile Python source; returns the error message on failure."""
    try:
        compile(source, filename, "exec")
    except SyntaxError as e:
        return f"{e.msg} (line {e.lineno})"
    return None
