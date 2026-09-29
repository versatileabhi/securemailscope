# SecureMailScope — Project Handoff Guide

This document explains how any new developer, agent, or account should resume work on SecureMailScope safely and without introducing errors or skipping phases.

## Steps to Resume

### 1. Read `progress.md` first

`progress.md` is the single source of truth for current phase, completed work, blockers, and verification commands. Always start here.

### 2. Read `README.md`

Confirm the current phase and understand what is and is not implemented.

### 3. Read `docs/development_phases.md`

Understand the full phase plan and the acceptance criteria for the current and next phases.

### 4. Run environment and test commands

```bash
python --version
# Must be 3.11 or later

python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows
# or: source .venv/bin/activate

pip install -e .[dev]
pytest
ruff check .
python -m securemailscope status
```

### 5. Verify the last completed phase

Check that all acceptance criteria for the last marked-complete phase in `progress.md` are genuinely met. Do not assume previous work is correct without verification.

### 6. Work only on the next uncompleted phase

Do not skip phases. Do not implement features belonging to a later phase.

### 7. Update `progress.md` after tests pass

Record:
- Files changed.
- Commands run and their output.
- Test results.
- Any blockers or decisions made.

### 8. Never silently skip a phase

If a phase cannot be completed (dependency unavailable, requirement ambiguous), record the blocker in `progress.md` and `docs/assumptions.md`. Do not advance the phase counter.
