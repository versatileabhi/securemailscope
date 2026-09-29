# SecureMailScope — Makefile
# Requires GNU Make. On Windows, use Git Bash, WSL, or run commands directly.
# Equivalent direct Python commands are documented in README.md.

.PHONY: setup test lint format run-status clean

PYTHON := python
PIP := pip

setup:
	$(PYTHON) -m venv .venv
	.venv/Scripts/pip install -e .[dev] || .venv/bin/pip install -e .[dev]

test:
	$(PYTHON) -m pytest $(PYTEST_ARGS)

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

run-status:
	$(PYTHON) -m securemailscope status

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/ .coverage
