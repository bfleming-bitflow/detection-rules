PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin

.PHONY: help venv lint sigma-check yara-check test coverage coverage-check check clean

help:
	@echo "venv             create .venv and install development dependencies"
	@echo "lint             ruff and yamllint"
	@echo "sigma-check      validate Sigma rules with sigma-cli"
	@echo "yara-check       compile YARA rules"
	@echo "test             run the test suite"
	@echo "coverage         regenerate docs/coverage.md"
	@echo "coverage-check   fail if docs/coverage.md is out of date"
	@echo "check            lint, sigma-check, test and coverage-check (what CI runs)"

venv:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements-dev.txt

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/yamllint -s .

sigma-check:
	$(BIN)/sigma check --fail-on-issues rules/sigma

yara-check:
	$(BIN)/python -c "import yara; from pathlib import Path; yara.compile(filepaths={p.stem: str(p) for p in Path('rules/yara').glob('*.yar')}); print('yara ok')"

test:
	$(BIN)/pytest --cov=tools --cov-report=term-missing --cov-fail-under=80

coverage:
	$(BIN)/python tools/coverage.py

coverage-check:
	$(BIN)/python tools/coverage.py --check

check: lint sigma-check yara-check test coverage-check

clean:
	rm -rf .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
