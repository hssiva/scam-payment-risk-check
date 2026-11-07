PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

.PHONY: setup lint format test eval verify run-api clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -r requirements-dev.txt
	$(BIN)/python -m pip install -e . --no-deps

lint:
	$(BIN)/ruff check .

format:
	$(BIN)/ruff format .

test:
	$(BIN)/pytest

eval:
	$(BIN)/python -m scamcheck.evaluate

verify:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/pytest
	@$(MAKE) --no-print-directory eval

run-api:
	$(BIN)/uvicorn scamcheck.api:app --host 127.0.0.1 --port 8000

clean:
	rm -rf $(VENV) build dist .pytest_cache .ruff_cache htmlcov .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.egg-info' -type d -prune -exec rm -rf {} +
