# ICS Deception Framework — top level Makefile
#
# Targets:
#   install      install the package (runtime dependencies only)
#   install-dev  install the package in editable mode with dev and PQC dependencies
#   build        compile all native (C++) targets into build/
#   test         run the Python test suite
#   lint         run ruff over src/ and tests/
#   check        compileall + lint + build + test + shell checks + packaging
#   run          start the FastAPI controller bound to loopback
#   capabilities report which post-quantum backends are available
#   package      build the wheel and source distribution
#   release      build the portable release ZIP and checksums
#   clean        remove build artifacts, caches, runtime logs and release output

PYTHON  ?= python3
BUILD_DIR ?= build
RUNTIME_DIR ?= runtime
RELEASE_DIR ?= dist/release

.PHONY: all install install-dev build test lint check run clean compileall \
        shell-syntax shellcheck package release capabilities

all: build

install:
	$(PYTHON) -m pip install .

install-dev:
	$(PYTHON) -m pip install -e ".[dev,pqc]"

build:
	$(MAKE) -C src/native BUILD_DIR=$(abspath $(BUILD_DIR))

compileall:
	$(PYTHON) -m compileall -q src tests scripts

lint:
	$(PYTHON) -m ruff check src tests scripts

test:
	$(PYTHON) -m pytest

shell-syntax:
	bash -n scripts/deploy_rpi.sh

# ShellCheck is advisory: it is not installed everywhere, and a missing linter
# must not fail a developer's local `make check`. CI installs and enforces it.
shellcheck:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/deploy_rpi.sh && echo "shellcheck: clean"; \
	else \
		echo "shellcheck: not installed, skipping (CI enforces this)"; \
	fi

package:
	$(PYTHON) -m build

release:
	$(PYTHON) scripts/make_release.py --output $(RELEASE_DIR)

capabilities:
	$(PYTHON) -m ics_deception.pqc_evidence.cli capabilities

check: compileall lint build test shell-syntax shellcheck
	@echo "All checks passed."

run:
	$(PYTHON) -m ics_deception.controller.cli --host 127.0.0.1 --port 8000

clean:
	$(MAKE) -C src/native BUILD_DIR=$(abspath $(BUILD_DIR)) clean
	rm -rf $(BUILD_DIR) $(RUNTIME_DIR)
	rm -rf dist *.egg-info src/*.egg-info
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
