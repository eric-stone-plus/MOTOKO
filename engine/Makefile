# MOTOKO engine — test entry. The green count is an executable assertion,
# not an oral state ("411 passed, 1 skipped" as of 2026-09-13).
PY ?= 3.11

ifeq ($(shell command -v uv 2>/dev/null),)
  RUN_PYTEST = python3 -m pytest
else
  RUN_PYTEST = uv run --python $(PY) --with pytest -- pytest
endif

.PHONY: test install clean

test:
	$(RUN_PYTEST) tests/ -q

install:
	uv pip install -e .

clean:
	rm -rf motoko/__pycache__ motoko/*/__pycache__ .pytest_cache
