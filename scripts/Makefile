# Unit tests for the campaign scripts. Separate from the repository's top-level
# Makefile (syzkaller's own build); run from anywhere with `make -C scripts test`.
#
#   make test                    all modules
#   make test T=test_triage      one module (tests/test_triage.py)
#   make test V=1                one line per test

PYTHON ?= python3
VERBOSE := $(if $(V),-v,)

.PHONY: test
test:
ifdef T
	$(PYTHON) -m unittest $(VERBOSE) tests.$(T)
else
	$(PYTHON) -m unittest discover $(VERBOSE) -s tests
endif
