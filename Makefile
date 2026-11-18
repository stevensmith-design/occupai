# OccupAI v0.1. Python 3 stdlib only: nothing to install.
PYTHON ?= python3

.PHONY: help test demo lint clean

help:
	@echo "make test   run the test suite (fixtures are built in a temp folder; fake keys generated at test time)"
	@echo "make demo   briefing -> scan -> tracker on the fixtures, offline (output in build/demo/storage)"
	@echo "make clean  remove build/"

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) examples/demo/run_demo.py

lint:
	$(PYTHON) -m compileall -q occupai_scan tests examples

clean:
	rm -rf build
