.PHONY: static commercial silicon-gate rust-gate

static:
	python3 scripts/static_gate.py
	python3 scripts/commercial_gate.py

commercial:
	python3 scripts/commercial_gate.py

silicon-gate:
	python3 scripts/silicon_gate.py

rust-gate:
	./scripts/rust_gate.sh
