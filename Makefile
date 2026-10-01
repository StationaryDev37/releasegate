.PHONY: bedrock-static silicon-gate rust-gate

bedrock-static:
	python3 scripts/static_gate.py
	python3 scripts/silicon_gate.py

silicon-gate:
	python3 scripts/silicon_gate.py

rust-gate:
	./scripts/rust_gate.sh
