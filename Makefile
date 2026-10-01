.PHONY: bedrock-static rust-gate

bedrock-static:
	python3 scripts/static_gate.py

rust-gate:
	./scripts/rust_gate.sh
