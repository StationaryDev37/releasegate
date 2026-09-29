.PHONY: check test run
check:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test --all-targets

test:
	cargo test --all-targets

run:
	cargo run --release
