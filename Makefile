.PHONY: install check test test-all bench serve paper-figures changelog

install:
	cargo install --path crates/chaperone-cli --locked

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo check --workspace

test:
	cargo test --workspace

test-all:
	cargo test --workspace --all-features

bench:
	cargo run -p chaperone-cli -- bench

serve:
	cargo run -p chaperone-cli -- serve

paper-figures:
	cargo run --release -p chaperone-cli -- bench

changelog:
	git cliff --latest