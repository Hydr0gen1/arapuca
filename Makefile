.PHONY: build release test lint fmt check audit header clean

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

lint: fmt-check clippy

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy -- -D warnings

check: fmt-check clippy test

audit:
	cargo audit
	cargo deny check

header:
	cbindgen --config cbindgen.toml --crate arapuca --output include/arapuca.h

clean:
	cargo clean

# Static Linux binary (musl).
static:
	cargo build --release --target x86_64-unknown-linux-musl
