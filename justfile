[private]
default:
    @just --justfile {{justfile()}} --list --list-heading $'Project commands:\n'

lint:
    cargo fmt --all -- --check
    cargo all-features clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --features="full" --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --features="full-groth16,full-plonk" --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --features="bin" --workspace --tests --examples --benches --bins -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo all-features doc --workspace -q --no-deps


test:
    cargo test --all-features

check-pr: lint test