cd ..
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --verbose

pause