RUSTFLAGS='-Clinker=rust-lld' cargo build --release --features=parallel --bin phase1-coordinator --target x86_64-unknown-linux-musl
