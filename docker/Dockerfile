FROM lukemathwalker/cargo-chef:latest-rust-1.61.0 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
RUN rustup target add x86_64-unknown-linux-musl
# COPY --from=planner /app/phase1/Cargo.toml phase1-cli/Cargo.toml
COPY --from=planner /app/setup-utils/Cargo.toml setup-utils/Cargo.toml
# COPY --from=planner /app/phase1-cli/Cargo.toml phase1-cli/Cargo.toml
# COPY --from=planner /app/phase1-cli/src/main.rs phase1-cli/src/main.rs
COPY --from=planner /app/recipe.json recipe.json
RUN RUSTFLAGS='-Clinker=rust-lld' cargo chef cook --package setup-utils --target x86_64-unknown-linux-musl --recipe-path recipe.json

# We do not need the Rust toolchain to run the binary!
# FROM debian:bullseye-slim AS runtime
# WORKDIR /app
# COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/phase1-coordinator /usr/local/bin
# ENTRYPOINT ["/usr/local/bin/phase1-coordinator"]
