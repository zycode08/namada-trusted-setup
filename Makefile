CARGO := cargo
CARGO_NIGHTLY := $(CARGO) +nightly
CLI_FLAGS := --bin namada-ts --features=cli

build:
	$(CARGO) build

check:
	$(CARGO) check --workspace --all-targets

check-release:
	$(CARGO) check --release --workspace

fmt:
	$(CARGO_NIGHTLY) fmt --all

clippy:
	$(CARGO_NIGHTLY) clippy --all-targets --all-features -- -D warnings

clippy-fix:
	$(CARGO_NIGHTLY) clippy --fix -Z unstable-options --all-targets --allow-dirty --allow-staged

update:
	$(CARGO) update

clean:
	$(CARGO) clean

# NOTE: The following commands are for debug purposes only

close-ceremony: # Stop local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) close-ceremony

verify: # Verify pending contributions on local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) verify-contributions

update-coordinator: # Manually update the coordinator
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) update-coordinator

get-contributions: # Get the received contributions on local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) get-contributions

run-coordinator:
	aws s3 rm s3://${AWS_S3_BUCKET} --recursive
	RUST_LOG=debug $(CARGO) run --features=parallel --bin phase1-coordinator

.PHONY : build check clean clippy clippy-fix close-ceremony fmt get-contributions run-coordinator update verify