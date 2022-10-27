CARGO := cargo
CARGO_NIGHTLY := $(CARGO) +nightly
CLI_FLAGS := --bin namada-ts --features=cli

build:
	$(CARGO) build

check:
	$(CARGO) check --all-targets

contribution: # Run contributor against a local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) contribute default

offline-contribution: # Computes offline contribution
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) contribute offline

close-ceremony: # Stop local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) close-ceremony

verify: # Verify pending contributions on local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) verify-contributions

update-coordinator: # Update manually the coordinator
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) update-coordinator

get-contributions: # Get the received contributions on local coordinator (0.0.0.0:8080)
	RUST_LOG=debug $(CARGO) run $(CLI_FLAGS) get-contributions

run-coordinator:
	HEALTH_PATH="." RUST_LOG=debug $(CARGO) run --features=parallel --bin phase1-coordinator

test-coordinator:
	$(CARGO) test --test test_coordinator -- --test-threads=1

test-e2e:
	$(CARGO) test --test e2e -- --test-threads=1

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

.PHONY : build check clean clippy clippy-fix close-ceremony contribution fmt get-contributions offline-contribution run-coordinator test-coordinator test-e2e update verify