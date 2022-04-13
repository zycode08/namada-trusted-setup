CARGO := cargo
CARGO_NIGHTLY := $(CARGO) +nightly

build:
	$(CARGO) build

check:
	$(CARGO) check

contribution: # Run contributor against a local coordinator (127.0.0.1:8000)
	$(CARGO) run --bin phase1 --features=cli

run-coordinator:
	$(CARGO) run --bin phase1-coordinator

test-coordinator:
	$(CARGO) test --test test_coordinator --features testing -- --test-threads=1

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

.PHONY : build check clean clippy contribution fmt contributor run-coordinator test-coordinator update