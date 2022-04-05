CARGO := cargo
CARGO_NIGHTLY := $(CARGO) +nightly

build:
	$(CARGO) build

run-coordinator:
	$(CARGO) run --bin phase1-coordinator

test-coordinator:
	$(CARGO) test --test test_coordinator --features testing -- --test-threads=1

fmt:
	$(CARGO_NIGHTLY) fmt

clippy:
	$(CARGO_NIGHTLY) clippy --all-targets --all-features -- -D warnings

update:
	$(CARGO) update

clean:
	$(CARGO) clean

.PHONY : build clean clippy fmt run-coordinator test-coordinator update