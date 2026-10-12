# AIVM developer shortcuts. `make help` lists targets.
# Every target is plain cargo so `rtk make <target>` also works.

.PHONY: help build check test test-adv demo e2e clippy fmt fmt-check verify clean query path explain graph-update debug-test

help: ## Show this help
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*?## "} {printf "  %-10s %s\n", $$1, $$2}'

build: ## Compile the whole workspace
	cargo build --workspace

check: ## Fast type-check, no codegen
	cargo check --workspace --all-targets

test: ## All unit + integration tests
	cargo test --workspace

test-adv: ## Adversarial must-deny suite only (spec §38)
	cargo test -p aivm-adversarial

demo: ## One-shot enforcement self-test (ALLOW/DENY table, temp dir)
	cargo run -q -p aivm-cli -- demo

e2e: ## Full CLI cycle via scripts/smoke.sh (create/inspect/run/logs)
	sh scripts/smoke.sh

clippy: ## Lints; fails on warnings
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## Format all code
	cargo fmt --all

fmt-check: ## Fail if formatting drifts
	cargo fmt --all -- --check

verify: fmt-check clippy test demo ## The full gate: format + lints + tests + self-test
	@echo "verify: all green"

clean: ## Remove build artifacts and demo VM homes
	cargo clean
	rm -rf ./vms

# --- search: knowledge graph first, grep second (graph has file:line evidence) ---
query: ## Graph search: make query Q="how does policy evaluation work?"
	graphify query "$(Q)" --budget 1200

path: ## Concept path: make path A=ToolGateway B=AuditWriter
	graphify path "$(A)" "$(B)"

explain: ## Explain a node: make explain N=Policy
	graphify explain "$(N)"

graph-update: ## Incremental graph refresh after structural changes (headless, cached)
	graphify update .

# --- debug: single-test repro with backtrace + untruncated output ---
debug-test: ## Repro one test: make debug-test F=traversal_denied [P=aivm-tools]
	RUST_BACKTRACE=1 cargo test $(if $(P),-p $(P),--workspace) $(F) -- --nocapture
