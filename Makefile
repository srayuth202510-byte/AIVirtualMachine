# ทางลัดนักพัฒนา AIVM ดูรายการด้วย `make help`
# ทุก target คือ cargo ธรรมดา ใช้ `rtk make <target>` ได้เหมือนกัน

.PHONY: help build check test test-adv test-microvm check-microvm demo e2e llama-smoke clippy fmt fmt-check verify ci clean query path explain graph-update debug-test

help: ## แสดงวิธีใช้นี้
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*?## "} {printf "  %-10s %s\n", $$1, $$2}'

build: ## คอมไพล์ทั้ง workspace
	cargo build --workspace

check: ## ตรวจ type เร็ว ไม่สร้างโค้ด
	cargo check --workspace --all-targets

test: ## เทสต์ unit + integration ทั้งหมด
	cargo test --workspace

test-adv: ## ชุด must-deny อย่างเดียว (สเปก §38)
	cargo test -p aivm-adversarial

test-microvm: ## เทสต์ MicroVM ทั้งสาย (บูตจริงรันด้วยถ้าตั้ง AIVM_MICROVM_PINS)
	cargo test -p aivm-sandbox --features microvm
	cargo test -p aivm-tools --features microvm
	cargo test -p aivm-runtime --features microvm

check-microvm: ## lint โค้ดหลังฟีเจอร์ microvm ทั้งสาย (กันแก้พังเงียบ)
	cargo clippy -p aivm-sandbox -p aivm-tools -p aivm-runtime -p aivm-cli --all-targets --features microvm -- -D warnings

demo: ## self-test เส้น enforcement ครั้งเดียว (ตาราง ALLOW/DENY, temp dir)
	cargo run -q -p aivm-cli -- demo

e2e: ## วงจร CLI ครบผ่าน scripts/smoke.sh (create/inspect/run/logs)
	sh scripts/smoke.sh

llama-smoke: ## ทดสอบโมเดล local จริง: make llama-smoke MODEL=/path/model.gguf [PROMPT='...']
	sh scripts/llama-smoke.sh "$(MODEL)" "$(PROMPT)"

clippy: ## ตรวจ lint เจอ warning คือตก
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## จัดฟอร์แมตโค้ดทั้งหมด
	cargo fmt --all

fmt-check: ## ตกถ้าฟอร์แมตเพี้ยน
	cargo fmt --all -- --check

verify: fmt-check clippy test demo ## ด่านรวม: format + lint + test + self-test
	@echo "verify: all green"

ci: verify e2e check-microvm test-microvm ## เหมือน CI บน GitHub: verify + วงจร CLI ครบ + microvm

clean: ## ลบ build artifact กับบ้าน VM เดโม
	cargo clean
	rm -rf ./vms

# --- ค้นหา: ถามกราฟก่อน ค่อย grep (กราฟมีหลักฐาน file:line) ---
query: ## ค้นกราฟ: make query Q="..."
	graphify query "$(Q)" --budget 1200

path: ## ทางระหว่าง concept: make path A=... B=...
	graphify path "$(A)" "$(B)"

explain: ## อธิบาย node: make explain N=...
	graphify explain "$(N)"

graph-update: ## รีเฟรชกราฟแบบเพิ่มทีละส่วนหลังแก้โครงสร้าง (headless, มี cache)
	graphify update .

# --- ดีบัก: จำลองเทสต์เดียวพร้อม backtrace + output เต็ม ---
debug-test: ## จำลองเทสต์เดียว: make debug-test F=... [P=...]
	RUST_BACKTRACE=1 cargo test $(if $(P),-p $(P),--workspace) $(F) -- --nocapture
