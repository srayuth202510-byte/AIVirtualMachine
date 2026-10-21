# ทางลัดนักพัฒนา AIVM ดูรายการด้วย `make help`
# ทุก target คือ cargo ธรรมดา ใช้ `rtk make <target>` ได้เหมือนกัน

.PHONY: help build check test test-adv test-coding test-llama test-microvm test-hardware test-container check-llama check-microvm check-hardware check-ci demo e2e llama-smoke clippy fmt fmt-check verify ci clean bench setup-host pins audit-pack query path explain graph-update debug-test

help: ## แสดงวิธีใช้นี้
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS=":.*?## "} {printf "  %-10s %s\n", $$1, $$2}'

build: ## คอมไพล์ทั้ง workspace
	cargo build --workspace

check: ## ตรวจ type เร็ว ไม่สร้างโค้ด
	cargo check --workspace --all-targets

test: ## เทสต์ unit + integration ทั้งหมด
	cargo test --workspace
	python3 -m unittest discover -s scripts -p 'test_qwen_*.py'
	python3 -m unittest discover -s scripts -p 'test_supervisor.py'
	python3 -m unittest discover -s scripts -p 'test_detection.py'
	python3 -m unittest discover -s scripts -p 'test_immunity.py'
	python3 -m unittest discover -s scripts -p 'test_pins.py'
	python3 -m unittest discover -s scripts -p 'test_security_court.py'
	python3 -m unittest discover -s scripts -p 'test_fuzz_seeded.py'
	python3 -m unittest discover -s scripts -p 'test_llama_replay.py'
	python3 -m unittest discover -s scripts -p 'test_model_host_validation.py'
	python3 scripts/eval-qwen-audit.py
	python3 scripts/smoke-qwen-watch.py

test-adv: ## ชุด must-deny อย่างเดียว (สเปก §38)
	cargo test -p aivm-adversarial

test-coding: ## ทดสอบ agent อ่าน/แก้โค้ด + GCC/ld + test binary จริง พร้อม adversarial quotas
	cargo test -p aivm-runtime --test coding_workflow

test-llama: ## คอมไพล์และทดสอบ local GGUF backend ที่อยู่หลังฟีเจอร์ llama
	cargo test -p aivm-model -p aivm-model-worker --features llama

check-llama: ## lint local GGUF backend และ worker ทุก target
	cargo clippy -p aivm-model -p aivm-model-worker --all-targets --features llama -- -D warnings

test-container: ## รัน container boundary tests จริง (ต้องตั้ง AIVM_CONTAINER_TEST_CONFIG)
	cargo test -p aivm-sandbox --test container

test-microvm: ## เทสต์ MicroVM ทั้งสาย (บูตจริงรันด้วยถ้าตั้ง AIVM_MICROVM_PINS)
	cargo test -p aivm-sandbox --features microvm
	cargo test -p aivm-tools --features microvm
	cargo test -p aivm-runtime --features microvm

check-microvm: ## lint โค้ดหลังฟีเจอร์ microvm ทั้งสาย (กันแก้พังเงียบ)
	cargo clippy -p aivm-sandbox -p aivm-tools -p aivm-runtime -p aivm-cli --all-targets --features microvm -- -D warnings

test-hardware: ## เทสต์ Hardware Isolation ทั้งสาย (บูตจริงรันด้วยถ้าตั้ง AIVM_HARDWARE_PINS)
	cargo test -p aivm-sandbox --features hardware
	cargo test -p aivm-tools --features hardware
	cargo test -p aivm-runtime --features hardware

check-hardware: ## lint โค้ดหลังฟีเจอร์ hardware ทั้งสาย (กันแก้พังเงียบ)
	cargo clippy -p aivm-sandbox -p aivm-tools -p aivm-runtime -p aivm-cli --all-targets --features hardware -- -D warnings

check-ci: ## กัน CI/docs drift (make ci ตรงกับ .github/workflows/ci.yml)
	python3 scripts/check-ci-parity.py

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

ci: verify e2e check-llama test-llama check-microvm test-microvm check-hardware test-hardware ## เหมือน CI บน GitHub: verify + วงจร CLI ครบ + llama + microvm + hardware

clean: ## ลบ build artifact กับบ้าน VM เดโม
	cargo clean
	rm -rf ./vms

bench: ## วัด demo/adversarial/audit คร่าวๆ (smoke-bench กัน regression)
	sh scripts/bench.sh

setup-host: ## ตรวจ host แบบอ่านอย่างเดียว สรุป Tier1/2/3
	sh scripts/setup-host.sh

pins: ## สร้าง pins.json จากไฟล์จริง: make pins KERNEL=.. ROOTFS=.. FC=.. OUT=.. (FC=- = โหมด hardware)
	sh scripts/make-pins.sh "$(KERNEL)" "$(ROOTFS)" "$(FC)" "$(OUT)"

audit-pack: ## รวมหลักฐานเตรียม external audit: make audit-pack [OUT=dir]
	sh scripts/audit-pack.sh "$(or $(OUT),./target/audit-pack-$(shell date -u +%F))"

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
