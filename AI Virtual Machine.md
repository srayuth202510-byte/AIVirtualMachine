AI Virtual Machine

«An isolated execution environment for autonomous AI agents, where the AI can reason freely but can only act within capabilities granted by the runtime.»

\---

1\. Vision

AI Virtual Machine (AIVM) คือ runtime สำหรับรัน AI Agent โดยเฉพาะ

แนวคิดหลัก:

Traditional VM  
    ↓  
Virtualize Hardware

Docker  
    ↓  
Isolate Processes

AI Virtual Machine  
    ↓  
Isolate AI Agency

AIVM ไม่ได้มีหน้าที่เพียง sandbox process แต่ต้องควบคุม:

\- AI State  
\- Memory  
\- Context  
\- Tools  
\- Filesystem  
\- Network  
\- Processes  
\- Compute Resources  
\- Capabilities  
\- State Transitions

หลักการสำคัญ:

«The AI may think, but the AI does not own the machine.»

\---

2\. Core Philosophy

AIVM ใช้หลักการ:

LLM \= Brain  
Cube \= State  
Capability \= Permission  
Policy \= Law  
Runtime \= Boundary  
Sandbox \= Physical Isolation

AI สามารถสร้างความคิดหรือคำสั่งได้อย่างอิสระ แต่การกระทำทุกอย่างต้องผ่าน Runtime

AI  
 │  
 │ Intent  
 ▼  
Cube  
 │  
 │ Capability Check  
 ▼  
Policy Engine  
 │  
 ├── DENY  
 │  
 └── ALLOW  
        │  
        ▼  
      Tool  
        │  
        ▼  
     Sandbox

AI ไม่มี direct access ไปยัง Host OS

\---

3\. Goals

Primary Goals

1\. Run autonomous AI agents safely.  
2\. Isolate AI from the host operating system.  
3\. Provide capability-based permissions.  
4\. Maintain explicit AI state.  
5\. Control state transitions.  
6\. Isolate filesystem access.  
7\. Isolate network access.  
8\. Control CPU/RAM/GPU resources.  
9\. Provide controlled tool execution.  
10\. Provide persistent AI memory.  
11\. Support local and remote LLMs.  
12\. Make the runtime deterministic and observable.

\---

4\. Non-Goals

AIVM ไม่ใช่:

\- General purpose VM  
\- Cloud orchestration system  
\- LLM training framework  
\- RAG database เพียงอย่างเดียว  
\- Docker replacement โดยตรง  
\- Agent framework แบบ LangChain replacement

AIVM เป็น:

«Execution and security boundary for autonomous AI.»

\---

5\. Architecture

                         HOST OS  
┌─────────────────────────────────────────────────────────┐  
│                                                         │  
│                    AI VM Runtime                        │  
│                                                         │  
│  ┌───────────────────────────────────────────────────┐  │  
│  │                   Supervisor                      │  │  
│  │                                                   │  │  
│  │  ┌─────────────┐      ┌──────────────────────┐  │  │  
│  │  │   Agent     │─────▶│      Cube Engine     │  │  │  
│  │  │   Runtime   │      │                      │  │  │  
│  │  └─────────────┘      │ State                │  │  │  
│  │                       │ Context              │  │  │  
│  │                       │ Memory               │  │  │  
│  │                       │ Capability           │  │  │  
│  │                       └──────────┬───────────┘  │  │  
│  │                                  │              │  │  
│  │                                  ▼              │  │  
│  │                       ┌──────────────────────┐ │  │  
│  │                       │    Policy Engine     │ │  │  
│  │                       └──────────┬───────────┘ │  │  
│  │                                  │              │  │  
│  │             ┌────────────────────┼───────────┐  │  │  
│  │             ▼                    ▼           ▼  │  │  
│  │          Filesystem            Tools       Network  
│  │             │                    │           │  │  
│  │             └────────────────────┼───────────┘  │  │  
│  │                                  ▼              │  │  
│  │                           Sandbox Layer         │  │  
│  └───────────────────────────────────────────────────┘  │  
│                                                         │  
│                    Linux / Hypervisor                   │  
└─────────────────────────────────────────────────────────┘

\---

6\. AI VM Layers

Layer 0 — Hardware

CPU  
RAM  
GPU  
NPU  
Storage  
Network

\---

Layer 1 — Host OS

Initial target:

Linux

Required primitives:

\- namespaces  
\- cgroups  
\- seccomp  
\- capabilities  
\- mount isolation  
\- network namespaces  
\- process isolation

Future:

KVM  
Firecracker  
MicroVM

\---

7\. Layer 2 — AI Supervisor

Supervisor เป็น process ที่อยู่นอก AI sandbox

หน้าที่:

Start VM  
Stop VM  
Pause VM  
Kill VM  
Monitor VM  
Manage resources  
Manage capabilities  
Manage state

ตัวอย่าง:

aivm run coder  
aivm stop coder  
aivm inspect coder  
aivm kill coder

Supervisor ต้องเป็น trusted component

AI ไม่สามารถแก้ Supervisor ได้

\---

8\. Layer 3 — Cube Engine

Cube คือหัวใจของ AIVM

Cube ทำหน้าที่เป็น:

AI State  
Context  
Memory  
Capability State  
Policy Context  
Temporal State

\---

9\. Cube State Model

### 9.1 พื้นฐาน

Cube ใช้การจัดระเบียบข้อมูลตามมิติ:

X \= Domain  
Y \= Concept  
Z \= Time  
T \= Confidence

ตัวอย่าง:

Domain     \= filesystem  
Concept    \= project/auth.rs  
Time       \= current task  
Confidence \= 0.94

### 9.2 Cube Cell Structure

Cube Cell ไม่ได้ถูกออกแบบเพื่อเก็บเพียง Knowledge แต่เป็น Security Context ของ AI ใน State นั้น ๆ

```rust
struct CubeCell {
    status_flags: u8,

    domain_id: u32,
    concept_id: u32,

    state_id: u32,

    confidence: u8,

    capability_mask: u64,

    policy_id: u32,

    timestamp: u64,
    access_count: u64,
    last_accessed: u64,
}
```

### 9.3 State Retention Strategy (ป้องกัน State Explosion)

เพื่อป้องกันไม่ให้ Cube เติบโตไม่จำกัดใน Session ยาว มีหลักการจัดการ State ดังนี้:

#### 9.3.1 Projection-Based Design (Event Sourcing)

Cube ไม่ควรเก็บประวัติการกระทำทั้งหมดไว้ใน Memory โดยตรง แต่ควรใช้หลักการ:

1. **Current Projection เท่านั้น**: `Cube.current_state()` จะเก็บเฉพาะสถานะปัจจุบัน (Working Projection) จาก Events ที่ผ่านมา
2. **Events อยู่ภายนอก Sandbox**: ทุก Action ที่ผ่าน Tool Gateway จะถูกบันทึกเป็น Immutable Event ใน Audit Log
3. **Snapshot + Compaction**: ทุก N Events หรือเมื่อเกิด State Transition ให้สร้าง Snapshot แล้ว Archive Events ที่เก่ากว่าเกินกำหนด
4. **Replay On-Demand**: สามารถสร้าง Projection ใหม่จาก Events ได้เสมอ แต่ไม่จำเป็นต้องโหลดทั้งหมดไว้ใน RAM

#### 9.3.2 Working Set Management

- **Working Set Only**: เก็บเฉพาะ `(domain, concept)` ที่อยู่ใน Active Working Set ในขณะนั้น ไม่โหลด Knowledge/Context ทั้ง Repo ลงใน Cube
- **Per-Task Cube**: แยก Cube Instance ต่อ Task แทนการใช้ Global Cube ตลอดทั้ง Session เพื่อลด Scope ลงอย่างมาก
- **LRU Eviction**: มี Hard Cap (`max_cells`, `max_domains`) หากเกินกำหนดจะทำ LRU Eviction แต่ **ห้าม Evict Cell ใด ๆ ที่เกี่ยวข้องกับ Current State, Active Transition หรือ Pending Capability** โดยเด็ดขาด
- **Time-Based TTL**: Concept ที่ไม่มีการ Access เกินเวลาที่กำหนด (X นาที) จะถูก Archive ไปยัง Persistent Storage ไม่ลบทิ้งจากระบบ
- **Archive ไม่ได้หมายถึง Delete**: ข้อมูลที่ถูก Archive ยังคงอยู่ใน Audit Log (Append-Only) อยู่แล้ว Cube ใน Memory ไม่จำเป็นต้องเก็บครบทุกอย่าง

#### 9.3.3 Memory Guarantees

- **Fail-Closed on Eviction**: หากไม่สามารถระบุได้แน่ชัดว่า Cell นั้น Safe ที่จะ Evict → ห้าม Evict และ Log Warning แทน
- **Deterministic Projection**: การสร้าง Projection จาก Events ต้องเป็น Deterministic เสมอ (ไม่ขึ้นกับ Order ของ Eviction)
- **State Integrity Check**: ก่อนและหลัง Compaction/Snapshot ต้องมี Integrity Check เพื่อยืนยันว่า Current State ไม่เสียหาย

\---

10\. Capability Model

Capability คือสิทธิ์ในการกระทำแบบ Granular (Least Privilege) โดยมีขอบเขตที่ชัดเจน

### 10.1 Primitive Actions

Primitive Actions ที่รองรับ:

READ  
WRITE  
EXECUTE  
NETWORK  
SPAWN  
GPU  
SECRET  
DEPLOY  
DELETE  
RENAME  
MOUNT

### 10.2 Capability Structure

การระบุสิทธิ์เพียง Boolean ไม่เพียงพอ ต้องมี Scope ที่แม่นยำ

```rust
struct Capability {
    action: String,
    resource: String,
    scope: String,
    condition: Option<Condition>,
    expiration: Option<u64>,
    max_uses: Option<u64>,
    used_count: u64,
}
```

Field แต่ละตัวมีความสำคัญดังนี้:

- **action**: การกระทำที่อนุญาต (read, write, execute, network, ...)
- **resource**: ทรัพยากรที่เข้าถึงได้ (filesystem, process, network, secret, ...)
- **scope**: ขอบเขตการเข้าถึงที่เฉพาะเจาะจง (เช่น `/workspace`, `github.com`, `cargo test`)
- **condition**: เงื่อนไขเพิ่มเติม (เช่น ต้องอยู่ใน State `VALIDATE`, path ต้องเป็น canonical path)
- **expiration**: เวลาหมดอายุของ Capability (Time-Based Lease) — ป้องกัน Privilege Creep
- **max_uses**: จำนวนครั้งสูงสุดที่สามารถใช้ได้ (One-Time/Usage-Limited Lease)

### 10.3 หลักการออกแบบ

1. **Default Deny**: ทุก Action เริ่มจาก DENY, ต้องมี Capability ที่ชัดเจนเท่านั้นจึงจะ ALLOW
2. **Least Privilege**: อนุญาตเพียงเท่าที่จำเป็น (Need-to-Know) ไม่กว้างเกินไป
3. **Time-Bounded**: ควรมี `expiration` สำหรับ Capability ที่มีระดับความเสี่ยงสูง
4. **Usage-Bounded**: ใช้ `max_uses` สำหรับ Operation ที่ควรทำเพียงครั้งเดียว (เช่น Secret Access)
5. **State-Aware**: Capability สามารถถูกตรวจสอบร่วมกับ Current State (ดู 14. Dynamic Capability)

---

11\. Capability Example

```yaml
capabilities:
  - action: read
    resource: filesystem
    scope: /workspace

  - action: write
    resource: filesystem
    scope: /workspace/src

  - action: execute
    resource: process
    scope: "cargo test"

  - action: network
    resource: network
    scope: "github.com"
    condition:
      protocol: https

  - action: secret
    resource: github_token
    scope: "repo:write"
    expiration: 300  # หมดอายุใน 300 วินาที
    max_uses: 1       # ใช้ได้เพียงครั้งเดียว
```

AI สามารถทำเฉพาะสิ่งที่ Capability อนุญาต และต้องผ่านการตรวจสอบครบถ้วน (Capability Check + Policy Check + State Validation)

\---

12\. Capability Boundary

ทุก Action ต้องผ่าน Chain ของ Enforcement ที่เป็น Hard Boundary:

```text
Agent
  ↓
Intent (Reasoned Action)
  ↓
Cube (Current State + Context)
  ↓
Capability Resolver (Action + Resource + Scope + Expiration + Uses)
  ↓
Policy Engine (State-Aware + Conditional Rules)
  ↓
Tool Gateway (Canonicalization + TOCTOU Hardening)
  ↓
Tool Executor (Trusted Path)
  ↓
Sandbox (OS-Level Isolation)
```

### 12.1 Hard Enforcement Rules

**ห้ามโดยเด็ดขาด (No Direct Access):**

- Agent → syscall (ต้องผ่าน Tool Executor + seccomp allowlist เท่านั้น)
- Agent → shell (`/bin/sh`, `/bin/bash`, ตลอดจน shell interpreters โดยตรง)
- Agent → filesystem (ต้องผ่าน Filesystem Gateway + Path Canonicalization)
- Agent → network (ต้องผ่าน Network Gateway + Destination Allowlist)
- Agent → process spawn (ต้องผ่าน Process Executor ใน Trusted Path เท่านั้น)

### 12.2 Enforcement Guarantees

1. **Canonicalization ก่อน Check**: ทุก Path จะถูก Resolve เป็น Canonical Realpath ก่อนตรวจสอบ Scope (ป้องกัน Symlink Traversal + TOCTOU Race)
2. **Check-Then-Act + Re-Check**: ใช้หลักการ Defensive Programming โดยมีการ Verify ซ้ำก่อน Execution (TOCTOU Hardening)
3. **Fail-Closed ทุกจุด**: หากการตรวจสอบใด ๆ ล้มเหลว → `DENY` โดยไม่ Default เป็น Allow
4. **Trusted Path Separation**: Tool Executor, Gateway, Supervisor รันใน Trusted Domain แยกจาก AI Sandbox Completely

\---

13\. Policy Engine

Policy Engine เป็นกฎหมายของ AI VM (Security Policy Layer) ควบคุมว่า Action ใดที่มี Capability แล้ว ยังสามารถ Execute ได้ภายใต้ Context ปัจจุบันหรือไม่

### 13.1 หลักการ

1. **Deny-Overrides**: `deny` มี Priority สูงกว่า `allow` เสมอ (`deny_overrides: true`)
2. **Order-Independent**: ผลการ Evaluate ไม่ขึ้นกับลำดับของ Rules ใน Policy File
3. **Fail-Closed**: หาก Policy Parse ล้มเหลว, Evaluate ล้มเหลว หรือ Context ไม่ครบถ้วน → **DENY** ทันที (ไม่ Fallback ไป Allow)
4. **Deterministic**: Policy Evaluation ต้องเป็น Deterministic เสมอ (ไม่มี Time/Random ที่ไม่ได้ระบุใน Context อย่างชัดเจน)
5. **State-Aware**: Policy สามารถอิงกับ Current State, Transition, Confidence และ Temporal State ได้

### 13.2 Policy Structure

#### รูปแบบพื้นฐาน (MVP - RBAC + Path/Domain Allowlist)

```yaml
name: coding-default
deny_overrides: true

filesystem:
  read:
    - /workspace
  write:
    - /workspace/src
  deny:
    - /workspace/.git/config
    - "**/.env*"
    - "**/secrets/**"

process:
  allow:
    - /usr/bin/cargo
    - /usr/bin/rustc
    - /usr/bin/git
  deny:
    - /bin/sh
    - /bin/bash
    - /usr/bin/python3  # อนุญาตผ่าน Tool Gateway เท่านั้น หากจำเป็น

network:
  allow:
    - github.com
    - crates.io
  deny:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "172.16.0.0/12"
    - "127.0.0.1"
    - "::1"

system:
  allow: []
```

#### Advanced Policy ด้วย Conditions (Expression-Based)

Policy รองรับ Conditional Evaluation เพื่อรองรับ Use Case ซับซ้อน (AND/OR, Time-Based, Dependency, State-Dependent)

```yaml
rules:
  - id: allow_write_src
    action: write
    resource: filesystem
    scope: /workspace/src/**
    when: "state in {'MODIFY', 'VALIDATE'} && confidence >= 0.8"

  - id: require_test_before_network
    action: network
    resource: network
    scope: "*"
    when: "state == 'VALIDATE' && tests_passed == true"
    effect: allow

  - id: deny_network_during_analyze
    action: network
    resource: network
    scope: "*"
    when: "state == 'ANALYZE'"
    effect: deny
```

### 13.3 Policy Expression Language

แนะนำให้ใช้ **CEL (Common Expression Language)** เป็น Expression Engine เนื่องจาก:

- **เรียบง่ายและ Well-Specified**: ใช้กันอย่างแพร่หลายใน K8s, OPA lineage
- **Sandboxed & Safe**: ไม่สามารถ Execute Arbitrary Code ได้
- **Type-Safe & Deterministic**: ผลลัพธ์ชัดเจน ไม่ผันผวน
- **Sweet Spot**: ยืดหยุ่นพอสำหรับ Use Case ซับซ้อน แต่ไม่ Over-Engineered เหมือน Full Datalog

**MVP Recommendation**: เริ่มด้วย YAML + Simple Boolean (`&& || !`) ก่อน ค่อยย้ายไป CEL เมื่อจำเป็นต้องมี Logic ซับซ้อน

### 13.4 Policy Enforcement Principles

1. **Precedence Explicit**: เสมอใช้ `deny_overrides` และ Treat `effect: deny` ว่า Stronger
2. **Default-Deny at Rule Level**: ถ้าไม่ Match Rule ใดเลย → DENY
3. **Context Completeness**: ต้องมี Context ครบถ้วน (state, path, capability, timestamp) ก่อน Evaluate
4. **Fail-Closed on Evaluation Error**: Expression Error, Type Mismatch, Missing Context → DENY

\---

14\. Dynamic Capability

Capability สามารถเปลี่ยนแปลงตาม AI State, Context และผลลัพธ์ที่เกิดขึ้น (State-Driven Least Privilege)

### 14.1 หลักการ

Dynamic Capability คือการที่สิทธิ์จะถูก **Grant หรือ Revoke** ตาม Progress ของ Agent โดยอิงกับ State Machine และ Validation Results แทนการให้สิทธิ์ทั้งหมดตั้งแต่แรก

### 14.2 ตัวอย่างการเปลี่ยนแปลงตาม State

**Initial State (INIT):**
```yaml
capabilities:
  - read:workspace
  - search:code
```

**หลังจาก AI วิเคราะห์สำเร็จ (ANALYZE → MODIFY, confidence > threshold):**
```yaml
capabilities:
  - read:workspace
  - search:code
  - write:workspace/src
  - execute:cargo_test
```

**หลัง Test ผ่าน (MODIFY → VALIDATE, tests_passed == true):**
```yaml
capabilities:
  - read:workspace
  - search:code
  - write:workspace/src
  - execute:cargo_test
  - network:github.com  # เฉพาะใน State VALIDATE เท่านั้น
```

**Deploy ยังไม่สามารถทำได้ (ยังไม่ถึง DEPLOY State + ไม่ผ่าน Policy):**
```yaml
# DEPLOY จะไม่ถูก Grant จนกว่าจะผ่าน Validation + Policy ทุกอย่าง
# และมักจะต้องมี Human-in-the-Loop (HITL) เพิ่มเติม
```

### 14.3 หลักการควบคุม Dynamic Capability

1. **Monotonicity with Constraints**: Capability สามารถถูกเพิ่มขึ้นได้เมื่อผ่าน Validation แต่การ Revoke ต้องเป็น Explicit และ Traceable ใน Audit
2. **State-Gated Grant**: การ Grant Capability ใหม่ต้องอยู่ภายใต้ Valid State Transition เท่านั้น (ไม่สามารถ Grant ข้าม State ได้)
3. **Time-Bounded**: Dynamic Capability ที่เพิ่มขึ้นควรมี `expiration` โดยเฉพาะถ้าเป็น High-Privilege (เช่น NETWORK, SECRET, DEPLOY)
4. **Just-In-Time (JIT)**: สำหรับ Operation ที่เสี่ยงสูง ควร Grant เป็น Scoped + Short-Lived + Auto-Revoke ทันทีหลัง Execution
5. **Auditable**: ทุกการ Grant/Revoke จะถูกบันทึกใน Audit Log (Outside Sandbox) โดยไม่สามารถถูกแก้ไขได้
6. **Re-Evaluate on State Change**: เมื่อ State เปลี่ยน, Capability ที่หมดเงื่อนไขจะถูก Revoke หรือ Invalidated โดยอัตโนมัติ

\---

15\. State Transition

AI State ต้องเปลี่ยนผ่าน transition ที่ถูกต้อง

INIT  
  │  
  ▼  
ANALYZE  
  │  
  │ confidence \> threshold  
  ▼  
MODIFY  
  │  
  │ tests passed  
  ▼  
VALIDATE  
  │  
  │ policy approved  
  ▼  
DEPLOY

AI ไม่สามารถกระโดด:

INIT → DEPLOY

ได้โดยตรง

เว้นแต่ policy อนุญาต

\---

16\. Tool Gateway

Tools ต้องถูกเรียกผ่าน gateway

AI  
 │  
 │ tool\_call  
 ▼  
Tool Gateway  
 │  
 ▼  
Capability Check  
 │  
 ▼  
Policy Check  
 │  
 ▼  
Tool Executor

ตัวอย่าง:

{  
  "tool": "filesystem.write",  
  "path": "/workspace/src/main.rs",  
  "content": "..."  
}

Gateway ตรวจ:

Is WRITE allowed?  
Is path allowed?  
Is current state valid?  
Is capability expired?  
Does policy allow it?

ถ้าไม่ผ่าน:

DENIED

\---

17\. Filesystem Isolation

AI VM มี Virtual Filesystem แบบ Sandbox (Path-Constrained)

### 17.1 Filesystem Layout

```text
/
├── workspace/  (Project/Working Directory)
├── memory/     (Session/Persistent Memory - ไม่ใช่ AI Context Dump)
├── model/      (Model Artifacts - Read-Only)
├── tmp/        (Ephemeral, Size-Limited ด้วย cgroups)
└── tools/      (Trusted Tool Binaries - Read-Only)
```

### 17.2 Isolation Principles

Host Filesystem **ไม่ถูก Expose โดยตรง** ให้กับ AI Sandbox

**ตัวอย่าง:**

- Host: `/home/user/private`, `/home/user/.ssh`, `/etc`, `/root`
- AI เห็น: `/workspace` เท่านั้น (Mount Bind แบบ Read-Only/Read-Write ตาม Scope ที่กำหนด)

AI **ไม่ควรเห็นหรือเข้าถึง**:

- `/home/user/private`
- `/etc`
- `/root`
- `.ssh`
- `.env`, `*.env`, `secrets/`
- Policy, Config, Supervisor Binary, Audit Directories

เว้นแต่ Capability + Policy จะอนุญาตอย่าง **ชัดเจนและ Scoped** เท่านั้น

### 17.3 Path Hardening

1. **Canonicalization**: ทุก Path Request จะถูก Resolve เป็น Canonical Realpath (`realpath`) ก่อนตรวจสอบ
2. **No Symlink Escape**: ตรวจสอบว่า Resolved Path ยังอยู่ภายใน Allowed Mount Points หลัง Canonicalization (ป้องกัน Symlink Traversal)
3. **TOCTOU Hardening**: ใช้ `openat()` + `O_NOFOLLOW` เมื่อเป็นไปได้ และ Re-Validate ก่อน Execution
4. **Mount Namespace**: ใช้ Mount Namespace แยกจาก Host, Host Paths ที่ไม่จำเป็นจะไม่ถูก Mount เลย (Principle of Least Exposure)
5. **Read-Only Boundary**: Policy/Config Paths ถูก Mount เป็น `ro` (Read-Only), Supervisor Paths ควรเป็น Immutable/Read-Only
6. **Deny Write to Sensitive Paths**: Tool Gateway จะ Explicitly Deny WRITE/DELETE/RENAME ไปยัง Boundary Directories เสมอ

\---

18\. Network Isolation

Network ไม่ใช่ "Default Allow" แต่เป็น **Explicit-Allow โดยผ่าน Gateway เท่านั้น**

### 18.1 Network Flow

```text
AI (Sandbox)
  ↓
Network Gateway (Trusted, Outside Sandbox)
  ↓
Policy Engine (Destination + Protocol + State Check)
  ↓
Capability Check (network action + scope)
  ↓
Destination (Allowlisted Only)
```

### 18.2 Default Policy

**Default: DENY ALL** — ไม่มี Network Access เว้นแต่ Allowlist อย่างชัดเจน

```yaml
network:
  allow:
    - github.com
    - crates.io
  deny:
    - "10.0.0.0/8"      # RFC1918 Private
    - "192.168.0.0/16"
    - "172.16.0.0/12"
    - "127.0.0.1"       # Loopback
    - "::1"
    - "169.254.0.0/16"  # Link-local
    - "100.64.0.0/10"   # CGNAT/Cloud Metadata
    # Cloud Metadata Endpoints (High Risk)
    - "169.254.169.254" # AWS/Azure/GCP Metadata
```

### 18.3 Network Hardening

1. **Egress-Only**: AI Sandbox มี Network Namespace แบบ Isolated, Default เป็น `down` หรือ No Default Route, อนุญาตเฉพาะ Egress ที่ผ่าน Gateway
2. **DNS Policy**: DNS Resolution ผ่าน Trusted Resolver, อาจจำกัด Domain Resolution เฉพาะ Allowlist
3. **Protocol Restriction**: กำหนด Protocol/Port (เช่น `https` เท่านั้น) ผ่าน Capability Condition
4. **State-Aware Access**: Network Access ควรถูกควบคุมด้วย State (เช่น `require_test_before_network: true`) ตาม 13.2
5. **No Direct Sockets**: AI ไม่สามารถเปิด Raw Socket/Bind ได้ (ถูก Block โดย seccomp + Network Namespace)
6. **Private Network Block**: Block Private/Loopback/Link-Local/Metadata Endpoints โดย Default (Defense-in-Depth)

\---

19\. Resource Isolation

AI VM ต้องมี resource quota

resources:

  cpu: 4

  memory: 8GB

  storage: 20GB

  gpu:  
    enabled: true  
    memory: 8GB

  processes: 64

ใช้:

cgroups

สำหรับ MVP

และ:

GPU isolation  
NVIDIA MIG  
device filtering

ใน future

\---

20\. Memory System

AIVM มี memory หลายระดับ:

Short-term Context  
       ↓  
Working Memory  
       ↓  
Session Memory  
       ↓  
Persistent Memory

Cube สามารถทำหน้าที่เป็น index/state layer

LLM  
 ↓  
Context Request  
 ↓  
Cube  
 ↓  
Memory Retrieval  
 ↓  
Relevant Context  
 ↓  
LLM

\---

21\. CubeRAG Integration

CubeRAG เป็น subsystem ของ AIVM

AIVM  
│  
├── Cube State  
│  
├── Capability  
│  
├── Policy  
│  
└── CubeRAG  
      ├── Chunking  
      ├── Retrieval  
      ├── Ranking  
      └── Context Assembly

CubeRAG มีหน้าที่ตอบ:

«What information should the AI see?»

Capability Engine ตอบ:

«What actions may the AI perform?»

State Engine ตอบ:

«What state is the AI currently in?»

\---

22\. Agent Runtime

Agent Runtime เป็น execution loop:

Observe  
   ↓  
Retrieve Context  
   ↓  
Reason  
   ↓  
Generate Intent  
   ↓  
Capability Check  
   ↓  
Execute  
   ↓  
Observe Result  
   ↓  
Update Cube  
   ↓  
Repeat

\---

23\. AI VM Main Loop

loop {  
    let state \= cube.current\_state();

    let context \= memory.retrieve(\&state);

    let intent \= agent.reason(context);

    let decision \= policy.evaluate(  
        \&state,  
        \&intent  
    );

    match decision {  
        Allow(capability) \=\> {  
            let result \= tools.execute(  
                capability,  
                intent  
            );

            cube.update(result);  
        }

        Deny(reason) \=\> {  
            cube.record\_denial(reason);  
        }  
    }  
}

\---

24\. Security Model

AIVM ใช้ **Defense-in-Depth** (หลายชั้นของการป้องกัน, Independent Layers)

```text
                AI (Untrusted)
                 │
        ┌────────▼────────┐
        │  State Boundary  │  (State Transition Validation)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │ Capability Layer │  (Action + Scope + Expiration)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │   Policy Layer   │  (Deny-Overrides + State-Aware)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │   Tool Gateway   │  (Canonicalization + TOCTOU + Check-Then-Act)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  Tool Executor   │  (Trusted Path, Seccomp-Hardened)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  Sandbox Layer   │  (Namespaces + cgroups + Landlock)
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  OS Isolation    │  (seccomp-BPF Allowlist + No Privs)
        └────────┬────────┘
                 │
                 ▼
                HOST
```

### 24.1 Security Principles

- **Never Trust the Agent. Trust the Boundary.** — AI ถือเป็น Adversary โดย Default แม้จะเป็น Well-Behaved Model
- **Fail-Closed by Default**: ทุกชั้นต้อง Default เป็น DENY
- **Principle of Least Privilege**: อนุญาตเท่าที่จำเป็นเท่านั้น, มี Scope ที่แคบที่สุด
- **Structural > Logical**: ใช้ Enforcement แบบ Structural (mount, namespace, seccomp, FS attrs) มากกว่า Logical Checks เพียงอย่างเดียว
- **Defense-in-Depth, Independent Failure**: หากชั้นหนึ่งพลาด ชั้นถัดไปยังคงป้องกันได้
- **Complete Mediation**: ทุก External Action ต้องผ่าน Mediation Point ทั้งหมด (Complete Mediation)

\---

25\. Audit System

ทุก Action, Decision, Grant/Revoke, Denial, Capability Change, State Transition ต้องถูก Audit อย่างสมบูรณ์และตรวจสอบย้อนหลังได้

### 25.1 Audit Record Schema

```json
{
  "timestamp": 1730000000,
  "agent": "coder",
  "state": "MODIFY",
  "action": "write",
  "resource": "/workspace/src/auth.rs",
  "decision": "allow",
  "policy": "coding-default",
  "capability": "write:workspace/src",
  "result": "success",
  "request_id": "req_9f7e3a82",
  "session_id": "sess_coder_001",
  "rule_matched": "allow_write_src",
  "state_transition": "ANALYZE->MODIFY",
  "hash_prev": "e8f2a903...",
  "hash_entry": "b7c943e1..."
}
```

Field เพิ่มเติมที่ควรบันทึก:
- **request_id**: Correlation ID สำหรับทุก Request
- **hash_prev + hash_entry**: ใช้สำหรับ Hash Chaining (Tamper-Evident)
- **capability_state**: ก่อน/หลัง (กรณี Dynamic Capability Grant/Revoke)
- **secret_request**: สำหรับ Secret Requests (เหตุผลเป็น Metadata เท่านั้น, ห้าม Log Secret Value)
- **rule_matched**: Policy Rule ID ที่ Match (เพื่อการตรวจสอบ)

### 25.2 Tamper-Proof Requirements

Audit Log ต้องได้รับการคุ้มครองให้เป็น **Tamper-Evident + Append-Only**

1. **Outside Sandbox**: Audit Log อยู่ภายนอก AI Sandbox เสมอ, AI ไม่มีสิทธิ์เข้าถึง Audit Directory/Socket
2. **Append-Only FS**: ใช้ `chattr +a` บน Audit Files/Directories (สามารถเขียนเพิ่มได้เท่านั้น, ห้าม Truncate/Delete/Overwrite)
3. **Immutable on Seal**: หลัง Rotation/Close, ตั้งค่าเป็น `chattr +i` หรือเก็บเป็น Read-Only
4. **Hash Chaining / Merkle Tree**: ทุก Record เชื่อมโยงกับ Hash ของ Record ก่อนหน้า (`prev_hash`) เพื่อสร้าง Tamper-Evident Chain
5. **Monotonic Sequence**: ใช้ Strictly Increasing Sequence Number เพื่อตรวจจับ Gap/Replay
6. **Unidirectional Write**: ใช้ One-Way Pipe/Unix Domain Socket จาก Sandbox → Audit Writer (Trusted Process) AI ไม่สามารถ Read ได้
7. **Redaction by Default**: ทุก Sensitive Data (Secrets, Tokens, Keys) จะถูก Redact อัตโนมัติ ห้ามบันทึกลง Audit Log
8. **Durability**: `fsync`/`fdatasync` หลังเขียน Entry สำคัญ
9. **Secure Rotation**: Rotate เป็นไฟล์ใหม่ → Compute Hash/Seal → Sign (ถ้ามี) ก่อน Archive
10. **Out-of-Band Shipping (Production)**: ส่งไป External WORM Storage (Append-Only Log Store) แยกจาก Host สำหรับ Strongest Protection

### 25.3 Audit Guarantees

- **AI ไม่สามารถแก้ไขย้อนหลังได้**: เนื่องจากอยู่นอก Sandbox + Append-Only + Hash Chain
- **Complete Coverage**: ทุก Decision (Allow/Deny) ต้องถูก Log (รวมถึง Denied Attempts)
- **Integrity Verification**: สามารถ Verify Audit Chain ได้แบบ Offline (Audit the Audit)
- **Non-Repudiation**: มี Request ID + Session ID + Traceable Path

\---

26\. Secrets

Secrets **ไม่ควร** อยู่ใน Environment ของ AI Sandbox โดยตรง (ไม่ปล่อยให้ AI Process ทั้งก้อนอ่านได้)

### 26.1 Flow แบบ Zero-Trust

```text
AI (Sandbox)
  ↓
Secret Request (Structured Schema)
  ↓
Capability Check (secret action + scope + expiration + max_uses)
  ↓
Policy Check (State-Aware + Risk Assessment)
  ↓
Risk Evaluation (HITL Gate สำหรับ High-Risk)
  ↓
Secret Broker (Trusted, Outside Sandbox)
  ↓
Tool Executor (Inject เฉพาะ Invocation ที่จำเป็น)
  ↓
Zeroize Immediately after Execution
```

### 26.2 หลักการ Zero-Trust สำหรับ Secrets

1. **No Global Exposure**: ไม่ตั้ง Environment Variable ทั้งหมดให้ AI Process อ่านได้ (เช่น `GITHUB_TOKEN`, `OPENAI_API_KEY`)
2. **Tool-Scoped Injection**: Secret จะถูก Inject เข้าไปเฉพาะ Tool Executor (env/argv/fd) ที่จำเป็นเท่านั้น **ไม่ส่งกลับไปยัง AI Context, Memory, Cube, Tool Result**
3. **Structured Request Only**: AI ต้องร้องขอผ่าน Schema ที่แคบ:

```json
{
  "tool": "git.push",
  "resource": "github_token",
  "scope": "repo:write",
  "purpose": "push_to_origin"
}
```

4. **Justification is Metadata, Not Trust**: "เหตุผล" ของ AI จะถูกเก็บใน Audit เท่านั้น **ไม่ใช่ Signal ที่ Override Policy หรือ Capability**
5. **Time-Bounded & Usage-Limited**: ทุก Secret มี `expiration` + `max_uses` (เช่น ใช้ครั้งเดียว, หมดอายุใน 5 นาที)
6. **State-Gated**: Secret Request ต้องผ่าน State Validation (เช่น `require_test_before_network=true` + อยู่ใน State `VALIDATE`)
7. **Risk-Based Human-in-the-Loop (HITL)**: 
   - **Low-Risk**: Read-Only Token, Scoped แคบมาก อาจ Auto-Allow (กรณีที่ Policy อนุญาตชัดเจน)
   - **High-Risk**: Write/Deploy, Token เข้าถึง Production, Destructive Operations → **Default: Require HITL**
8. **One-Time Lease**: จัดสรร Lease ชั่วคราว, Auto-Revoke ทันทีหลัง Tool Execution เสร็จ
9. **Non-Exfiltrable**: Secret Broker **ห้าม Log Secret Value** ทุกช่องทาง, มี Redaction อัตโนมัติใน Audit
10. **Zeroization**: ล้าง Memory/FD ทันทีหลังใช้งาน (Secure Erase)
11. **Break-Glass Path**: มี Explicit Break-Glass สำหรับ Admin แยกจาก Agent Path

### 26.3 Anti-Social-Engineering Safeguards

- **Treat AI Justification Skeptically**: ไม่พึ่ง Prompt-Based Justification
- **Rate-Limit & Quota**: จำกัดจำนวน Secret Requests ต่อ Session/Time เพื่อตรวจจับ Probing
- **Cross-Check with Capability**: Request Scope ต้อง Match กับ Capability ที่ AI มีอยู่เท่านั้น (ไม่ขยาย Scope ได้)
- **Audit All Requests**: ทุก Secret Request (Granted/Denied/Cancelled) ถูก Log พร้อม Metadata (ไม่รวม Secret)

**MVP Recommendation**: เริ่มด้วย **Tool-Scoped + One-Time Lease + Structured Schema + HITL Default สำหรับ High-Risk Operations**

\---

27\. VM Levels

AIVM แบ่ง Security Level ตามระดับ Isolation (Progressive Hardening)

### Level 0 — Process Sandbox (MVP Target)

- Linux Namespaces (mnt, pid, net, ipc, uts)
- cgroups v1/v2 (CPU, Memory, PIDs, I/O)
- seccomp-BPF (Allowlist + KILL_PROCESS)
- Landlock (FS+IPC Restrictions) — แนะนำให้เพิ่มตั้งแต่ MVP+
- Capability Dropping (Drop All Unnecessary Linux Caps)
- No New Privileges

**เหมาะสำหรับ**: Controlled Agents, Trusted Workloads, MVP Development

---

### Level 1 — Container Sandbox

- OCI Runtime (runc/crun) 
- \+ AIVM Policy Engine (State-Aware)
- \+ Cube Engine (State + Capability)
- \+ Tool Gateway (Complete Mediation)
- \+ Hardened seccomp/Apprmor/Profile
- \+ Read-Only Root FS (Selective)

**เหมาะสำหรับ**: General Purpose Coding Agents ที่ต้องการ Isolation ดีกว่า Process Sandbox

---

### Level 2 — MicroVM

- KVM + Firecracker (Minimal Attack Surface)
- \+ AIVM Boundary Layers
- \+ Virtio-Network with Gateway Control
- \+ Virtio-FS/9p หรือ Block Device แบบ Constrained
- \+ vCPU/Memory Quota
- \+ Minimal Kernel/Init

**เหมาะสำหรับ**: Untrusted Autonomous Agents, Multi-Tenant Scenarios

---

### Level 3 — Hardware-Isolated AI VM (Future)

- Hardware Hypervisor (KVM/SNP/TDX หรือ Baremetal)
- GPU/NPU Isolation (MIG, SR-IOV, vGPU)
- Secure Boot + Measured Boot
- TEE (Trusted Execution Environment)
- Remote Attestation
- Confidential Computing
- Disk Encryption + Secure Key Storage

**เหมาะสำหรับ**: Production/High-Security, Regulated Environments, Sensitive Data

### Migration Path

Architecture ด้านบน (Cube, Capability, Policy, Tool Gateway, Audit) **ไม่ต้องเปลี่ยน** เมื่อย้ายจาก Level 0 → 1 → 2 → 3 เนื่องจากเป็น Conceptual Model เดียวกัน (Boundary-Oriented Design)

\---

28\. Configuration

ตัวอย่าง "aivm.yaml"

name: coder

runtime:  
  isolation: sandbox

model:  
  provider: local  
  name: qwen

resources:  
  cpu: 4  
  memory: 8GB  
  storage: 20GB

filesystem:  
  read:  
    \- ./repo

  write:  
    \- ./repo/src

network:  
  allow:  
    \- github.com  
    \- crates.io

tools:  
  allow:  
    \- git  
    \- cargo  
    \- rustc

capabilities:  
  initial:  
    \- read:workspace  
    \- search:code

policy:  
  require\_test\_before\_network: true

\---

29\. CLI

aivm create coder

aivm run coder

aivm inspect coder

aivm state coder

aivm capabilities coder

aivm logs coder

aivm pause coder

aivm kill coder

\---

30\. Inspect

คำสั่ง:

aivm inspect coder

ควรแสดง:

AI VM: coder

State:  
  ANALYZE

Model:  
  qwen

Resources:  
  CPU      4  
  Memory   8 GB  
  GPU      1

Capabilities:  
  READ     /workspace  
  SEARCH   /workspace

Denied:  
  WRITE  
  NETWORK  
  DEPLOY

Network:  
  github.com     DENIED

Processes:  
  3

Memory:  
  128 MB

\---

31\. Project Structure

Initial Rust project:

aivm/  
│  
├── Cargo.toml  
│  
├── crates/  
│   │  
│   ├── aivm-cli/  
│   │  
│   ├── aivm-supervisor/  
│   │  
│   ├── aivm-runtime/  
│   │  
│   ├── aivm-cube/  
│   │  
│   ├── aivm-policy/  
│   │  
│   ├── aivm-capability/  
│   │  
│   ├── aivm-sandbox/  
│   │  
│   ├── aivm-tools/  
│   │  
│   ├── aivm-memory/  
│   │  
│   ├── aivm-network/  
│   │  
│   ├── aivm-audit/  
│   │  
│   └── aivm-model/  
│  
├── policies/  
│  
├── examples/  
│  
└── tests/

\---

32\. MVP

MVP ไม่ควรเริ่มด้วย Hypervisor แต่เน้น **Hard Enforcement** ให้ได้ก่อน

### MVP Stack

```text
Linux (Host Primitives)
 + Rust
 + Namespaces (mnt, pid, net, ipc, uts)
 + cgroups v2 (CPU, Memory, PIDs, I/O)
 + seccomp-BPF (Allowlist + KILL_PROCESS)
 + Landlock (FS/IPC) — Recommended
 + Capability Dropping (No Unnecessary Caps, No New Privileges)
 + Cube Engine (Projection-Based + Hard Cap)
 + Capability Engine (Time/Usage-Bounded)
 + Policy Engine (Deny-Overrides + Fail-Closed)
 + Tool Gateway (Canonicalization + TOCTOU)
 + Audit Writer (Append-Only + Outside Sandbox)
 + Secret Broker (Tool-Scoped, HITL-Gated) — Minimal Viable
```

### MVP Goal (Hard Acceptance Criteria)

> «Run an AI coding agent that **cannot** access anything outside its declared workspace, **cannot** spawn arbitrary processes/shells, **cannot** make arbitrary syscalls, and **every** external action is mediated, authorized, auditable and deny-by-default.»

### MVP Security Baseline

- **Fail-Closed Everywhere**: Parse/Error/Eval → DENY
- **Structural Enforcement**: Mount ro, seccomp allowlist, no CAP_SYS_ADMIN, boundary paths explicitly denied
- **Adversarial-First**: มี Negative Test Suite (Must-Deny) ตั้งแต่ Phase 1
- **Tamper-Evident Audit**: Append-Only (+a) + Outside Sandbox + Hash Chain (minimum)

\---

33\. MVP Milestones

Phase 1 — Sandbox

\- Process isolation  
\- Filesystem isolation  
\- Resource limits  
\- Process lifecycle

\---

Phase 2 — Capability

\- Capability model  
\- Capability verification  
\- Resource scopes  
\- Expiration  
\- Deny-by-default

\---

Phase 3 — Cube

\- Cube state  
\- State transitions  
\- Context state  
\- Capability state  
\- Confidence  
\- Temporal state

\---

Phase 4 — Tool Gateway

\- filesystem  
\- process  
\- git  
\- compiler  
\- test runner  
\- network

ทุก tool ต้องผ่าน capability verification

\---

Phase 5 — Agent Runtime

Observe  
→ Reason  
→ Intent  
→ Capability  
→ Execute  
→ Observe

\---

Phase 6 — CubeRAG

\- code chunking  
\- indexing  
\- retrieval  
\- reranking  
\- context assembly  
\- state-aware retrieval

\---

Phase 7 — MicroVM

เปลี่ยน isolation layer:

Linux Sandbox  
     ↓  
MicroVM

โดย architecture ด้านบนยังเหมือนเดิม

\---

34\. Critical Design Principle

AIVM ต้องแยก:

Thinking

ออกจาก:

Acting

LLM สามารถคิด:

"I should delete this file."

แต่ไม่ได้หมายความว่า:

delete(file)

จะเกิดขึ้น

ต้องผ่าน:

Intent  
 ↓  
Capability  
 ↓  
Policy  
 ↓  
Tool

นี่คือหัวใจของระบบ

\---

35\. Security Invariant

AIVM ต้องรักษา Security Invariants ต่อไปนี้เสมอ (Non-Negotiable):

1. **`I-1`**: AI cannot directly access host resources. (No Direct Syscalls, No Direct FS/Net/Proc Access)
2. **`I-2`**: Every external action must have a capability. (Complete Mediation + Capability Required)
3. **`I-3`**: Every capability must have a policy. (Policy Evaluation Required, Deny-Overrides)
4. **`I-4`**: Every state transition must be validated. (State Machine Enforcement, No Unvalidated Jumps)
5. **`I-5`**: AI cannot modify its own security boundary. (Structural Immutability: Read-Only Mounts, No Privilege to Remount, Explicitly Denied Write Paths, Supervisor Out-of-Band)
6. **`I-6`**: Fail-closed on uncertainty. (Parse/Eval/Context Error → DENY)
7. **`I-7`**: Every authorized action is auditable. (Append-Only, Tamper-Evident, Outside Sandbox, Complete Coverage)
8. **`I-8`**: Least privilege is enforced at all times. (Scoped, Time-Bounded, Usage-Bounded, State-Aware, Just-In-Time where applicable)
9. **`I-9`**: Security checks precede execution. (Check-Then-Act with TOCTOU Hardening, Canonicalization Before Check)
10. **`I-10`**: The boundary is enforced structurally, not just logically. (Namespaces, seccomp-BPF Allowlist, Mount Isolation, FS Immutable/Append-Only, Capability Dropping)

\---

36\. Long-Term Architecture

เป้าหมายระยะยาว:

                    AI Virtual Machine  
                           │  
             ┌─────────────┴─────────────┐  
             │                           │  
       Cognitive Plane             Execution Plane  
             │                           │  
        ┌────┴────┐               ┌──────┴──────┐  
        │         │               │             │  
      Cube      Memory          Sandbox       Tools  
        │         │               │             │  
        └────┬────┘               └──────┬──────┘  
             │                           │  
             └─────────────┬─────────────┘  
                           │  
                     Policy Engine  
                           │  
                     Resource Layer  
                           │  
                    Host / Hypervisor

\---

37\. Final Concept

AIVM ไม่ควรถูกมองว่า:

«"Docker ที่เอาไว้รัน LLM"»

แต่ควรถูกมองว่า:

«A virtual machine for autonomous intelligence.»

Docker virtualizes/isolate process execution

AIVM isolates AI agency

Docker:

Process  
   ↓  
Container Boundary  
   ↓  
Host

AIVM:

AI  
 ↓  
State Boundary  
 ↓  
Capability Boundary  
 ↓  
Policy Boundary  
 ↓  
Tool Boundary  
 ↓  
Sandbox Boundary  
 ↓  
Host

ดังนั้น Cube เป็นแกนกลางของ Cognitive Boundary:

                 CUBE  
                  │  
       ┌──────────┼──────────┐  
       │          │          │  
      STATE    CONTEXT   CAPABILITY  
       │          │          │  
       └──────────┼──────────┘  
                  │  
                POLICY  
                  │  
                ACTION

เป้าหมายสุดท้ายคือ:

«AI มีอิสระในการคิด แต่ไม่มีอิสระในการทะลุขอบเขตของเครื่อง»

และ architecture นี้เปิดทางให้ AIVM พัฒนาได้ตั้งแต่ Linux sandbox → container → microVM → hardware-isolated AI VM โดยไม่ต้องเปลี่ยน conceptual model ของ Cube และ Capability layer.

---

38\. Adversarial Testing & Security Validation

AIVM จะถูกทดสอบแบบ **Adversarial-First** โดยถือว่า AI คือ Untrusted Adversary โดย Default

### 38.1 Core Testing Philosophy

- **Negative Testing First**: เน้น Test Cases ที่ "Must DENY" มากกว่า "Must ALLOW"
- **Fail-Closed Verification**: ทุกกรณี Error (Parse, Eval, Context Missing) ต้อง DENY และไม่ Crash
- **Continuous Red Teaming**: รัน Adversarial Suite ทุก CI เพื่อป้องกัน Regression
- **Property-Based Testing**: ทดสอบ Invariants (`I-1` ถึง `I-10`) แบบ Automated

### 38.2 Adversarial Test Categories

| Category | Test Cases | Expected Result |
|---|---|---|
| **Filesystem Escape** | อ่าน `/etc/passwd`, `~/.ssh/id_rsa`, `.env`, `/proc/self/mounts`, `../../etc/shadow`, Symlink Traversal (`/workspace/link → /etc`) | **DENY** + Audit |
| **Process Execution** | Spawn `bash`, `sh -c`, `python -c`, `curl`, Exec ผ่าน PATH, `memfd_create+execve` | **DENY** (อนุญาตเฉพาะ Whitelisted Tools ผ่าน Tool Gateway) |
| **Syscall Bypass** | Direct Syscalls นอก Allowlist, `ptrace`, `execveat`, Clone Flags อันตราย | **KILL_PROCESS** (seccomp) + Audit |
| **Namespace/Privilege** | `unshare`, `mount`, `umount2`, `chroot`, `pivot_root`, `setns`, Remount, CAP Attempts | **DENY** (seccomp + No Caps) |
| **Tool Gateway Bypass** | Command Injection (`git; rm -rf /`), Shell Interpolation, LD_PRELOAD, Arg Injection | **DENY** + Canonicalize + Validate |
| **Network** | Private CIDR (10/8, 192.168/16, 172.16/12), Loopback (127.0.0.1, ::1), Cloud Metadata (169.254.169.254), Non-Allowlisted Domains | **DENY** ตาม Policy |
| **Boundary Tampering** | เขียนไป `policies/`, `aivm.yaml`, Audit Dir, Rename/Truncate/Delete Boundary Files, `chmod/chown` Config | **DENY** (Read-Only Mount + FS Attr + Gateway Block) |
| **Capability Abuse** | Expired Capability, Usage Exceeded (`max_uses`), State Mismatch, Scope Escalation (`/workspace` → `/`) | **DENY** + Revoke + Audit |
| **TOCTOU** | Symlink Swap ระหว่าง Check-Act, Path Race Conditions | **Hardened** (realpath + openat+O_NOFOLLOW + Re-Check) |
| **Resource Exhaustion** | Fork Bomb, RAM Exhaustion, Disk Fill, PID Exhaustion | **Throttled/Killed** (cgroups v2 + pids.max) |
| **Secret Abuse** | Multiple Requests, Scope Escalation, Prompt Engineering/Social Engineering, Probing Allowlist | **DENY/HITL**, Rate-Limit, Structured-Only, Audit All |
| **State Machine Bypass** | กระโดด `INIT → DEPLOY` โดยตรง, Invalid Transitions | **DENY** (State Validation) |

### 38.3 Security Validation Requirements

1. **Invariant Verification**: มี Automated Tests ที่ตรวจสอบ `I-1`–`I-10` ทุก CI Run
2. **Fail-Closed Matrix**: ทดสอบทุก Enforcement Point เมื่อ Error เกิดขึ้น → ต้องเป็น DENY
3. **Boundary Proof**: Structural Hardening (mount ro, seccomp, namespaces, FS attrs) ต้อง Verified โดย Test ไม่ใช่แค่ Code Review
4. **Audit Integrity**: Periodic Integrity Verification ของ Hash Chain + Sequence Number
5. **Red Team Regression**: Adversarial Tests ต้องผ่าน 100% สำหรับ Security-Critical Paths