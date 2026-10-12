//! CLI ของ `aivm` — ดูสเปก §29-§30

use aivm_runtime::VmConfig;
use aivm_supervisor::Supervisor;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aivm", about = "AI Virtual Machine — isolate AI agency")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// ไดเรกทอรี root ของ supervisor (บ้านของแต่ละ VM)
    #[arg(long, default_value = "./vms")]
    root: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// สร้าง VM จากไฟล์ config aivm.yaml
    Create {
        name: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// รันหนึ่งก้าวแบบผ่านตัวกลาง
    Run {
        name: String,
    },
    /// แสดง state โมเดล ทรัพยากร และสิทธิ์
    Inspect {
        name: String,
    },
    /// แสดง state ปัจจุบันของ agent
    State {
        name: String,
    },
    /// แสดงสิทธิ์ตั้งต้น
    Capabilities {
        name: String,
    },
    /// พิมพ์ท้ายล็อก audit
    Logs {
        name: String,
    },
    /// ตรวจ hash chain ของ audit รวมไฟล์ rotate แล้วสรุป
    Audit {
        name: String,
    },
    Pause {
        name: String,
    },
    Stop {
        name: String,
    },
    Kill {
        name: String,
    },
    /// เปลี่ยน state แบบ validate พร้อมให้/เพิกถอนสิทธิ์แบบ dynamic (สเปก §14)
    /// guard คือหลักฐานจาก operator ไม่ใช่คำอ้างของ agent
    Transition {
        name: String,
        /// INIT|ANALYZE|MODIFY|VALIDATE|DEPLOY
        state: String,
        /// ความเชื่อมั่นสำหรับ ANALYZE -> MODIFY (ค่าเริ่มต้น 0)
        #[arg(long, default_value_t = 0.0)]
        confidence: f64,
        /// เทสต์ผ่านแล้ว (สำหรับ MODIFY -> VALIDATE)
        #[arg(long, default_value_t = false)]
        tests_passed: bool,
        /// policy อนุมัติแล้ว (สำหรับ VALIDATE -> DEPLOY)
        #[arg(long, default_value_t = false)]
        policy_approved: bool,
    },
    /// self-test เส้น enforcement ใน workspace ชั่วคราว
    /// ไม่ต้องใช้ --root พิมพ์ตาราง ALLOW/DENY แล้วจบด้วย exit code
    /// ไม่เป็นศูนย์ถ้ามีเคสไหนผิดปกติ
    Demo,
}

fn main() -> Result<(), AnyErr> {
    let cli = Cli::parse();
    let root = cli.root.clone();
    let mut sup = Supervisor::new(cli.root);
    match cli.cmd {
        Cmd::Create { name, config } => {
            let cfg = VmConfig::from_file(&config).map_err(err)?;
            // ลงทะเบียนเข้า root ของ supervisor เอง (create จะ validate การบูต)
            sup.create(&name, cfg).map_err(err)?;
            println!("created vm '{name}'");
        }
        Cmd::Run { name } => {
            // `run` ต้อง `create` มาก่อน ถ้าไม่มีช่วยบอกให้ชัด
            if sup.status(&name).is_none() {
                eprintln!("vm '{name}' not registered under this --root; `create` it first");
                std::process::exit(2);
            }
            let out = sup.run(&name).map_err(err)?;
            println!("{out}");
        }
        Cmd::Inspect { name } => println!("{}", sup.inspect(&name).map_err(err)?),
        Cmd::State { name } => println!("{}", sup.inspect(&name).map_err(err)?),
        Cmd::Capabilities { name } => println!("{}", sup.inspect(&name).map_err(err)?),
        Cmd::Logs { name } => {
            let p = root.join(&name).join("audit.jsonl");
            match std::fs::read_to_string(&p) {
                Ok(t) => {
                    for line in t
                        .lines()
                        .rev()
                        .take(20)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                    {
                        println!("{line}");
                    }
                }
                Err(e) => eprintln!("no audit log yet: {e}"),
            }
        }
        Cmd::Audit { name } => {
            // เก็บสายไฟล์: archive (audit.<suffix>.jsonl) เก่าไปใหม่
            // แล้วปิดท้ายด้วยไฟล์ live
            let dir = root.join(&name);
            let mut archives: Vec<PathBuf> = vec![];
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.filter_map(|e| e.ok()) {
                    let p = e.path();
                    if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                        // archive คือ audit.<suffix>.jsonl เท่านั้น
                        // (ไฟล์ live ชื่อ audit.jsonl ตรง ๆ ต้องไม่นับซ้ำ)
                        if n != "audit.jsonl" && n.starts_with("audit.") && n.ends_with(".jsonl") {
                            archives.push(p);
                        }
                    }
                }
            }
            archives.sort();
            let live = dir.join("audit.jsonl");
            if live.is_file() {
                archives.push(live);
            }
            if archives.is_empty() {
                eprintln!("no audit log yet for '{name}'");
                std::process::exit(2);
            }
            match aivm_audit::verify_sequence(&archives) {
                Ok(n) => println!(
                    "audit {name}: {} file(s), {} entries, chain verified",
                    archives.len(),
                    n
                ),
                Err(e) => {
                    eprintln!("audit {name}: CHAIN BROKEN: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Pause { name } => {
            sup.pause(&name).map_err(err)?;
            println!("paused '{name}'");
        }
        Cmd::Stop { name } => {
            sup.stop(&name).map_err(err)?;
            println!("stopped '{name}'");
        }
        Cmd::Kill { name } => {
            sup.kill(&name).map_err(err)?;
            println!("killed '{name}'");
        }
        Cmd::Transition {
            name,
            state,
            confidence,
            tests_passed,
            policy_approved,
        } => {
            use std::str::FromStr;
            let next = aivm_cube::AgentState::from_str(&state).map_err(err)?;
            let guards = aivm_cube::TransitionGuards {
                confidence,
                confidence_threshold: aivm_runtime::CONFIDENCE_THRESHOLD,
                tests_passed,
                policy_approved,
            };
            let (granted, revoked) = sup.transition(&name, next, &guards).map_err(err)?;
            println!("{name}: -> {next} (granted {granted}, revoked {revoked})");
        }
        Cmd::Demo => {
            let rep = aivm_runtime::demo::mediated_demo().map_err(err)?;
            for c in &rep.cases {
                let mark = if c.pass { "ok  " } else { "FAIL" };
                println!(
                    "{mark} expect {:5} {:45} -> {}",
                    c.expected.label(),
                    c.name,
                    c.got
                );
            }
            println!(
                "audit: {} entries, chain {}",
                rep.audit_entries,
                if rep.audit_verified {
                    "verified"
                } else {
                    "BROKEN"
                }
            );
            println!(
                "demo: {}/{} pass{}",
                rep.passed(),
                rep.cases.len(),
                if rep.ok() { "" } else { " — FAILED" }
            );
            if !rep.ok() {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

type AnyErr = Box<dyn std::error::Error>;
fn err<E: std::fmt::Display>(e: E) -> AnyErr {
    Box::<dyn std::error::Error>::from(format!("{e}"))
}
