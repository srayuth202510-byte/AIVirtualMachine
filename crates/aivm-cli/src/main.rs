//! `aivm` CLI — spec §29–§30.

use aivm_runtime::VmConfig;
use aivm_supervisor::Supervisor;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aivm", about = "AI Virtual Machine — isolate AI agency")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Supervisor root dir (VM homes).
    #[arg(long, default_value = "./vms")]
    root: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a VM from an aivm.yaml config.
    Create {
        name: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Run one mediated step.
    Run {
        name: String,
    },
    /// Show state, model, resources, capabilities.
    Inspect {
        name: String,
    },
    /// Show current agent state.
    State {
        name: String,
    },
    /// List initial capabilities.
    Capabilities {
        name: String,
    },
    /// Print audit log tail.
    Logs {
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
    /// Validated state transition with dynamic grant/revoke (spec §14).
    /// Guards are operator-supplied evidence, never agent claims.
    Transition {
        name: String,
        /// INIT|ANALYZE|MODIFY|VALIDATE|DEPLOY
        state: String,
        /// Confidence for ANALYZE -> MODIFY (default 0).
        #[arg(long, default_value_t = 0.0)]
        confidence: f64,
        /// Tests passed (for MODIFY -> VALIDATE).
        #[arg(long, default_value_t = false)]
        tests_passed: bool,
        /// Policy approved (for VALIDATE -> DEPLOY).
        #[arg(long, default_value_t = false)]
        policy_approved: bool,
    },
    /// Self-test the enforcement chain in a throwaway workspace.
    /// No --root needed; prints an ALLOW/DENY table and exits
    /// non-zero if any case misbehaves.
    Demo,
}

fn main() -> Result<(), AnyErr> {
    let cli = Cli::parse();
    let root = cli.root.clone();
    let mut sup = Supervisor::new(cli.root);
    match cli.cmd {
        Cmd::Create { name, config } => {
            let cfg = VmConfig::from_file(&config).map_err(err)?;
            // Register into supervisor root manually (create validates boot).
            sup.create(&name, cfg).map_err(err)?;
            println!("created vm '{name}'");
        }
        Cmd::Run { name } => {
            // `run` needs a prior `create`; be helpful if missing.
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
