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
    Create { name: String, #[arg(long)] config: PathBuf },
    /// Run one mediated step.
    Run { name: String },
    /// Show state, model, resources, capabilities.
    Inspect { name: String },
    /// Show current agent state.
    State { name: String },
    /// List initial capabilities.
    Capabilities { name: String },
    /// Print audit log tail.
    Logs { name: String },
    Pause { name: String },
    Stop { name: String },
    Kill { name: String },
}

fn main() -> Result<(), AnyErr> {
    let cli = Cli::parse();
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
            let p = PathBuf::from("./vms").join(&name).join("audit.jsonl");
            match std::fs::read_to_string(&p) {
                Ok(t) => {
                    for line in t.lines().rev().take(20).collect::<Vec<_>>().into_iter().rev() {
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
    }
    Ok(())
}

type AnyErr = Box<dyn std::error::Error>;
fn err<E: std::fmt::Display>(e: E) -> AnyErr {
    Box::<dyn std::error::Error>::from(format!("{e}"))
}
