//! Trusted in-container entry point. Not a user-facing process executor.
fn main() {
    if let Err(error) = aivm_sandbox::container::init_main() {
        eprintln!("aivm-container-init: {error}");
        std::process::exit(125);
    }
}
