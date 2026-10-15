#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::{os::unix::process::ExitStatusExt, process::Command};
#[test]
fn filter_child() {
    let Ok(kind) = std::env::var("AIVM_NETWORK_FILTER_CHILD") else {
        return;
    };
    aivm_sandbox::install_worker_network_seccomp().unwrap();
    unsafe {
        match kind.as_str() {
            "socket" => {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            }
            "x32" => {
                libc::syscall(
                    0x40000000 | libc::SYS_socket,
                    libc::AF_INET,
                    libc::SOCK_STREAM,
                    0,
                );
            }
            "uring" => {
                libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null::<u8>());
            }
            _ => panic!("unknown probe"),
        }
    }
    panic!("network syscall escaped filter");
}
#[test]
fn socket_x32_and_io_uring_are_killed() {
    for kind in ["socket", "x32", "uring"] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "filter_child"])
            .env("AIVM_NETWORK_FILTER_CHILD", kind)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGSYS), "{kind}: {status}");
    }
}
