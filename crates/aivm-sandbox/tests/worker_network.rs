#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::{os::unix::process::ExitStatusExt, process::Command};
#[test]
fn filter_child() {
    let Ok(kind) = std::env::var("AIVM_NETWORK_FILTER_CHILD") else {
        return;
    };
    aivm_sandbox::install_worker_network_seccomp().unwrap();
    // SAFETY: เรียกใน child ของเทสต์หลังติดตั้ง seccomp เพื่อตรวจว่า kernel บล็อก socket/x32 syscall จริง
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
            // regression #16: cross-process/inspection ต้องถูก kill เหมือน network
            "ptrace" => {
                libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
            }
            "process_vm_readv" => {
                libc::syscall(
                    libc::SYS_process_vm_readv,
                    0,
                    std::ptr::null::<libc::iovec>(),
                    0,
                    std::ptr::null::<libc::iovec>(),
                    0,
                    0,
                );
            }
            "bpf" => {
                libc::syscall(libc::SYS_bpf, 0, std::ptr::null::<u8>(), 0);
            }
            "kcmp" => {
                libc::syscall(libc::SYS_kcmp, 0, 0, 0, 0, 0);
            }
            "personality" => {
                libc::syscall(libc::SYS_personality, 0xffffffffu64);
            }
            "userfaultfd" => {
                libc::syscall(libc::SYS_userfaultfd, 0);
            }
            "perf_event_open" => {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    std::ptr::null::<u8>(),
                    0,
                    -1,
                    -1,
                    0,
                );
            }
            "pidfd_open" => {
                libc::syscall(libc::SYS_pidfd_open, 1, 0);
            }
            "pidfd_getfd" => {
                libc::syscall(libc::SYS_pidfd_getfd, 0, 0, 0);
            }
            "keyctl" => {
                libc::syscall(libc::SYS_keyctl, 0, 0, 0, 0, 0);
            }
            "dumpable" => {
                aivm_sandbox::disable_process_dumpable().unwrap();
                let mut core = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut core), 0);
                assert_eq!(core.rlim_cur, 0);
                assert_eq!(core.rlim_max, 0);
                assert_eq!(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
                std::process::exit(0);
            }
            _ => panic!("unknown probe"),
        }
    }
    panic!("denied syscall escaped filter");
}
#[test]
fn network_and_cross_process_syscalls_are_killed() {
    for kind in [
        "socket",
        "x32",
        "uring",
        "ptrace",
        "process_vm_readv",
        "bpf",
        "kcmp",
        "personality",
        "userfaultfd",
        "perf_event_open",
        "pidfd_open",
        "pidfd_getfd",
        "keyctl",
    ] {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "filter_child"])
            .env("AIVM_NETWORK_FILTER_CHILD", kind)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGSYS), "{kind}: {status}");
    }
    let dumpable_status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "filter_child"])
        .env("AIVM_NETWORK_FILTER_CHILD", "dumpable")
        .status()
        .unwrap();
    assert!(dumpable_status.success(), "{dumpable_status}");
}
