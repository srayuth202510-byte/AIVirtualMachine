//! เปิดไฟล์ผ่าน directory fd ทุกชั้น ปฏิเสธ symlink และ special files
use crate::ToolError;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

fn io_error() -> ToolError {
    ToolError::Io(std::io::Error::last_os_error().to_string())
}
fn name(bytes: &[u8]) -> Result<CString, ToolError> {
    CString::new(bytes).map_err(|_| ToolError::Denied("NUL in path".into()))
}
fn open_dir(fd: i32, part: &CString) -> Result<File, ToolError> {
    // SAFETY: part เป็น CString และ fd เปิดอยู่; File รับ ownership ของ fd ใหม่
    let raw = unsafe {
        libc::openat(
            fd,
            part.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io_error());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
pub fn open(workspace: &Path, path: &Path, write: bool) -> Result<File, ToolError> {
    let root = name(workspace.as_os_str().as_bytes())?;
    let mut dir = open_dir(libc::AT_FDCWD, &root)?;
    let relative = path
        .strip_prefix(workspace)
        .map_err(|_| ToolError::Denied("outside workspace".into()))?;
    let parts: Vec<_> = relative.components().collect();
    if parts.is_empty() || parts.iter().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(ToolError::Denied("invalid file path".into()));
    }
    for part in &parts[..parts.len() - 1] {
        let part = name(part.as_os_str().as_bytes())?;
        match open_dir(dir.as_raw_fd(), &part) {
            Ok(next) => dir = next,
            Err(_) if write => {
                // mkdirat/openat ใช้ parent fd เดิม จึงไม่ตาม parent ที่ถูกสลับ
                let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), part.as_ptr(), 0o700) };
                if rc < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(io_error());
                }
                dir = open_dir(dir.as_raw_fd(), &part)?;
            }
            Err(e) => return Err(e),
        }
    }
    let last = name(parts.last().unwrap().as_os_str().as_bytes())?;
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if write {
            libc::O_WRONLY | libc::O_CREAT
        } else {
            libc::O_RDONLY
        };
    let raw = unsafe { libc::openat(dir.as_raw_fd(), last.as_ptr(), flags, 0o600) };
    if raw < 0 {
        return Err(io_error());
    }
    let file = unsafe { File::from_raw_fd(raw) };
    let meta = file.metadata().map_err(|e| ToolError::Io(e.to_string()))?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(ToolError::Denied(
            "requires a regular file with one link".into(),
        ));
    }
    if write {
        file.set_len(0).map_err(|e| ToolError::Io(e.to_string()))?;
    }
    Ok(file)
}
