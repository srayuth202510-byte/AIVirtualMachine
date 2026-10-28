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
fn parent(workspace: &Path, path: &Path, write: bool) -> Result<(File, CString), ToolError> {
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
    Ok((dir, last))
}

pub fn open(workspace: &Path, path: &Path, write: bool) -> Result<File, ToolError> {
    let (dir, last) = parent(workspace, path, write)?;
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

pub const WRITE_PREFIX: &str = ".aivm-write-";

fn sync_directory(dir: &File) -> Result<(), ToolError> {
    let dot = name(b".")?;
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io_error());
    }
    unsafe { File::from_raw_fd(raw) }
        .sync_all()
        .map_err(|error| ToolError::Io(error.to_string()))
}

/// ใช้ pinned parent fd และ renameat: target ต้องเป็น bytes เก่าหรือใหม่ทั้งไฟล์เมื่อ crash
pub fn replace_with_hook(
    workspace: &Path,
    path: &Path,
    bytes: &[u8],
    hook: &mut impl FnMut(&str) -> std::io::Result<()>,
) -> Result<(), ToolError> {
    use std::io::Write;
    let (dir, last) = parent(workspace, path, true)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let exists = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            last.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let mode = if exists == 0 {
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 {
            return Err(ToolError::Denied(
                "atomic write requires a regular file with one link".into(),
            ));
        }
        metadata.st_mode & 0o777
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        0o600
    } else {
        return Err(io_error());
    };
    let temporary = name(format!("{WRITE_PREFIX}{}.tmp", uuid::Uuid::new_v4()).as_bytes())?;
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(io_error());
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    let result = (|| {
        let io = |error: std::io::Error| ToolError::Io(error.to_string());
        hook("file-created").map_err(io)?;
        let half = bytes.len() / 2;
        file.write_all(&bytes[..half]).map_err(io)?;
        hook("file-partial").map_err(io)?;
        file.write_all(&bytes[half..]).map_err(io)?;
        file.sync_all().map_err(io)?;
        hook("file-synced").map_err(io)?;
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temporary.as_ptr(),
                dir.as_raw_fd(),
                last.as_ptr(),
            )
        } != 0
        {
            return Err(io_error());
        }
        hook("file-renamed").map_err(io)?;
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
            return Err(io_error());
        }
        file.sync_all().map_err(io)?;
        sync_directory(&dir)?;
        hook("file-directory-synced").map_err(io)
    })();
    unsafe {
        libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0);
    }
    result
}

/// caller ถือ exclusive VM lease; ลบเฉพาะ temporary namespace ที่ runtime เป็นเจ้าของ
pub fn recover_pending(workspace: &Path) -> Result<usize, ToolError> {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(workspace).follow_links(false) {
        let entry = entry.map_err(|error| ToolError::Io(error.to_string()))?;
        let Some(text) = entry.file_name().to_str() else {
            continue;
        };
        let Some(id) = text
            .strip_prefix(WRITE_PREFIX)
            .and_then(|text| text.strip_suffix(".tmp"))
        else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_err() {
            return Err(ToolError::Denied("invalid pending write name".into()));
        }
        let file = open(workspace, entry.path(), false)?;
        let metadata = file
            .metadata()
            .map_err(|error| ToolError::Io(error.to_string()))?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(ToolError::Denied("invalid pending write owner/mode".into()));
        }
        let (dir, filename) = parent(workspace, entry.path(), false)?;
        if unsafe { libc::unlinkat(dir.as_raw_fd(), filename.as_ptr(), 0) } != 0 {
            return Err(io_error());
        }
        sync_directory(&dir)?;
        count += 1;
    }
    Ok(count)
}
