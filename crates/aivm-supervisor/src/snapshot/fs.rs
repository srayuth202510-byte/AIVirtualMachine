//! Descriptor-relative traversal. Never follow workspace or archive symlinks.
use super::{error, FileEntry, Inventory, Result, MAX_BYTES, MAX_ENTRIES};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

fn name(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(error)
}

pub(super) fn root(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(error)
}

pub(super) fn pin(parent: &File, part: &OsStr) -> Result<File> {
    let part = name(part)?;
    // SAFETY: the live parent descriptor and CString outlive openat. File owns
    // only the newly returned descriptor. O_PATH cannot open a device for I/O.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            part.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn readable(file: &File) -> Result<File> {
    // The O_PATH descriptor stays alive, so this procfs link refers to the
    // pinned inode even if the original pathname is renamed or replaced.
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(error)
}

pub(super) fn directory(parent: &File, part: &OsStr) -> Result<File> {
    let file = pin(parent, part)?;
    if !file.metadata().map_err(error)?.is_dir() {
        return Err(error("requires a directory; symlinks rejected"));
    }
    readable(&file)
}

pub(super) fn mkdir(parent: &File, part: &OsStr) -> Result<File> {
    let c = name(part)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    directory(parent, part)
}

pub(super) fn new_file(parent: &File, part: &OsStr) -> Result<File> {
    let part = name(part)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            part.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn write(parent: &File, part: &str, bytes: &[u8]) -> Result<()> {
    let mut file = new_file(parent, OsStr::new(part))?;
    file.write_all(bytes).map_err(error)?;
    file.sync_all().map_err(error)
}

pub(super) fn read(parent: &File, part: &str, maximum: u64) -> Result<Vec<u8>> {
    let file = pin(parent, OsStr::new(part))?;
    let meta = file.metadata().map_err(error)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > maximum {
        return Err(error("invalid or oversized snapshot metadata"));
    }
    let mut bytes = Vec::new();
    readable(&file)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() as u64 > maximum {
        return Err(error("snapshot metadata size limit"));
    }
    Ok(bytes)
}

pub(super) fn names(parent: &File) -> Result<Vec<std::ffi::OsString>> {
    std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))
        .map_err(error)?
        .take(MAX_ENTRIES + 1)
        .map(|e| e.map(|e| e.file_name()).map_err(error))
        .collect()
}

pub(super) fn valid_path(path: &str) -> Result<()> {
    let parts: Vec<_> = Path::new(path).components().collect();
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || parts.len() > 64
        || parts.iter().any(|c| !matches!(c, Component::Normal(_)))
        || parts
            .iter()
            .map(|c| c.as_os_str().to_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("/")
            != path
        || parts.iter().any(|c| c.as_os_str().len() > 255)
    {
        return Err(error("invalid snapshot relative path"));
    }
    Ok(())
}

fn stable(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
        before.nlink(),
    ) == (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
        after.nlink(),
    )
}

pub(super) fn inventory(source: &File, target: Option<&File>) -> Result<Inventory> {
    let mut found = Inventory::default();
    let mut entries = 0;
    walk(source, target, "", &mut found, &mut entries)?;
    found.directories.sort();
    found.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(found)
}

fn walk(
    source: &File,
    target: Option<&File>,
    prefix: &str,
    found: &mut Inventory,
    entries: &mut usize,
) -> Result<()> {
    let before = source.metadata().map_err(error)?;
    let mut children = Vec::new();
    for entry in
        std::fs::read_dir(format!("/proc/self/fd/{}", source.as_raw_fd())).map_err(error)?
    {
        *entries += 1;
        if *entries > MAX_ENTRIES {
            return Err(error("snapshot entry limit exceeded"));
        }
        children.push(entry.map_err(error)?.file_name());
    }
    children.sort();
    for child in children {
        let text = child
            .to_str()
            .ok_or_else(|| error("snapshot paths must be UTF-8"))?;
        let path = if prefix.is_empty() {
            text.into()
        } else {
            format!("{prefix}/{text}")
        };
        valid_path(&path)?;
        let pinned = pin(source, &child)?;
        let meta = pinned.metadata().map_err(error)?;
        if meta.is_dir() {
            found.directories.push(path.clone());
            let next = readable(&pinned)?;
            let destination = target.map(|dir| mkdir(dir, &child)).transpose()?;
            walk(&next, destination.as_ref(), &path, found, entries)?;
        } else if meta.is_file() && meta.nlink() == 1 {
            if meta.len() > MAX_BYTES.saturating_sub(found.bytes) {
                return Err(error("snapshot byte limit exceeded"));
            }
            let mut file = readable(&pinned)?;
            let mut output = target.map(|dir| new_file(dir, &child)).transpose()?;
            let mut hash = Sha256::new();
            let mut size = 0u64;
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let n = file.read(&mut buffer).map_err(error)?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > MAX_BYTES.saturating_sub(found.bytes) {
                    return Err(error("snapshot byte limit exceeded"));
                }
                hash.update(&buffer[..n]);
                if let Some(dst) = &mut output {
                    dst.write_all(&buffer[..n]).map_err(error)?;
                }
            }
            if !stable(&meta, &file.metadata().map_err(error)?) || size != meta.len() {
                return Err(error("workspace changed while taking snapshot"));
            }
            if let Some(dst) = output {
                dst.sync_all().map_err(error)?;
            }
            found.bytes += size;
            found.files.push(FileEntry {
                path,
                size,
                sha256: format!("{:x}", hash.finalize()),
                executable: meta.mode() & 0o100 != 0,
            });
        } else {
            return Err(error(
                "snapshot rejects symlinks, hard links and special files",
            ));
        }
    }
    if !stable(&before, &source.metadata().map_err(error)?) {
        return Err(error("directory changed during snapshot"));
    }
    if let Some(target) = target {
        target.sync_all().map_err(error)?;
    }
    Ok(())
}

pub(super) fn set_executable(root: &File, path: &str, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    valid_path(path)?;
    let mut parent = root.try_clone().map_err(error)?;
    let parts: Vec<_> = Path::new(path).components().collect();
    for part in &parts[..parts.len() - 1] {
        parent = directory(&parent, part.as_os_str())?;
    }
    let pinned = pin(&parent, parts.last().unwrap().as_os_str())?;
    let meta = pinned.metadata().map_err(error)?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(error(
            "restored permissions require a regular file with one link",
        ));
    }
    let file = readable(&pinned)?;
    file.set_permissions(std::fs::Permissions::from_mode(if executable {
        0o700
    } else {
        0o600
    }))
    .map_err(error)?;
    file.sync_all().map_err(error)
}

pub(super) fn publish(root: &File, temporary: &str, id: &str) -> Result<()> {
    let old = name(OsStr::new(temporary))?;
    let new = name(OsStr::new(id))?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            root.as_raw_fd(),
            old.as_ptr(),
            root.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(error(std::io::Error::last_os_error()));
    }
    root.sync_all().map_err(error)
}
