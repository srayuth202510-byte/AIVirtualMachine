//! ไฟล์ state ที่มี secret: สร้าง 0600 ตั้งแต่เปิด และ replace แบบ atomic
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    write_private_with_hook(path, text, &mut |_| Ok(()))
}

/// ใช้ hook ใน fault injection โดย production ไม่มี environment switch ที่ฆ่า process
pub fn write_private_with_hook(
    path: &Path,
    text: &str,
    hook: &mut impl FnMut(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("state parent missing"))?;
    let temporary = parent.join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        hook("created")?;
        file.write_all(text.as_bytes())?;
        hook("written")?;
        file.sync_all()?;
        hook("synced")?;
        std::fs::rename(&temporary, path)?;
        hook("renamed")?;
        std::fs::File::open(parent)?.sync_all()?;
        hook("directory-synced")
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
