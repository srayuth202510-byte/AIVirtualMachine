//! ไฟล์ state ที่มี secret: สร้าง 0600 ตั้งแต่เปิด และ replace แบบ atomic
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
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
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
