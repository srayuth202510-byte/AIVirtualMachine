//! หาเพดาน RAM จาก host และ cgroup v1/v2 ทุกชั้นที่มองเห็น โดยไม่แก้ cgroup
use std::{
    io,
    path::{Component, Path, PathBuf},
};

pub(super) fn default_budget() -> io::Result<u64> {
    budget_from_sources(
        &std::fs::read_to_string("/proc/meminfo")?,
        &std::fs::read_to_string("/proc/self/cgroup")?,
        &std::fs::read_to_string("/proc/self/mountinfo")?,
        |path| std::fs::read_to_string(path),
    )
}

fn invalid() -> io::Error {
    io::Error::other("cannot determine effective memory ceiling")
}

fn absolute_path(raw: &str) -> io::Result<PathBuf> {
    // mountinfo escape ใช้ octal; ไม่ให้ membership ที่หลุด namespace เดินออก mount
    let mut bytes = Vec::new();
    let mut source = raw.as_bytes().iter().copied();
    while let Some(byte) = source.next() {
        if byte == b'\\' {
            let digits: Vec<_> = source.by_ref().take(3).collect();
            let value = match digits.as_slice() {
                [b'0', b'4', b'0'] => b' ',
                [b'0', b'1', b'1'] => b'\t',
                [b'0', b'1', b'2'] => b'\n',
                [b'1', b'3', b'4'] => b'\\',
                _ => return Err(invalid()),
            };
            bytes.push(value);
        } else {
            bytes.push(byte);
        }
    }
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| invalid())?);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid());
    }
    Ok(path)
}

fn budget_from_sources(
    meminfo: &str,
    membership: &str,
    mountinfo: &str,
    mut read: impl FnMut(&Path) -> io::Result<String>,
) -> io::Result<u64> {
    if membership.trim().is_empty() {
        return Err(invalid());
    }
    let mut ceiling = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|kb| kb.checked_mul(1024))
        .ok_or_else(invalid)?;
    for entry in membership.lines().filter(|line| !line.is_empty()) {
        let mut fields = entry.splitn(3, ':');
        let id = fields.next().ok_or_else(invalid)?;
        let controllers = fields.next().ok_or_else(invalid)?;
        let member = fields.next().ok_or_else(invalid)?;
        let v2 = id == "0" && controllers.is_empty();
        if !v2 && !controllers.split(',').any(|part| part == "memory") {
            continue;
        }
        let member = absolute_path(member)?;
        let mut found = false;
        for mount in mountinfo.lines() {
            let Some((before, after)) = mount.split_once(" - ") else {
                continue;
            };
            let options: Vec<_> = after.split_whitespace().collect();
            if options.len() < 3 {
                return Err(invalid());
            }
            let applies = if v2 {
                options[0] == "cgroup2"
            } else {
                options[0] == "cgroup" && options[2].split(',').any(|part| part == "memory")
            };
            if !applies {
                continue;
            }
            let fields: Vec<_> = before.split_whitespace().collect();
            if fields.len() < 6 {
                return Err(invalid());
            }
            let root = absolute_path(fields[3])?;
            let mountpoint = absolute_path(fields[4])?;
            let Ok(relative) = member.strip_prefix(&root) else {
                continue;
            };
            found = true;
            let mut directory = mountpoint.join(relative);
            loop {
                let path = directory.join(if v2 {
                    "memory.max"
                } else {
                    "memory.limit_in_bytes"
                });
                match read(&path) {
                    Ok(text) if v2 && text.trim() == "max" => {}
                    Ok(text) => {
                        ceiling = ceiling.min(text.trim().parse::<u64>().map_err(|_| invalid())?)
                    }
                    // root ของ v2 ไม่มี memory.max; ลูกที่ไม่เปิด memory controller ก็ไม่มีได้
                    Err(error) if v2 && error.kind() == io::ErrorKind::NotFound => {
                        // แยก controller ที่ไม่เปิดจาก cgroup ที่หายไป/namespace mapping ผิด
                        read(&directory.join("cgroup.controllers"))?;
                    }
                    Err(error) => return Err(error),
                }
                if directory == mountpoint {
                    break;
                }
                if !directory.pop() || !directory.starts_with(&mountpoint) {
                    return Err(invalid());
                }
            }
        }
        if !found {
            return Err(invalid());
        }
    }
    // headroom 25% ของ ceiling ที่มีผลจริง คำนวณก่อนแปลงเป็น MiB กันปัดเกินงบ
    Ok((u128::from(ceiling) * 3 / 4 / (1024 * 1024)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    const HOST: &str = "MemTotal: 67108864 kB\n"; // 64 GiB
    const V2: &str = "1 0 0:1 / /cg rw - cgroup2 none rw\n";

    fn budget(member: &str, mounts: &str, files: &[(&str, &str)]) -> io::Result<u64> {
        let files: HashMap<_, _> = files.iter().copied().collect();
        budget_from_sources(HOST, member, mounts, |path| {
            if path
                .file_name()
                .is_some_and(|name| name == "cgroup.controllers")
            {
                return Ok(String::new());
            }
            files
                .get(path.to_str().unwrap())
                .map(|text| text.to_string())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        })
    }

    #[test]
    fn unlimited_and_missing_v2_controller_use_host_with_headroom() {
        assert_eq!(
            budget("0::/\n", V2, &[("/cg/memory.max", "max")]).unwrap(),
            49152
        );
        assert_eq!(budget("0::/app\n", V2, &[]).unwrap(), 49152);
    }

    #[test]
    fn nested_cgroups_use_smallest_parent_or_child_limit() {
        for (parent, child, expected) in [
            ("8589934592", "max", 6144),
            ("8589934592", "4294967296", 3072),
            ("1073741824", "8589934592", 768),
        ] {
            assert_eq!(
                budget(
                    "0::/service/worker\n",
                    V2,
                    &[
                        ("/cg/service/memory.max", parent),
                        ("/cg/service/worker/memory.max", child),
                    ]
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn subtree_mounts_and_escaped_paths_map_to_the_process_cgroup() {
        assert_eq!(
            budget(
                "0::/service/worker\n",
                "1 0 0:1 /service /cg\\040space rw - cgroup2 none rw\n",
                &[
                    ("/cg space/memory.max", "8589934592"),
                    ("/cg space/worker/memory.max", "max"),
                ]
            )
            .unwrap(),
            6144
        );
    }

    #[test]
    fn v1_memory_hierarchy_and_unlimited_sentinel_are_respected() {
        assert_eq!(
            budget(
                "7:cpu,memory:/service/worker\n",
                "1 0 0:1 / /cg rw - cgroup none rw,memory\n",
                &[
                    ("/cg/memory.limit_in_bytes", "9223372036854771712"),
                    ("/cg/service/memory.limit_in_bytes", "8589934592"),
                    ("/cg/service/worker/memory.limit_in_bytes", "17179869184"),
                ]
            )
            .unwrap(),
            6144
        );
    }

    #[test]
    fn inaccessible_or_malformed_limits_do_not_fall_back_to_host_ram() {
        assert!(budget("", V2, &[]).is_err());
        assert!(budget("0::/service\n", "", &[]).is_err());
        assert!(budget("0::/../escape\n", V2, &[]).is_err());
        assert!(budget(
            "0::/service\n",
            V2,
            &[("/cg/service/memory.max", "invalid")]
        )
        .is_err());
        assert!(
            budget_from_sources(HOST, "0::/service", V2, |_| Err(io::Error::from(
                io::ErrorKind::PermissionDenied
            )))
            .is_err()
        );
        assert!(
            budget_from_sources(HOST, "0::/missing", V2, |_| Err(io::Error::from(
                io::ErrorKind::NotFound
            )))
            .is_err()
        );
        assert_eq!(
            budget("0::/service", V2, &[("/cg/service/memory.max", "0")]).unwrap(),
            0
        );
    }
}
