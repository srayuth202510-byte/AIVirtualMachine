//! Denial burst circuit breaker; operator-controlled reset.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// ตัวตัดวงจร deny-storm (G1 — `docs/threat-model.md`): agent ที่โดนยึดแล้ว
/// ไล่ probe จะทิ้งรอย DENY ถี่ ๆ ตัวนี้เฝ้าหน้าต่างบานเลื่อนแล้ว quarantine
/// ทั้ง gateway ชั่วคราว (fail-closed escalation)
///
/// ความซื่อสัตย์: นี่คือ circuit breaker กัน runaway loop / burst probing
/// ไม่ใช่ตัวจับ slow probing (ต่ำกว่า threshold ตรวจไม่เจอโดยออกแบบ) และ
/// ไม่ยืดเวลาเอง (hammer ต่อ = หมด cooldown แล้ว trigger ใหม่เป็นรอบ ๆ)
#[derive(Debug)]
pub struct DenyTracker {
    stamps: VecDeque<Instant>,
    quarantine_until: Option<Instant>,
    threshold: u32,
    window: Duration,
    cooldown: Duration,
}

/// default แบบ conservative: demo (7 denies) กับเทสต์ปกติไม่มีทางถึง
/// (margin กว้าง) แต่ loop ที่รันaway โดนตัดในนาทีเดียว
impl Default for DenyTracker {
    fn default() -> Self {
        Self {
            stamps: VecDeque::new(),
            quarantine_until: None,
            threshold: 20,
            window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
        }
    }
}

impl DenyTracker {
    #[cfg(test)]
    pub(super) fn test_config(threshold: u32, window_secs: u64, cooldown_secs: u64) -> Self {
        Self {
            stamps: VecDeque::new(),
            quarantine_until: None,
            threshold,
            window: Duration::from_secs(window_secs),
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// อยู่ใน quarantine หรือไม่ (หมดเวลาแล้วล้างเองแบบ lazy)
    pub(super) fn quarantined(&mut self, now: Instant) -> bool {
        if let Some(until) = self.quarantine_until {
            if now < until {
                return true;
            }
            self.quarantine_until = None;
        }
        false
    }

    /// บันทึก deny หนึ่งครั้ง คืน true ถ้าเพิ่งเข้า quarantine รอบใหม่
    /// (กำลัง quarantine อยู่แล้ว = นับต่อแต่ไม่ยืดเวลา — กัน attacker
    /// ปักหลักยึด VM ไว้ตลอดด้วยการ hammer ไม่หยุด)
    pub(super) fn record_deny(&mut self, now: Instant) -> bool {
        self.stamps.push_back(now);
        while self
            .stamps
            .front()
            .map(|t| now.duration_since(*t) > self.window)
            .unwrap_or(false)
        {
            self.stamps.pop_front();
        }
        if self.quarantine_until.is_some_and(|u| now < u) {
            return false;
        }
        if self.stamps.len() as u32 >= self.threshold {
            self.quarantine_until = Some(now + self.cooldown);
            return true;
        }
        false
    }

    /// ล้างสถานะ (operator เท่านั้น — เรียกจาก transition ฝั่ง runtime)
    pub fn clear(&mut self) {
        self.stamps.clear();
        self.quarantine_until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // G1: tracker ลั่นที่ threshold พอดี ไม่ยืดเวลาเอง หมด cooldown แล้วนับใหม่
    #[test]
    fn deny_tracker_triggers_no_extend_and_rearms() {
        let mut t = DenyTracker::test_config(3, 60, 60);
        let now = Instant::now();
        assert!(!t.record_deny(now));
        assert!(!t.record_deny(now));
        // ครั้งที่ 3 = ครบ threshold ลั่นรอบใหม่
        assert!(t.record_deny(now));
        assert!(t.quarantined(now));
        // hammer ต่อระหว่าง quarantine = นับแต่ไม่ยืดเวลา (ไม่คืน true อีก)
        let arm = t.quarantine_until;
        assert!(!t.record_deny(now));
        assert!(!t.record_deny(now));
        assert_eq!(t.quarantine_until, arm);
        // cooldown = 0 อีกรอบ: หมดทันที แต่ record ใหม่ลั่นซ้ำได้ (re-arm)
        let mut z = DenyTracker::test_config(2, 60, 0);
        assert!(!z.record_deny(now));
        assert!(z.record_deny(now));
        assert!(!z.quarantined(now));
        assert!(z.record_deny(now));
    }
}
