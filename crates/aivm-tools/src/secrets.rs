//! Strict secret requests and retained lease authority.
use crate::{CapabilitySet, SecretRequestBody, ToolError, ToolGateway, ToolResult};
use aivm_cube::Cube;
use aivm_secrets::{
    zeroize_secret, RiskLevel, SecretBroker, SecretError, SecretLease, SecretRequest,
};

const MAX_SECRET_FIELD: usize = 256;
pub(super) const MAX_LEASE_ID: usize = 128;

impl ToolGateway {
    /// ติด secret broker แบบ builder (operator ประกอบที่ runtime — ดู
    /// `Runtime::init`: broker เปล่า = deny หมด, มี secrets = ตาม policy)
    pub fn with_secret_broker(mut self, broker: SecretBroker) -> Self {
        self.secret_broker = Some(broker);
        self
    }

    /// broker สำหรับ rehydrate leases (G4b — runtime เท่านั้น)
    pub fn secret_broker_mut(&mut self) -> Option<&mut SecretBroker> {
        self.secret_broker.as_mut()
    }

    /// Restore only leases whose issuing authority still exists in the fresh
    /// capability set. Exhausted issuance quotas do not invalidate issued leases.
    pub fn restore_secret_leases(&mut self, cube: &Cube, leases: Vec<SecretLease>) {
        let leases = leases
            .into_iter()
            .filter(|lease| secret_authority(&self.caps, cube, &lease.request))
            .collect();
        if let Some(broker) = self.secret_broker.as_mut() {
            broker.restore(leases);
        }
    }

    /// leases ที่ยังมีชีวิตไว้ persist (G4b — runtime เท่านั้น)
    pub fn live_secret_leases(&self) -> Vec<aivm_secrets::SecretLease> {
        match &self.secret_broker {
            Some(b) => b.live_leases(),
            None => vec![],
        }
    }

    /// `secret.request`: ขอ one-time lease สำหรับ secret (G4 §26)
    ///
    /// สายบังคับใช้: structured schema เข้ม (ขาด/เกิน/type ผิด = DENY) ->
    /// broker ตรวจ capability + policy -> Low ออก lease ให้เลย, High ที่ไม่มี
    /// approval = DENY + audit `hitl-required` (approve flow แยกต่างหาก)
    ///
    /// คืนเฉพาะ lease_id + metadata — **secret value ไม่มีทางกลับไป
    /// AI context** (I-2/tool-scoped: ค่าถูก inject เข้า child env ตอน exec
    /// เท่านั้น แล้ว zeroize)
    pub fn secret_request(
        &mut self,
        cube: &mut Cube,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "secret.request", "-")?;
        let body: SecretRequestBody = match content {
            Some(s) => serde_json::from_str(s).map_err(|_| {
                self.deny_secret(
                    cube,
                    "bad-secret-request",
                    "secret.request needs a JSON object",
                )
            })?,
            None => {
                return Err(self.deny_secret(
                    cube,
                    "bad-secret-request",
                    "secret.request needs a JSON object",
                ));
            }
        };
        // ฟิลด์ต้องไม่ว่างและไม่ยาวเกิน (กัน log บวม — value ไม่มีทางผ่านช่องนี้)
        for (name, v) in [
            ("tool", &body.tool),
            ("resource", &body.resource),
            ("scope", &body.scope),
            ("purpose", &body.purpose),
        ] {
            if v.is_empty() || v.len() > MAX_SECRET_FIELD {
                return Err(self.deny_secret(
                    cube,
                    "bad-secret-request",
                    &format!("bad secret.request field: {name}"),
                ));
            }
        }
        // consumer binding: MVP มีผู้ใช้แค่ process.exec (อย่างอื่น = DENY)
        if body.tool != "process.exec" {
            return Err(self.deny_secret(
                cube,
                "secret-tool-unknown",
                "secret consumer must be process.exec",
            ));
        }
        let risk = match body.risk.as_deref() {
            None | Some("high") => RiskLevel::High,
            Some("low") => RiskLevel::Low,
            Some(_) => {
                return Err(self.deny_secret(
                    cube,
                    "bad-secret-request",
                    "risk must be low or high",
                ));
            }
        };
        let req = SecretRequest {
            tool: body.tool.clone(),
            resource: body.resource.clone(),
            scope: body.scope.clone(),
            purpose: body.purpose.clone(),
            max_uses: body.max_uses.unwrap_or(1),
            ttl_seconds: body.ttl_seconds.unwrap_or(300),
            risk,
        };
        let scope = format!("{}:{}", req.resource, req.scope);
        let broker = match self.secret_broker.as_mut() {
            Some(b) => b,
            None => {
                return Err(self.deny_secret(
                    cube,
                    "secret-unconfigured",
                    "secret broker not configured",
                ));
            }
        };
        // borrow broker จบใน match นี้ (owned ออกมา) แล้วค่อย audit
        // pending lease id (high-risk) ส่งต่อใน audit result ให้ operator
        // เอาไป approve (id ไม่ใช่ secret บอกได้)
        enum Outcome {
            Allow(SecretLease),
            Deny {
                rule: &'static str,
                msg: String,
                audit_result: String,
            },
        }
        let outcome = match broker.request_lease(req, cube, &mut self.caps, false, None) {
            Ok(lease) => Outcome::Allow(lease),
            Err(e) => {
                let (rule, msg, audit_result) = match &e {
                    SecretError::HitlRequired(id) => (
                        "hitl-required",
                        "high-risk secret requires operator approval".to_string(),
                        format!("pending:{id}"),
                    ),
                    SecretError::CapabilityDenied(_) => {
                        ("no-capability", "no capability".into(), "error".into())
                    }
                    SecretError::PolicyDenied(_) => (
                        "secret-policy",
                        "secret denied by policy".into(),
                        "error".into(),
                    ),
                    // ไม่บอกว่ามี resource อะไรบ้าง (กัน enumerate)
                    SecretError::SecretNotFound(_) => (
                        "secret-unknown",
                        "unknown secret resource".into(),
                        "error".into(),
                    ),
                    SecretError::InvalidRequest(_) => (
                        "bad-secret-request",
                        "bad secret request".into(),
                        "error".into(),
                    ),
                    _ => (
                        "secret-error",
                        "secret request failed".into(),
                        "error".into(),
                    ),
                };
                Outcome::Deny {
                    rule,
                    msg,
                    audit_result,
                }
            }
        };
        match outcome {
            Outcome::Allow(lease) => {
                let out = serde_json::json!({
                    "lease_id": lease.id,
                    "resource": lease.request.resource,
                    "scope": lease.request.scope,
                    "max_uses": lease.request.max_uses,
                    "hitl_approved": lease.hitl_approved,
                })
                .to_string();
                self.audit_decision(
                    cube,
                    "secret.request",
                    &scope,
                    "allow",
                    "lease-issued",
                    "success",
                )?;
                self.checkpoint(cube)?;
                Ok(ToolResult {
                    verification: None,
                    ok: true,
                    decision: "allow".into(),
                    output: out,
                })
            }
            Outcome::Deny {
                rule,
                msg,
                audit_result,
            } => {
                self.audit_decision(cube, "secret.request", &scope, "deny", rule, &audit_result)?;
                self.checkpoint(cube)?;
                Err(ToolError::Denied(msg))
            }
        }
    }

    /// deny  helper ของ `secret.request` (audit + Err ในรูปเดียว — resource
    /// ยังไม่รู้ตอน parse จึงใช้ "-")
    fn deny_secret(&mut self, cube: &mut Cube, rule: &str, msg: &str) -> ToolError {
        if let Err(e) = self.audit_decision(cube, "secret.request", "-", "deny", rule, "error") {
            return e;
        }
        ToolError::Denied(msg.to_string())
    }
}

/// Recheck authority without consuming the quota already charged at issuance.
pub(super) fn secret_authority(caps: &CapabilitySet, cube: &Cube, request: &SecretRequest) -> bool {
    let scope = format!("{}:{}", request.resource, request.scope);
    caps.caps.iter().any(|cap| {
        cap.covers("use", "secret", &scope)
            && !cap.is_expired()
            && !cap
                .condition
                .as_ref()
                .is_some_and(|condition| condition.is_stale_in(cube.current_state().as_str()))
    })
}

/// ล้างค่า secret ใน env pairs (best-effort zeroize)
pub(super) fn zeroize_env(env: &mut [(String, String)]) {
    for (_, v) in env.iter_mut() {
        zeroize_secret(v);
    }
}
