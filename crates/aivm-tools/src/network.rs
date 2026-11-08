//! HTTPS/TCP mediation, public destination checks, and byte accounting.
use crate::{ToolError, ToolGateway, ToolResult};
use aivm_cube::Cube;
use aivm_policy::Decision;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const MAX_FILE_BYTES: u64 = 1024 * 1024;

impl ToolGateway {
    /// `network.fetch`: HTTP request ผ่าน policy/network capability
    ///
    /// path: target URL (e.g., "https://api.github.com/repos/owner/repo")
    /// content: JSON { "method": "GET", "headers": {}, "body": null, "timeout_ms": 30000 }
    pub fn network_fetch(
        &mut self,
        cube: &mut Cube,
        url: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "network:fetch", url)?;
        let result = self.fetch_checked(cube, url, content);
        if let Err(ref error) = result {
            self.audit_decision(
                cube,
                "network:fetch",
                url,
                "deny",
                "fetch-failed",
                &error.to_string(),
            )?;
        }
        result
    }

    fn fetch_checked(
        &mut self,
        cube: &mut Cube,
        url: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        use aivm_capability::AuthorizationContext;
        let req: NetworkFetchRequest = serde_json::from_str(content.unwrap_or("{}"))
            .map_err(|e| ToolError::Denied(format!("invalid network.fetch request: {e}")))?;
        req.validate_read_only(self.policy.network.read_only)?;
        let (host, port, protocol) = parse_url(url)?;
        let scope = network_scope(&host, port);
        let action =
            if req.method.eq_ignore_ascii_case("GET") || req.method.eq_ignore_ascii_case("HEAD") {
                "network:fetch"
            } else {
                "network:connect"
            };
        let timeout_ms = req.timeout_ms.unwrap_or(30000);
        if !(1..=60000).contains(&timeout_ms) {
            return Err(ToolError::Denied("invalid timeout".into()));
        }
        let context = AuthorizationContext {
            request_bytes: req.body.as_ref().map(|v| v.len() as u64),
            protocol: Some(&protocol),
            port: Some(port),
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        };
        let idx = self
            .caps
            .authorize_with_context(action, "network", &scope, &context)
            .map_err(|e| ToolError::Denied(format!("network capability or constraint: {e}")))?;
        if self.policy.evaluate_network(&scope, &Self::ctx_of(cube)).0 != Decision::Allow {
            return Err(ToolError::Denied("network policy denied".into()));
        }
        let method = req.method.to_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD"
        ) {
            return Err(ToolError::Denied("unsupported HTTP method".into()));
        }
        if req.headers.keys().any(|key| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "host" | "connection" | "content-length" | "transfer-encoding"
            )
        }) {
            return Err(ToolError::Denied("protected HTTP header".into()));
        }
        // resolve ครั้งเดียว ตรวจทุก IP แล้วตรึง resolver; ไม่ตาม redirect
        let addresses = public_addresses(&host, port)?;
        let request_bytes = req.body.as_ref().map_or(0, |body| body.len() as u64);
        self.audit_decision(
            cube,
            action,
            &scope,
            "allow",
            "network-authorized",
            "authorized",
        )?;
        // หักไบต์ขาออกก่อนส่งคำขอ; นับเฉพาะคำตอบจะเปิดทางให้ส่งข้อมูลออกไม่จำกัด
        self.caps.account_bytes(idx, request_bytes);
        self.checkpoint(cube)?;
        let agent = ureq::AgentBuilder::new()
            // ไม่รับ proxy จาก environment แม้ dependency เปิด feature เพิ่มภายหลัง
            .try_proxy_from_env(false)
            .https_only(true)
            .redirects(0)
            .resolver(move |_: &str| Ok(addresses.clone()))
            .build();
        let mut request = agent
            .request(&method, url)
            .timeout(Duration::from_millis(timeout_ms));
        for (key, value) in req.headers {
            request = request.set(&key, &value);
        }
        let response = match if let Some(body) = req.body {
            request.send_string(&body)
        } else {
            request.call()
        } {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => return Err(ToolError::Io(error.to_string())),
        };
        let status = response.status();
        if (300..400).contains(&status) {
            return Err(ToolError::Denied(
                "redirects are disabled; authorize target separately".into(),
            ));
        }
        let body = self.read_network_response(cube, idx, response.into_reader())?;
        let output =
            String::from_utf8(body).map_err(|_| ToolError::Io("response is not UTF-8".into()))?;
        self.audit_decision(
            cube,
            action,
            &scope,
            "allow",
            &format!("status:{status}"),
            "success",
        )?;
        Ok(ToolResult {
            verification: None,
            ok: (200..300).contains(&status),
            decision: "allow".into(),
            output,
        })
    }

    /// นับ payload ที่ reader ส่งให้แอป แม้คำตอบถูกปฏิเสธหรือขาดกลางทาง
    pub(super) fn read_network_response(
        &mut self,
        cube: &Cube,
        idx: usize,
        mut reader: impl std::io::Read,
    ) -> Result<Vec<u8>, ToolError> {
        let limit = self.caps.caps[idx]
            .constraints
            .max_response_bytes
            .unwrap_or(MAX_FILE_BYTES)
            .min(MAX_FILE_BYTES);
        let mut body = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let total_remaining = self.caps.caps[idx].bytes_remaining().unwrap_or(u64::MAX);
            let remaining = total_remaining.min(limit.saturating_sub(body.len() as u64));
            // lookahead สูงสุดหนึ่งไบต์เพื่อแยก EOF พอดีงบออกจาก oversized response
            let size = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
            let count = match reader.read(&mut buffer[..size]) {
                Ok(0) => return Ok(body),
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(ToolError::Io(error.to_string())),
            };
            self.caps.account_bytes(idx, count as u64);
            self.checkpoint(cube)?;
            // เทียบกับงบก่อนบวกด้วย เพื่อไม่ให้ saturating counter กลบ overrun ที่ u64::MAX
            if count as u64 > total_remaining {
                return Err(ToolError::Denied("network byte budget exceeded".into()));
            }
            if body.len() as u64 + count as u64 > limit {
                return Err(ToolError::Denied("response size limit exceeded".into()));
            }
            body.extend_from_slice(&buffer[..count]);
        }
    }

    pub fn network_connect(
        &mut self,
        cube: &mut Cube,
        host_port: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        self.check_quarantine(cube, "network:connect", host_port)?;
        let result = self.connect_checked(cube, host_port, content);
        if let Err(ref error) = result {
            self.audit_decision(
                cube,
                "network:connect",
                host_port,
                "deny",
                "connect-failed",
                &error.to_string(),
            )?;
        }
        result
    }

    fn connect_checked(
        &mut self,
        cube: &mut Cube,
        host_port: &str,
        content: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        use aivm_capability::AuthorizationContext;
        // raw connection ไม่มี HTTP method ให้บังคับอ่านเท่านั้น จึงปฏิเสธก่อน DNS
        if self.policy.network.read_only {
            return Err(ToolError::Denied(
                "read-only network forbids raw connections".into(),
            ));
        }
        let req: NetworkConnectRequest = serde_json::from_str(content.unwrap_or("{}"))
            .map_err(|e| ToolError::Denied(format!("invalid network.connect request: {e}")))?;
        if req.protocol != "tcp" {
            return Err(ToolError::Denied("protocol must be tcp".into()));
        }
        let (host, port) = parse_host_port(host_port)?;
        let scope = network_scope(&host, port);
        let timeout_ms = req.timeout_ms.unwrap_or(30000);
        if !(1..=60000).contains(&timeout_ms) {
            return Err(ToolError::Denied("invalid timeout".into()));
        }
        let protocol = if req.tls { "https" } else { "tcp" };
        let context = AuthorizationContext {
            protocol: Some(protocol),
            port: Some(port),
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        };
        self.caps
            .authorize_with_context("network:connect", "network", &scope, &context)
            .map_err(|e| ToolError::Denied(format!("network capability or constraint: {e}")))?;
        if self.policy.evaluate_network(&scope, &Self::ctx_of(cube)).0 != Decision::Allow {
            return Err(ToolError::Denied("network policy denied".into()));
        }
        let addresses = public_addresses(&host, port)?;
        self.audit_decision(
            cube,
            "network:connect",
            &scope,
            "allow",
            "network-authorized",
            "authorized",
        )?;
        self.checkpoint(cube)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut stream = None;
        for addr in addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if let Ok(connected) = std::net::TcpStream::connect_timeout(&addr, remaining) {
                stream = Some(connected);
                break;
            }
        }
        let mut stream = stream.ok_or_else(|| ToolError::Io("connection failed".into()))?;
        if req.tls {
            use ureq::rustls;
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| ToolError::Denied("invalid TLS server name".into()))?;
            let mut tls = rustls::ClientConnection::new(std::sync::Arc::new(config), server)
                .map_err(|e| ToolError::Io(e.to_string()))?;
            while tls.is_handshaking() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(ToolError::Io("TLS handshake timeout".into()));
                }
                stream
                    .set_read_timeout(Some(remaining))
                    .map_err(|e| ToolError::Io(e.to_string()))?;
                stream
                    .set_write_timeout(Some(remaining))
                    .map_err(|e| ToolError::Io(e.to_string()))?;
                tls.complete_io(&mut stream)
                    .map_err(|e| ToolError::Io(format!("TLS handshake: {e}")))?;
            }
        }
        self.audit_decision(
            cube,
            "network:connect",
            &scope,
            "allow",
            if req.tls {
                "tls-connected"
            } else {
                "tcp-connected"
            },
            "success",
        )?;
        Ok(ToolResult {
            verification: None,
            ok: true,
            decision: "allow".into(),
            output: format!("connected to {scope}"),
        })
    }
}

/// Network fetch request structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct NetworkFetchRequest {
    #[serde(default = "default_get")]
    method: String,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: Option<u64>,
}

impl NetworkFetchRequest {
    pub(super) fn validate_read_only(&self, read_only: bool) -> Result<(), ToolError> {
        // ตรวจทุก request รวม credential เก่าที่เคยมีสิทธิ์เขียน ก่อนหัก quota
        if read_only
            && (!(self.method.eq_ignore_ascii_case("GET")
                || self.method.eq_ignore_ascii_case("HEAD"))
                || self.body.is_some()
                || self.headers.keys().any(|key| {
                    let key = key.to_ascii_lowercase();
                    key == "x-http-method" || key.contains("method-override")
                }))
        {
            return Err(ToolError::Denied(
                "read-only network requires GET/HEAD without body or method override".into(),
            ));
        }
        Ok(())
    }
}

fn default_get() -> String {
    "GET".into()
}

fn default_timeout() -> Option<u64> {
    Some(30000)
}

/// Network connect request structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NetworkConnectRequest {
    #[serde(default = "default_tcp")]
    protocol: String,
    #[serde(default)]
    tls: bool,
    #[serde(default = "default_timeout")]
    timeout_ms: Option<u64>,
}

fn default_tcp() -> String {
    "tcp".into()
}

/// Parse URL to extract host, port, and protocol
pub(super) fn parse_url(url: &str) -> Result<(String, u16, String), ToolError> {
    let parsed =
        url::Url::parse(url).map_err(|e| ToolError::Denied(format!("invalid URL: {e}")))?;
    let protocol = parsed.scheme().to_string();
    if protocol != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ToolError::Denied(
            "HTTPS URL without credentials required".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ToolError::Denied("URL missing host".into()))?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ToolError::Denied("URL missing port".into()))?;
    if port == 0 {
        return Err(ToolError::Denied("invalid port".into()));
    }
    Ok((host, port, protocol))
}

pub(super) fn parse_host_port(target: &str) -> Result<(String, u16), ToolError> {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| ToolError::Denied("host:port required".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ToolError::Denied("invalid port".into()))?;
    if host.is_empty() || host.contains(['/', '@', ':']) || port == 0 {
        return Err(ToolError::Denied("invalid host:port".into()));
    }
    Ok((host.to_ascii_lowercase(), port))
}
fn network_scope(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
pub(super) fn public_addresses(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, ToolError> {
    use std::net::ToSocketAddrs;
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| ToolError::Io(e.to_string()))?
        .collect();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|a| !aivm_policy::is_public_address(a.ip()))
    {
        return Err(ToolError::Denied(
            "private, loopback, or reserved destination".into(),
        ));
    }
    Ok(addresses)
}
