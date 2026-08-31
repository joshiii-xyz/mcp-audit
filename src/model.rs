use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ServerConfig {
    pub name: String,
    pub source_file: String,
    /// "stdio" or "http"
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditResult {
    pub server: ServerConfig,
    pub probed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub tools: Vec<ToolInfo>,
    pub findings: Vec<Finding>,
    pub score: u32,
    pub grade: char,
}

pub fn grade_for(score: u32) -> char {
    match score {
        90..=100 => 'A',
        75..=89 => 'B',
        60..=74 => 'C',
        40..=59 => 'D',
        _ => 'F',
    }
}

// ---- redaction / sanitizing helpers (used at output boundaries) ----

const SECRET_HINTS: &[&str] = &[
    "secret", "token", "api_key", "apikey", "api-key", "password", "passwd",
    "private_key", "privatekey", "access_key", "accesskey", "credential", "auth",
    "authorization", "session", "cookie",
];

fn is_secretish(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 20 || v.contains(char::is_whitespace) || v.starts_with('/') {
        return false;
    }
    let known = ["sk-", "ghp_", "gho_", "github_pat_", "AKIA", "xoxb-", "xoxp-", "Bearer ", "eyJ"];
    if known.iter().any(|p| v.starts_with(p)) {
        return true;
    }
    v.chars().all(|c| c.is_ascii_alphanumeric() || "-_.=~+".contains(c)) && v.chars().any(|c| c.is_ascii_digit())
}

pub fn redact_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut prev_is_flag = false;
    for a in args {
        let hint = SECRET_HINTS.iter().any(|h| a.to_lowercase().contains(h));
        if is_secretish(a) {
            out.push("[REDACTED]".into());
        } else if prev_is_flag {
            out.push("[REDACTED]".into());
        } else {
            out.push(a.clone());
        }
        prev_is_flag = hint;
    }
    out
}

pub fn redact_url(url: &str) -> String {
    // scheme://user:password@host -> scheme://user:[REDACTED]@host
    if let Some(scheme_end) = url.find("://") {
        let (scheme, rest) = url.split_at(scheme_end + 3);
        if let Some(at) = rest.find('@') {
            let userinfo = &rest[..at];
            if let Some(colon) = userinfo.find(':') {
                let user = &userinfo[..colon];
                return format!("{scheme}{user}:[REDACTED]@{}", &rest[at + 1..]);
            }
        }
    }
    url.to_string()
}

pub fn redact_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter().map(|(k, _)| (k.clone(), "[REDACTED]".to_string())).collect()
}

/// Escape control characters (ESC, newlines, etc.) so untrusted strings
/// cannot inject terminal escape sequences into reports.
pub fn sanitize_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\x1b' => out.push_str("\\e"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
