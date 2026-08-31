use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
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

// ---- raw config parsing ----

#[derive(Deserialize)]
pub struct RawMcpConfig {
    #[serde(default)]
    pub mcp_servers: std::collections::HashMap<String, RawServer>,
    // VS Code style
    #[serde(default)]
    pub servers: std::collections::HashMap<String, RawServer>,
}

#[derive(Deserialize)]
pub struct RawServer {
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    pub url: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub r#type: Option<String>,
}
