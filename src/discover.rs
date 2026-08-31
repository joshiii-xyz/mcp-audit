use std::path::Path;

use crate::model::{RawMcpConfig, RawServer, ServerConfig};

fn home() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Well-known MCP config locations on disk.
pub fn candidate_files() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(h) = home() {
        v.push(format!("{h}/.claude.json")); // Claude Code
        v.push(format!("{h}/.claude/mcp.json"));
        v.push(format!(
            "{h}/Library/Application Support/Claude/claude_desktop_config.json"
        )); // macOS desktop
        v.push(format!(
            "{h}/.config/Claude/claude_desktop_config.json"
        )); // Linux desktop
        v.push(format!("{h}/.cursor/mcp.json"));
        v.push(format!("{h}/.codeium/windsurf/mcp_config.json"));
        v.push(format!("{h}/.vscode/mcp.json"));
        v.push(format!("{h}/.gemini/settings.json"));
    }
    v
}

fn parse_config(text: &str, path: &str) -> Vec<ServerConfig> {
    let cfg: RawMcpConfig = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut collect = |map: &std::collections::HashMap<String, RawServer>| {
        for (name, s) in map {
            let transport = if s.command.is_some() {
                "stdio"
            } else if s.url.is_some() {
                "http"
            } else {
                continue;
            };
            out.push(ServerConfig {
                name: name.clone(),
                source_file: path.to_string(),
                transport: transport.to_string(),
                command: s.command.clone(),
                args: s.args.clone(),
                env: s.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                url: s.url.clone(),
            });
        }
    };
    collect(&cfg.mcp_servers);
    collect(&cfg.servers);
    out
}

/// Discover MCP servers from known config files plus explicit paths.
pub fn discover(extra_paths: &[String]) -> Vec<ServerConfig> {
    let mut servers = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut paths: Vec<String> = candidate_files();
    paths.extend(extra_paths.iter().cloned());
    for p in paths {
        let path = Path::new(&p);
        if !path.exists() {
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for s in parse_config(&text, &p) {
            // dedupe by (name, command/url)
            let key = format!(
                "{}|{}|{}",
                s.name,
                s.command.clone().unwrap_or_default(),
                s.url.clone().unwrap_or_default()
            );
            if !seen.contains(&key) {
                seen.push(key);
                servers.push(s);
            }
        }
    }
    servers
}
