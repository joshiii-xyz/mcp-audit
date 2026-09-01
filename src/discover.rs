use std::collections::HashSet;
use std::path::Path;

use crate::model::ServerConfig;

fn home() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Well-known MCP config locations on disk (macOS/Linux).
pub fn candidate_files() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(h) = home() {
        v.push(format!("{h}/.claude.json")); // Claude Code
        v.push(format!("{h}/.claude/mcp.json"));
        v.push(format!("{h}/Library/Application Support/Claude/claude_desktop_config.json"));
        v.push(format!("{h}/.config/Claude/claude_desktop_config.json"));
        v.push(format!("{h}/.cursor/mcp.json"));
        v.push(format!("{h}/.codeium/windsurf/mcp_config.json"));
        v.push(format!("{h}/.vscode/mcp.json"));
        v.push(format!("{h}/.gemini/settings.json"));
    }
    v
}

/// Recursively walk a JSON document and collect every object found under a
/// `mcpServers` or `servers` key (handles both camelCase clients like Claude
/// Desktop/Cursor/Windsurf and snake_case/VS Code styles, at any nesting
/// depth — e.g. Claude Code's `projects.<path>.mcpServers`).
fn walk(value: &serde_json::Value, path: &str, warnings: &mut Vec<String>, out: &mut Vec<ServerConfig>, depth: usize) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                // "mcpServers"/"mcp_servers" are unambiguous at any depth; a
                // bare "servers" key is only trusted at the document root to
                // avoid auditing unrelated "servers" blocks in generic JSON.
                let is_server_key = matches!(k.as_str(), "mcpServers" | "mcp_servers")
                    || (k == "servers" && depth == 0);
                if is_server_key && v.is_object() {
                    for (name, entry) in v.as_object().unwrap() {
                        parse_entry(name, entry, path, warnings, out);
                    }
                } else {
                    walk(v, path, warnings, out, depth + 1);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for it in items {
                walk(it, path, warnings, out, depth);
            }
        }
        _ => {}
    }
}

fn parse_entry(name: &str, entry: &serde_json::Value, path: &str, warnings: &mut Vec<String>, out: &mut Vec<ServerConfig>) {
    let Some(obj) = entry.as_object() else {
        warnings.push(format!("{path}: server '{name}' skipped (not an object)"));
        return;
    };
    let command = obj.get("command").and_then(|c| c.as_str()).map(|s| s.to_string());
    let url = obj.get("url").and_then(|u| u.as_str()).map(|s| s.to_string());
    if command.is_none() && url.is_none() {
        warnings.push(format!(
            "{path}: server '{name}' skipped (no 'command' or 'url' string field)"
        ));
        return;
    }
    let transport = if command.is_some() { "stdio" } else { "http" };

    let mut args = Vec::new();
    if let Some(a) = obj.get("args") {
        match a.as_array() {
            Some(items) => {
                for it in items {
                    match it.as_str() {
                        Some(s) => args.push(s.to_string()),
                        None => warnings.push(format!(
                            "{path}: server '{name}' has a non-string args element (ignored)"
                        )),
                    }
                }
            }
            None => warnings.push(format!("{path}: server '{name}' has non-array 'args' (ignored)")),
        }
    }

    let mut env = Vec::new();
    if let Some(e) = obj.get("env") {
        match e.as_object() {
            Some(map) => {
                for (k, v) in map {
                    match v.as_str() {
                        Some(s) => env.push((k.clone(), s.to_string())),
                        None => warnings.push(format!(
                            "{path}: server '{name}' env var '{k}' is not a string (ignored)"
                        )),
                    }
                }
            }
            None => warnings.push(format!("{path}: server '{name}' has non-object 'env' (ignored)")),
        }
    }

    out.push(ServerConfig {
        name: name.to_string(),
        source_file: path.to_string(),
        transport: transport.to_string(),
        command,
        args,
        env,
        url,
    });
}

/// Discover MCP servers from known config files plus explicit paths.
/// Returns (servers, per-file warnings). Explicit paths that are missing or
/// unreadable are hard errors; auto-discovered ones are silently skipped.
pub fn discover(extra_paths: &[String]) -> Result<(Vec<ServerConfig>, Vec<String>), String> {
    let mut servers = Vec::new();
    let mut warnings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut paths: Vec<(String, bool)> = candidate_files().into_iter().map(|p| (p, false)).collect();
    paths.extend(extra_paths.iter().cloned().map(|p| (p, true)));

    for (p, explicit) in paths {
        let path = Path::new(&p);
        if !path.exists() {
            if explicit {
                return Err(format!("config not found: {p}"));
            }
            continue;
        }
        let text = match std::fs::read(path) {
            Ok(t) => t,
            Err(e) => {
                if explicit {
                    return Err(format!("cannot read {p}: {e}"));
                }
                continue;
            }
        };
        let text = match String::from_utf8(text) {
            Ok(t) => t,
            Err(_) => {
                let msg = format!("{p}: not valid UTF-8, skipped");
                if explicit {
                    return Err(msg);
                }
                warnings.push(msg);
                continue;
            }
        };
        // strip BOM if present
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let value: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("{p}: invalid JSON ({e}); file skipped");
                if explicit {
                    return Err(msg);
                }
                warnings.push(msg);
                continue;
            }
        };
        let before = servers.len();
        walk(&value, &p, &mut warnings, &mut servers, 0);
        if servers.len() == before {
            warnings.push(format!("{p}: parsed but contains no MCP server entries"));
        }
    }

    // dedupe on name + command + args + url
    servers.retain(|s| {
        let key = format!(
            "{}|{}|{}|{}",
            s.name,
            s.command.clone().unwrap_or_default(),
            s.args.join("\u{1f}"),
            s.url.clone().unwrap_or_default()
        );
        seen.insert(key)
    });

    Ok((servers, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_camelcase_mcpservers() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"mcpServers":{"fs":{"command":"/bin/fs","args":["-v"],"env":{"API_TOKEN":"x"}}}}"#,
        ).unwrap();
        let mut out = Vec::new();
        let mut warn = Vec::new();
        walk(&doc, "test", &mut warn, &mut out, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "fs");
    }

    #[test]
    fn parses_nested_projects_mcpservers() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"projects":{"/home/user/proj":{"mcpServers":{"nested":{"command":"/bin/x"}}}},"mcp_servers":{}}"#,
        ).unwrap();
        let mut out = Vec::new();
        let mut warn = Vec::new();
        walk(&doc, "test", &mut warn, &mut out, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "nested");
    }

    #[test]
    fn tolerant_of_malformed_entries() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"mcpServers":{
                "good":{"command":"/bin/ok","args":[]},
                "badenv":{"command":"/bin/b","env":{"PORT":8080}},
                "notobj":"oops",
                "nothing":{"foo":1}
            }}"#,
        ).unwrap();
        let mut out = Vec::new();
        let mut warn = Vec::new();
        walk(&doc, "test", &mut warn, &mut out, 0);
        assert_eq!(out.len(), 2, "good + badenv survive; notobj/nothing skipped");
        assert!(!warn.is_empty());
    }
}
