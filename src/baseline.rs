use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{AuditResult, Finding, ServerConfig, Severity};

#[derive(Serialize, Deserialize)]
struct BaselineServer {
    name: String,
    command: String,
    args: Vec<String>,
    url: Option<String>,
    tools: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    version: u32,
    servers: Vec<BaselineServer>,
}

pub fn save(path: &str, results: &[AuditResult]) -> Result<(), String> {
    let b = Baseline {
        version: 1,
        servers: results
            .iter()
            .map(|r| BaselineServer {
                name: r.server.name.clone(),
                command: r.server.command.clone().unwrap_or_default(),
                args: r.server.args.clone(),
                url: r.server.url.clone(),
                tools: r.tools.iter().map(|t| t.name.clone()).collect(),
            })
            .collect(),
    };
    let json = serde_json::to_string_pretty(&b).map_err(|e| e.to_string())?;
    std::fs::write(Path::new(path), json).map_err(|e| format!("cannot write {}: {e}", path))
}

pub fn load(path: &str) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(Path::new(path))
        .map_err(|e| format!("cannot read {}: {e}", path))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not a valid baseline: {e}", path))
}

fn fingerprint(s: &ServerConfig) -> String {
    match (&s.command, &s.url) {
        (Some(c), _) => format!("{} {}", c, s.args.join(" ")),
        (_, Some(u)) => u.clone(),
        _ => String::new(),
    }
}

/// Compare audited results against a baseline, returning drift findings.
pub fn diff(baseline: &Baseline, results: &[AuditResult]) -> (Vec<(String, Finding)>, Vec<String>) {
    let mut findings = Vec::new();
    let mut removed = Vec::new();

    for old in &baseline.servers {
        match results.iter().find(|r| r.server.name == old.name) {
            None => removed.push(old.name.clone()),
            Some(r) => {
                let old_fp = if old.url.as_deref().map_or(false, |u| !u.is_empty()) {
                    old.url.clone().unwrap()
                } else {
                    format!("{} {}", old.command, old.args.join(" "))
                };
                if fingerprint(&r.server) != old_fp {
                    findings.push((
                        r.server.name.clone(),
                        Finding {
                            id: "CONFIG_DRIFT".into(),
                            severity: Severity::Critical,
                            message: "Server command/URL changed since baseline — config may have been tampered with".into(),
                            evidence: None,
                        },
                    ));
                }
                let old_tools: std::collections::HashSet<&str> =
                    old.tools.iter().map(|s| s.as_str()).collect();
                for t in &r.tools {
                    if !old_tools.contains(t.name.as_str()) {
                        findings.push((
                            r.server.name.clone(),
                            Finding {
                                id: "TOOL_ADDED".into(),
                                severity: Severity::High,
                                message: format!("Tool '{}' appeared since baseline — the server gained a new capability silently", t.name),
                                evidence: None,
                            },
                        ));
                    }
                }
                let new_tools: std::collections::HashSet<&str> =
                    r.tools.iter().map(|t| t.name.as_str()).collect();
                for t in &old.tools {
                    if !new_tools.contains(t.as_str()) {
                        findings.push((
                            r.server.name.clone(),
                            Finding {
                                id: "TOOL_REMOVED".into(),
                                severity: Severity::Low,
                                message: format!("Tool '{}' disappeared since baseline", t),
                                evidence: None,
                            },
                        ));
                    }
                }
            }
        }
    }

    for r in results {
        if !baseline.servers.iter().any(|s| s.name == r.server.name) {
            findings.push((
                r.server.name.clone(),
                Finding {
                    id: "SERVER_ADDED".into(),
                    severity: Severity::Medium,
                    message: "New MCP server appeared since baseline".into(),
                    evidence: None,
                },
            ));
        }
    }

    (findings, removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ToolInfo;

    fn server(name: &str, cmd: &str, tools: &[&str]) -> AuditResult {
        let s = ServerConfig {
            name: name.into(), source_file: "t".into(), transport: "stdio".into(),
            command: Some(cmd.into()), args: vec![], env: vec![], url: None,
        };
        let t = tools.iter().map(|n| ToolInfo { name: n.to_string(), description: None }).collect();
        crate::analyze::finalize(&s, true, None, t, vec![])
    }

    #[test]
    fn detects_added_tool() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/fs", &["read", "write", "exec"])
            ];
        let (f, _) = diff(&base, &now);
        assert!(f.iter().any(|(_, x)| x.id == "TOOL_ADDED" && x.severity == Severity::High));
    }

    #[test]
    fn detects_command_change() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/evil", &["read"])
            ];
        let (f, _) = diff(&base, &now);
        assert!(f.iter().any(|(_, x)| x.id == "CONFIG_DRIFT" && x.severity == Severity::Critical));
    }

    #[test]
    fn clean_match_is_silent() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/fs", &["read", "write"]), server("web", "/bin/web", &["fetch"])];
        let (f, removed) = diff(&base, &now);
        assert!(f.is_empty(), "unexpected findings: {f:?}");
        assert!(removed.is_empty());
    }

    #[test]
    fn detects_new_and_removed_servers() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/fs", &["read", "write"]), server("extra", "/bin/x", &[])
            ];
        let (f, removed) = diff(&base, &now);
        assert!(f.iter().any(|(_, x)| x.id == "SERVER_ADDED"));
        assert_eq!(removed, vec!["web".to_string()]);
    }
}
