use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{AuditResult, Finding, ServerConfig, Severity};

#[derive(Serialize, Deserialize)]
struct BaselineServer {
    name: String,
    #[serde(default)]
    probed: bool,
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
                probed: r.probed,
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
    let base: Baseline =
        serde_json::from_str(&text).map_err(|e| format!("{} is not a valid baseline: {e}", path))?;
    if base.version != 1 {
        return Err(format!(
            "{}: unsupported baseline format version {} (expected 1) — re-save the baseline",
            path, base.version
        ));
    }
    Ok(base)
}

fn fingerprint(s: &ServerConfig) -> String {
    match (&s.command, &s.url) {
        (Some(c), _) => format!("{} {}", c, s.args.join(" ")),
        (_, Some(u)) => u.clone(),
        _ => String::new(),
    }
}

/// Compare audited results against a baseline, returning drift findings.
pub fn diff(
    baseline: &Baseline,
    results: &[AuditResult],
    name_filter: &[String],
) -> (Vec<(String, Finding)>, Vec<String>) {
    let matches_filter = |name: &str| name_filter.is_empty() || name_filter.iter().any(|n| name.contains(n.as_str()));
    let mut findings = Vec::new();
    let mut removed = Vec::new();

    for old in &baseline.servers {
        if !matches_filter(&old.name) {
            continue; // scoped out by --only; not a removal
        }
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
                if !old.probed && r.probed && !r.tools.is_empty() {
                    findings.push((
                        r.server.name.clone(),
                        Finding {
                            id: "BASELINE_NOT_PROBED".into(),
                            severity: Severity::Low,
                            message: "Baseline was saved without --probe, so it recorded no tools; tool drift cannot be checked — re-save the baseline with --probe".into(),
                            evidence: None,
                        },
                    ));
                } else {
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
    }

    for r in results {
        if !baseline.servers.iter().any(|s| s.name == r.server.name) && matches_filter(&r.server.name) {
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
        let (f, _) = diff(&base, &now, &[]);
        assert!(f.iter().any(|(_, x)| x.id == "TOOL_ADDED" && x.severity == Severity::High));
    }

    #[test]
    fn detects_command_change() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/evil", &["read"])
            ];
        let (f, _) = diff(&base, &now, &[]);
        assert!(f.iter().any(|(_, x)| x.id == "CONFIG_DRIFT" && x.severity == Severity::Critical));
    }

    #[test]
    fn clean_match_is_silent() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/fs", &["read", "write"]), server("web", "/bin/web", &["fetch"])];
        let (f, removed) = diff(&base, &now, &[]);
        assert!(f.is_empty(), "unexpected findings: {f:?}");
        assert!(removed.is_empty());
    }

    #[test]
    fn detects_new_and_removed_servers() {
        let base = load("testdata/baseline.json").unwrap();
        let now = vec![server("fs", "/bin/fs", &["read", "write"]), server("extra", "/bin/x", &[])
            ];
        let (f, removed) = diff(&base, &now, &[]);
        assert!(f.iter().any(|(_, x)| x.id == "SERVER_ADDED"));
        assert_eq!(removed, vec!["web".to_string()]);
    }
}

#[cfg(test)]
mod unprobed_tests {
    use super::*;
    use crate::model::ToolInfo;

    #[test]
    fn unprobed_baseline_warns_instead_of_false_added() {
        let base: Baseline = serde_json::from_str(
            r#"{
                "version":1,
                "servers":[{"name":"fs","command":"/bin/fs","args":[],"url":null,"probed":false,"tools":[]}]
            }"#,
        ).unwrap();
        let s = ServerConfig {
            name: "fs".into(), source_file: "t".into(), transport: "stdio".into(),
            command: Some("/bin/fs".into()), args: vec![], env: vec![], url: None,
        };
        let tools = vec![ToolInfo { name: "read".into(), description: None }];
        let r = crate::analyze::finalize(&s, true, None, tools, vec![]);
        let (f, _) = diff(&base, &[r], &[]);
        assert!(f.iter().any(|(_, x)| x.id == "BASELINE_NOT_PROBED"));
        assert!(!f.iter().any(|(_, x)| x.id == "TOOL_ADDED"));
    }

    #[test]
    fn only_filter_scopes_removals() {
        let base: Baseline = serde_json::from_str(
            r#"{
                "version":1,
                "servers":[
                    {"name":"fs","command":"/bin/fs","args":[],"url":null,"probed":true,"tools":[]},
                    {"name":"web","command":"/bin/web","args":[],"url":null,"probed":true,"tools":[]}
                ]
            }"#,
        ).unwrap();
        let s = ServerConfig {
            name: "fs".into(), source_file: "t".into(), transport: "stdio".into(),
            command: Some("/bin/fs".into()), args: vec![], env: vec![], url: None,
        };
        let r = crate::analyze::finalize(&s, false, None, vec![], vec![]);
        let (f, removed) = diff(&base, &[r], &["fs".to_string()]);
        assert!(f.is_empty());
        assert!(removed.is_empty());
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    #[test]
    fn future_baseline_version_rejected() {
        let dir = std::env::temp_dir().join("mcpaudit-ver-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("b.json");
        std::fs::write(&p, r#"{"version": 99, "servers": []}"#).unwrap();
        assert!(load(p.to_str().unwrap()).is_err());
    }
}
