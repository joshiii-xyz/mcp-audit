use crate::model::AuditResult;

fn sev_color(s: crate::model::Severity) -> &'static str {
    use crate::model::Severity::*;
    match s {
        Critical => "\x1b[1;91m",
        High => "\x1b[1;93m",
        Medium => "\x1b[33m",
        Low => "\x1b[90m",
        Info => "\x1b[2m",
    }
}

const RESET: &str = "\x1b[0m";

/// Copy of results safe to print: secrets in args/urls/env redacted and all
/// untrusted strings stripped of control characters.
fn display(results: &[AuditResult]) -> Vec<AuditResult> {
    use crate::model::{redact_args, redact_env, redact_url, sanitize_display};
    results.iter().map(|r| {
        let mut server = r.server.clone();
        server.name = sanitize_display(&server.name);
        server.source_file = sanitize_display(&server.source_file);
        server.args = redact_args(&server.args).iter().map(|a| sanitize_display(a)).collect();
        server.env = redact_env(&server.env);
        server.url = server.url.as_ref().map(|u| sanitize_display(&redact_url(u)));
        if let Some(c) = &server.command {
            server.command = Some(sanitize_display(c));
        }
        let mut out = r.clone();
        out.server = server;
        out.tools = r.tools.iter().map(|t| crate::model::ToolInfo {
            name: sanitize_display(&t.name),
            description: t.description.as_ref().map(|d| sanitize_display(d)),
        }).collect();
        out.findings = r.findings.iter().map(|f| crate::model::Finding {
            id: f.id.clone(),
            severity: f.severity,
            message: sanitize_display(&f.message),
            evidence: f.evidence.as_ref().map(|e| sanitize_display(e)),
        }).collect();
        out.error = r.error.as_ref().map(|e| sanitize_display(e));
        out
    }).collect()
}

pub fn print_text(results: &[AuditResult], removed: &[String]) {
    let results = &display(results);
    let removed: Vec<String> = removed.iter().map(|r| crate::model::sanitize_display(r)).collect();
    for r in results {
        let s = &r.server;
        let via = match (&s.command, &s.url) {
            (Some(c), _) => {
                let mut x = c.clone();
                for a in &s.args {
                    x.push(' ');
                    x.push_str(a);
                }
                x
            }
            (_, Some(u)) => u.clone(),
            _ => "?".into(),
        };
        let grade_color = match r.grade {
            'A' => "\x1b[1;92m",
            'B' => "\x1b[1;32m",
            'C' => "\x1b[1;33m",
            'D' => "\x1b[1;91m",
            _ => "\x1b[1;31m",
        };
        println!(
            "\n{} [{grade_color}{}{RESET} {}/100] {}  ({} {})",
            sev_color(crate::model::Severity::Info),
            r.grade,
            r.score,
            s.name,
            s.transport,
            if r.probed { "probed" } else { "static only" }
        );
        println!("  via: {via}");
        println!("  config: {}", s.source_file);
        if let Some(e) = &r.error {
            println!("  {}probe error:{RESET} {e}", sev_color(crate::model::Severity::Medium));
        }
        if r.tools.is_empty() && r.probed {
            println!("  tools: none exposed");
        } else if !r.tools.is_empty() {
            println!("  tools ({}):", r.tools.len());
            for t in r.tools.iter().take(25) {
                println!("    - {}", t.name);
            }
            if r.tools.len() > 25 {
                println!("    ... and {} more", r.tools.len() - 25);
            }
        }
        if r.findings.is_empty() {
            println!("  findings: none");
        } else {
            println!("  findings:");
            for f in &r.findings {
                print!(
                    "    {}[{}]{RESET} {}",
                    sev_color(f.severity),
                    format!("{:?}", f.severity).to_uppercase(),
                    f.message
                );
                if let Some(e) = &f.evidence {
                    print!(" — \x1b[2m{e}\x1b[0m");
                }
                println!();
            }
        }
    }
    if !removed.is_empty() {
        println!(
            "\n{}[BASELINE]{} servers no longer present: {}",
            sev_color(crate::model::Severity::Medium),
            RESET,
            removed.join(", ")
        );
    }
    let a = results.iter().filter(|r| r.grade == 'A').count();
    let crit: usize = results
        .iter()
        .map(|r| r.findings.iter().filter(|f| f.severity == crate::model::Severity::Critical).count())
        .sum();
    println!(
        "\n{} servers audited, {} graded A, {crit} critical finding(s){RESET}\n",
        results.len(),
        a
    );
}

pub fn print_json(results: &[AuditResult]) {
    let safe = display(results);
    println!("{}", serde_json::to_string_pretty(&safe).unwrap_or_default());
}
