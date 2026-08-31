use crate::model::AuditResult;

fn sev_color(s: crate::model::Severity) -> &'static str {
    use crate::model::Severity::*;
    match s {
        Critical => "\x1b[1;91m",
        High => "\x1b[1;93m",
        Medium => "\x1b[33m",
        Low => "\x1b[90m",
    }
}

const RESET: &str = "\x1b[0m";

pub fn print_text(results: &[AuditResult]) {
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
            sev_color(crate::model::Severity::Low),
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
                print!("    {}[{}]{RESET} {}", sev_color(f.severity), format!("{:?}", f.severity).to_uppercase(), f.message);
                if let Some(e) = &f.evidence {
                    print!(" — \x1b[2m{e}\x1b[0m");
                }
                println!();
            }
        }
    }
    // summary
    let (a, crit) = (
        results.iter().filter(|r| r.grade == 'A').count(),
        results.iter().map(|r| r.findings.iter().filter(|f| f.severity == crate::model::Severity::Critical).count()).sum::<usize>(),
    );
    println!(
        "\n{} servers audited, {} graded A, {crit} critical finding(s){RESET}\n",
        results.len(),
        a
    );
}

pub fn print_json(results: &[AuditResult]) {
    println!("{}", serde_json::to_string_pretty(results).unwrap_or_default());
}
