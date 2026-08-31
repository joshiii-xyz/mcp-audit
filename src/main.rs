mod analyze;
mod discover;
mod model;
mod probe;
mod report;

use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "mcp-audit — scan and rate the trustworthiness of your MCP servers\n\n\
USAGE:\n  \
mcp-audit [options]\n\n\
OPTIONS:\n  \
  --probe            Launch each stdio server and inspect its exposed tools (default: static only)\n  \
  --json             Output a JSON report\n  \
  --strict           Exit non-zero if any server scores below C\n  \
  --timeout <secs>   Probe timeout in seconds (default: 10)\n  \
  --config <path>    Also scan an explicit MCP config file (repeatable)\n  \
  --help             Show this help\n\n\
EXAMPLES:\n  \
  mcp-audit                    # static audit of all known configs\n  \
  mcp-audit --probe --strict   # live probe + CI-friendly exit code\n"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut do_probe = false;
    let mut json = false;
    let mut strict = false;
    let mut timeout = 10;
    let mut extra: Vec<String> = Vec::new();

    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--probe" => do_probe = true,
            "--json" => json = true,
            "--strict" => strict = true,
            "--help" | "-h" => usage(),
            "--timeout" => {
                timeout = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("error: --timeout needs a number");
                        std::process::exit(2);
                    });
            }
            "--config" => {
                let p = it.next().unwrap_or_else(|| {
                    eprintln!("error: --config needs a path");
                    std::process::exit(2);
                });
                extra.push(p.clone());
            }
            other => {
                eprintln!("error: unknown option '{other}'");
                usage();
            }
        }
    }

    let servers = discover::discover(&extra);
    if servers.is_empty() {
        println!("No MCP servers found in known config locations.");
        return;
    }

    let results: Vec<model::AuditResult> = servers
        .iter()
        .map(|s| {
            let static_findings = analyze::analyze_static(s);
            if !do_probe || s.transport != "stdio" {
                return analyze::finalize(s, false, None, Vec::new(), static_findings);
            }
            match probe::probe(s, Duration::from_secs(timeout)) {
                Ok(tools) => {
                    let mut f = static_findings;
                    f.extend(analyze::analyze_tools(&tools));
                    analyze::finalize(s, true, None, tools, f)
                }
                Err(e) => {
                    let mut f = static_findings;
                    f.push(model::Finding {
                        id: "PROBE_FAILED".into(),
                        severity: model::Severity::Medium,
                        message: "Server could not be probed; it may be broken, slow, or refuse to start".into(),
                        evidence: None,
                    });
                    analyze::finalize(s, true, Some(e), Vec::new(), f)
                }
            }
        })
        .collect();

    if json {
        report::print_json(&results);
    } else {
        report::print_text(&results);
    }

    if strict {
        let fails = results.iter().filter(|r| matches!(r.grade, 'D' | 'F')).count();
        if fails > 0 {
            std::process::exit(1);
        }
    }
}
