mod analyze;
mod baseline;
mod discover;
mod model;
mod probe;
mod report;

use std::time::Duration;

fn usage(code: i32) -> ! {
    eprintln!(
        "mcp-audit — scan and rate the trustworthiness of your MCP servers\n\n\
USAGE:\n  \
mcp-audit [options]\n\n\
OPTIONS:\n  \
  --probe               Launch each stdio server and inspect its exposed tools (default: static only)\n  \
  --json                Output a JSON report\n  \
  --strict              Exit non-zero if any server grades D or F\n  \
  --fail-under <score>  Exit non-zero if any server scores below <score>\n  \
  --only <name>         Audit only servers whose name matches (repeatable)\n  \
  --save-baseline <f>   Write a trust baseline snapshot to file <f>\n  \
  --baseline <f>        Compare against a baseline; flag silent tool/config drift\n  \
  --timeout <secs>      Probe timeout in seconds (default: 10)\n  \
  --config <path>       Also scan an explicit MCP config file (repeatable)\n  \
  --help                Show this help\n\n\
TYPICAL WORKFLOW:\n  \
  mcp-audit --probe --save-baseline .mcp-audit-baseline.json\n  \
  mcp-audit --probe --baseline .mcp-audit-baseline.json --strict   # e.g. in CI\n"
    );
    std::process::exit(code);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut do_probe = false;
    let mut json = false;
    let mut strict = false;
    let mut fail_under: Option<u32> = None;
    let mut timeout = 10;
    let mut extra: Vec<String> = Vec::new();
    let mut only: Vec<String> = Vec::new();
    let mut save_baseline: Option<String> = None;
    let mut baseline_path: Option<String> = None;

    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        let mut val = |flag: &str| -> String {
            it.next()
                .cloned()
                .unwrap_or_else(|| {
                    eprintln!("error: {flag} needs a value");
                    std::process::exit(2);
                })
        };
        match a.as_str() {
            "--probe" => do_probe = true,
            "--json" => json = true,
            "--strict" => strict = true,
            "--help" | "-h" => usage(0),
            "--timeout" => timeout = val("--timeout").parse().unwrap_or_else(|_| {
                eprintln!("error: --timeout needs a number");
                std::process::exit(2);
            }),
            "--fail-under" => fail_under = Some(val("--fail-under").parse().unwrap_or_else(|_| {
                eprintln!("error: --fail-under needs a number 0-100");
                std::process::exit(2);
            })),
            "--only" => only.push(val("--only")),
            "--config" => extra.push(val("--config")),
            "--save-baseline" => save_baseline = Some(val("--save-baseline")),
            "--baseline" => baseline_path = Some(val("--baseline")),
            other => {
                eprintln!("error: unknown option '{other}'");
                usage(2);
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
        .filter(|s| only.is_empty() || only.iter().any(|n| s.name.contains(n.as_str())))
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

    let mut results = results;

    // Baseline drift detection
    let mut removed_servers: Vec<String> = Vec::new();
    if let Some(bp) = &baseline_path {
        match baseline::load(bp) {
            Ok(b) => {
                let (drift, removed) = baseline::diff(&b, &results);
                removed_servers = removed;
                for (server_name, finding) in drift {
                    if let Some(r) = results.iter_mut().find(|r| r.server.name == server_name) {
                        r.findings.push(finding);
                    }
                }
                // re-score with drift findings included
                for r in results.iter_mut() {
                    *r = analyze::finalize(&r.server.clone(), r.probed, r.error.clone(), r.tools.clone(), r.findings.clone());
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    }

    if let Some(bp) = &save_baseline {
        if let Err(e) = baseline::save(bp, &results) {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
        if !json {
            println!("Baseline saved to {bp}\n");
        }
    }

    if json {
        report::print_json(&results);
    } else {
        report::print_text(&results, &removed_servers);
    }

    let mut fail = false;
    if strict {
        fail |= results.iter().any(|r| matches!(r.grade, 'D' | 'F'));
    }
    if let Some(min) = fail_under {
        fail |= results.iter().any(|r| r.score < min);
    }
    if baseline_path.is_some() && !removed_servers.is_empty() {
        // a baselined server disappearing entirely is suspicious too
        fail = true;
    }
    if fail {
        std::process::exit(1);
    }
}
