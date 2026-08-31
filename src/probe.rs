use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::model::{ServerConfig, ToolInfo};

pub struct ProbeOutcome {
    pub tools: Vec<ToolInfo>,
    pub error: Option<String>,
}

const MAX_LINE: usize = 1 << 20; // 1 MiB per JSON-RPC line
const MAX_LINES: usize = 4096;

/// Read one line, bounded: lines longer than MAX_LINE are truncated (the
/// remainder is discarded up to the newline).
fn read_line_capped<R: BufRead>(r: &mut R) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut skipping = false;
    loop {
        let (found_nl, consumed, chunk) = {
            let avail = match r.fill_buf() {
                Ok(a) => a,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if avail.is_empty() {
                (false, 0usize, None)
            } else {
                match avail.iter().position(|&b| b == b'\n') {
                    Some(i) => (true, i + 1, Some(avail[..i].to_vec())),
                    None => (false, avail.len(), Some(avail.to_vec())),
                }
            }
        };
        if consumed > 0 {
            r.consume(consumed);
        }
        if let Some(c) = chunk {
            if !skipping && buf.len() < MAX_LINE {
                let take = (MAX_LINE - buf.len()).min(c.len());
                buf.extend_from_slice(&c[..take]);
                if take < c.len() {
                    skipping = true;
                }
            }
        }
        if found_nl {
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if consumed == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
            };
        }
    }
}

/// Minimal MCP JSON-RPC client over stdio: initialize -> tools/list.
/// Always reaps the child process, even on timeout or error.
pub fn probe(s: &ServerConfig, timeout: Duration) -> ProbeOutcome {
    let outcome = run_probe(s, timeout);
    outcome
}

fn run_probe(s: &ServerConfig, timeout: Duration) -> ProbeOutcome {
    let cmd = match &s.command {
        Some(c) => c.clone(),
        None => {
            return ProbeOutcome { tools: vec![], error: Some("no command".into()) };
        }
    };
    let mut cmd_builder = Command::new(&cmd);
    cmd_builder
        .args(&s.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in &s.env {
        cmd_builder.env(k, v);
    }
    let mut child = match cmd_builder.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ProbeOutcome { tools: vec![], error: Some(format!("failed to launch '{cmd}': {e}")) };
        }
    };
    let mut stdin = match child.stdin.take() {
        Some(x) => x,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return ProbeOutcome { tools: vec![], error: Some("no stdin".into()) };
        }
    };
    let stdout = child.stdout.take();

    let (tx, rx) = mpsc::channel::<(Vec<ToolInfo>, Option<String>)>();
    let handle = std::thread::spawn(move || {
        let mut tools = Vec::new();
        let mut error: Option<String> = None;
        let mut saw_handshake = false;
        if let Some(stdout) = stdout {
            let mut reader = BufReader::new(stdout);
            let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-audit","version":"0.1.0"}}}"#;
            let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
            let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
            if stdin.write_all(init.as_bytes()).and_then(|_| stdin.write_all(b"\n")).is_err() {
                let _ = tx.send((tools, Some("could not write to server stdin".into())));
                return;
            }
            let _ = stdin.flush();

            'outer: for _ in 0..MAX_LINES {
                let line = match read_line_capped(&mut reader) {
                    Ok(Some(l)) => l,
                    Ok(None) => break, // EOF
                    Err(_) => break,
                };
                if line.trim().is_empty() {
                    continue;
                }
                let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(_) => continue, // tolerate non-JSON noise
                };
                let id = v.get("id").and_then(|i| i.as_u64());
                match id {
                    Some(1) => {
                        saw_handshake = true;
                        let _ = stdin
                            .write_all(initialized.as_bytes())
                            .and_then(|_| stdin.write_all(b"\n"))
                            .and_then(|_| stdin.write_all(list.as_bytes()))
                            .and_then(|_| stdin.write_all(b"\n"));
                        let _ = stdin.flush();
                    }
                    Some(2) => {
                        if let Some(err_obj) = v.get("error") {
                            error = Some(format!(
                                "server returned JSON-RPC error to tools/list: {err_obj}"
                            ));
                        } else if let Some(items) = v.pointer("/result/tools").and_then(|t| t.as_array()) {
                            for it in items {
                                tools.push(ToolInfo {
                                    name: it.get("name").and_then(|n| n.as_str()).unwrap_or("?").to_string(),
                                    description: it.get("description").and_then(|d| d.as_str()).map(|x| x.to_string()),
                                });
                            }
                        }
                        break 'outer;
                    }
                    _ => continue,
                }
            }
            if error.is_none() && saw_handshake {
                // we asked for tools/list but never saw id=2
                error = Some("server closed output before answering tools/list".into());
            } else if error.is_none() && !saw_handshake {
                error = Some("server never responded to MCP initialize handshake".into());
            }
        }
        let _ = tx.send((tools, error));
    });

    let result = match rx.recv_timeout(timeout) {
        Ok((tools, error)) => ProbeOutcome { tools, error },
        Err(_) => ProbeOutcome {
            tools: vec![],
            error: Some(format!(
                "probe timed out after {}s (server may be slow to start — try --timeout)",
                timeout.as_secs()
            )),
        },
    };

    // Always reap the child, on every path.
    let _ = child.kill();
    let _ = child.wait();
    let _ = handle.join();
    result
}
