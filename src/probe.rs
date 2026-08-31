use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::model::{ServerConfig, ToolInfo};

/// Minimal MCP JSON-RPC client over stdio: initialize -> tools/list.
pub fn probe(s: &ServerConfig, timeout: Duration) -> Result<Vec<ToolInfo>, String> {
    let cmd = s.command.as_deref().ok_or("no command")?;
    let mut child = Command::new(cmd)
        .args(&s.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to launch '{cmd}': {e}"))?;

    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;

    let (tx, rx) = mpsc::channel::<Vec<ToolInfo>>();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        // initialize
        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-audit","version":"0.1.0"}}}"#;
        let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        if stdin.write_all(init.as_bytes()).and_then(|_| stdin.write_all(b"\n")).is_err() {
            let _ = tx.send(Vec::new());
            return;
        }
        let _ = stdin.flush();
        // collect lines until we see response id 2 (or run out)
        let mut tools = Vec::new();
        for _ in 0..64 {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("id").and_then(|i| i.as_u64()) == Some(2) {
                if let Some(items) = v.pointer("/result/tools").and_then(|t| t.as_array()) {
                    for it in items {
                        tools.push(ToolInfo {
                            name: it.get("name").and_then(|n| n.as_str()).unwrap_or("?").to_string(),
                            description: it.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                        });
                    }
                }
                break;
            }
            if v.get("id").and_then(|i| i.as_u64()) == Some(1) {
                let _ = stdin.write_all(initialized.as_bytes()).and_then(|_| stdin.write_all(b"\n")).and_then(|_| stdin.write_all(list.as_bytes())).and_then(|_| stdin.write_all(b"\n"));
                let _ = stdin.flush();
            }
        }
        let _ = child.kill();
        let _ = tx.send(tools);
    });

    match rx.recv_timeout(timeout) {
        Ok(tools) => {
            let _ = handle.join();
            Ok(tools)
        }
        Err(_) => Err(format!("probe timed out after {}s (server may be slow to start — try --timeout)", timeout.as_secs())),
    }
}
