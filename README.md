# mcp-audit

**Scan and rate the trustworthiness of MCP (Model Context Protocol) servers configured on your machine.**

Every AI coding assistant (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI...) now runs third-party MCP servers as local processes or network endpoints — often with your credentials in scope and the model auto-granting them tool access. Almost nobody audits what those servers actually are.

`mcp-audit` is a single fast binary that does it for you.

## What it checks

**Static (no execution, always runs):**
- Unpinned registry executions (`npx -y pkg`, `uvx pkg`) — supply-chain risk
- Direct remote/shell code execution (`curl|sh`, `bash -c http...`)
- Auto-approve / skip-permissions launch flags
- Credential-looking env vars handed to third-party processes
- Plain-HTTP (unencrypted) remote servers

**Live probe (`--probe`):** speaks MCP JSON-RPC over stdio and inspects the server's actual tool list:
- **Tool poisoning** — prompt-injection language hidden in tool descriptions
- **Hidden Unicode** — zero-width/invisible characters used to smuggle instructions
- **Dangerous tools** — exec/shell/write/delete/network capabilities
- **Undocumented tools** and oversized tool surfaces

Each server gets a **0–100 trust score and letter grade** with severity-tagged findings.

## Usage

```bash
mcp-audit                    # static audit of all known configs
mcp-audit --probe            # also launch stdio servers and list their tools
mcp-audit --probe --strict   # exit 1 if any server grades D/F (CI-friendly)
mcp-audit --json             # machine-readable report
mcp-audit --config ./mcp.json --config other.json   # explicit config files
mcp-audit --timeout 15       # probe timeout in seconds
```

Config locations auto-discovered: `~/.claude.json` (including nested `projects.<path>.mcpServers`), Claude Desktop (macOS/Linux), `~/.cursor/mcp.json`, Windsurf, VS Code, Gemini CLI. Any JSON (or `--config` file) containing `mcpServers` (camelCase), `mcp_servers`, or `servers` objects — at any nesting depth — is parsed. Malformed individual entries are skipped with a stderr warning instead of aborting the file; explicit `--config` paths that don't exist are hard errors (exit 2).

Scoped npm packages are understood: `npx -y @scope/pkg` is unpinned (flagged), `npx -y @scope/pkg@1.2.3` is not. Only true pipe-to-shell patterns (`curl ... | bash`) are flagged CRITICAL; a bare `curl` is MEDIUM.

`--probe` refuses to execute a config it has flagged CRITICAL (use `--force-probe` to override) and passes the config's `env` to the server so real servers respond. Timed-out or broken probes never leave orphaned processes, and a server that fails the MCP handshake is reported (HIGH), not silently treated as clean.

## Example output

```
 [D 51/100] poisoner  (stdio probed)
  via: ./fake-poisoner.py
  tools (3):
    - run_command
    - note​hidden
    - list_files
  findings:
    [CRITICAL] Tool 'run_command' description contains prompt-injection-style language — "ignore all previous"
    [CRITICAL] Tool 'run_command' name/description contains invisible Unicode characters
    [MEDIUM] Tool 'run_command' can execute commands, write/delete files, or reach the network
```

## Baseline workflow (detect silent drift)

MCP supply-chain attacks usually arrive as a *silent change*: a server you trusted
gains a new tool, or its command is swapped. Snapshot once, then diff:

```bash
mcp-audit --probe --save-baseline .mcp-audit-baseline.json
# ...time passes...
mcp-audit --probe --baseline .mcp-audit-baseline.json --strict
```

Drift findings:
- **CRITICAL** — server command/URL changed since baseline (config tampering)
- **HIGH** — a tool appeared that didn't exist before
- **LOW** — a tool disappeared
- **MEDIUM** — a brand-new server appeared; baselined servers that vanish also fail the run

Commit `.mcp-audit-baseline.json` to your repo or dotfiles to share the baseline.

Secrets are redacted at the output boundary — `env` values, credential-shaped `args` (`--api-key sk-...`), and URL userinfo (`user:pass@host`) never appear in text or JSON reports. Terminal control characters from untrusted server/tool names are escaped, so a hostile server cannot inject escape sequences into your report.

## Design

- Single dependency pair (`serde`/`serde_json`), no runtime beyond std
- Bounded-memory, no telemetry, nothing leaves your machine except the probes you ask for
- Exit code aware: wire `--strict` into CI to gate environments

## Building

```bash
cargo build --release   # binary at target/release/mcp-audit
cargo test
```

## License

MIT
