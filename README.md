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

Config locations auto-discovered: `~/.claude.json`, Claude Desktop (macOS/Linux), `~/.cursor/mcp.json`, Windsurf, VS Code, Gemini CLI. Anything parseable with `mcpServers` / `servers` keys works with `--config`.

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
