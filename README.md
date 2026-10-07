# mcpscope

An MCP server runs on your machine with your privileges and feeds tools straight into your AI agent. A server that's typosquatted, leaking a key, injecting code through an env var, or reachable by anyone on the internet is a problem you usually can't see, because it's buried in a JSON config you set up once and forgot — or in a config a repo planted for you. mcpscope reads the MCP servers configured across your host apps — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Roo, LM Studio, Gemini/Copilot CLI, Kiro, Codex, Zed — and the project-level configs a repo ships, and audits them.

It's offline. It never runs your servers and never phones home: it reads config files off disk, checks them against a set of rules, and prints what's wrong. Nothing about your setup leaves your machine.

```
$ mcpscope ./some-repo          # audit a repo's MCP configs before you trust it

  mcpscope 0.1.0  —  MCP server config audit (offline)

  Scanned:  project (3)  —  3 servers
  Findings:  2 high, 1 medium, 0 low

  HIGH    docs-helper (project)  Code-injection via NODE_OPTIONS
  HIGH    leaky (project)        Plaintext secret in config
  MEDIUM  fetcher (project)      Unpinned package install
```

## Why offline matters here

A tool that audits your secrets and setup shouldn't ship them to a cloud API to do it. mcpscope is a single Go binary that runs entirely locally — no account, no telemetry, no network calls — and it never launches a server to read it. Snyk's MCP scan, by contrast, needs an account, has no offline mode, and executes your stdio servers to harvest their tool descriptions. Offline config linting isn't unique any more — other local scanners read `.mcp.json` and its siblings too. What none of them checks is the **`env` block**: the variables a config sets to make the server load attacker code before it does anything (the CVE-2026-44995 shape). mcpscope leans on that, and on the **project-level configs a repo plants** — a repo's `.gemini/settings.json` loads unprompted because Gemini CLI ships with Trusted Folders off by default, and headless `claude -p` / the Agent SDK load project servers without asking. The scan fails loud instead of green when it can't read a file.

## Install

```bash
go install github.com/NotChaosuu/mcpscope/cmd/mcpscope@latest
```

Go 1.22+. One dependency — `BurntSushi/toml` (pure Go, no network) — for parsing Codex's `config.toml`.

## Usage

```bash
mcpscope                       # discover every host's config and audit all of them
mcpscope ./some-repo           # audit a repo's project-level MCP configs
mcpscope ./path/to/mcp.json    # audit one specific config file
mcpscope --json | jq           # machine-readable (findings is always an array)
mcpscope --exit-code --min-severity high   # CI gate
```

With no argument it walks the known config locations for each host app. Point it at a directory to audit that repo's project-level configs (`.mcp.json`, `.cursor/mcp.json`, …) before you open it in a host that would load them, or at a file to audit that one directly.

**On failure it stays loud.** A config it can't read or interpret never reads as clean: a `WARNING: N config(s) could not be read — INCOMPLETE` goes to stderr, `--json` carries `"complete": false`, and `--exit-code` returns **2** for an incomplete scan versus **1** for real findings. That covers invalid JSON or TOML, a servers block of the wrong shape, and a dedicated MCP file with no recognizable block. An odd-typed field in one server is tolerated (it's ignored) without dropping the rest of the file; a wrapper-less `.mcp.json` — the bare form VS Code and Copilot CLI accept — is read; a Codex config's own `[projects."…"]` / `[plugins."…"]` tables are ignored, not misread as an error; and a *general settings file* that simply has no MCP section (a Zed or Gemini `settings.json`, a `~/.claude.json` with only preferences) is a clean empty scan, not a false alarm.

## What it checks

**Unpinned installs.** A server launched with `npx`/`pnpx -y <package>`, `uvx`, `pnpm dlx`, `pipx run`, or a tagless `docker run` image, with no exact version, resolves fresh on every run — a typosquat, a registered hallucinated name, or a malicious new release gets pulled and executed. For npm-family runners only a full `major.minor.patch` counts as pinned: `@latest`, a dist-tag, and a range (`@1`, `@1.2`, `^1.2.0`) are all flagged.

**Env-var code injection.** `NODE_OPTIONS` carrying `-r`/`--require`/`--import`/`--loader`/`--experimental-loader` (normalized the way Node's own parser reads it, so quoted and `_`-spelled variants don't slip past), `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS`, `GIT_SSH_COMMAND`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONPATH` under a world-writable prefix, or an `envFile` — the ways a config makes the server run attacker code or drop TLS checks before it does anything (the CVE-2026-44995 shape). Assignments smuggled through an `env VAR=… <cmd>` wrapper (past its `-u`/`-C`/`-S` options) are audited too. Package-source and LLM base-URL redirects (`NPM_CONFIG_REGISTRY`, `UV_INDEX_URL`, `ANTHROPIC_BASE_URL`, …) are reported at **low** — they're usually a corporate mirror or gateway, worth seeing but not a gate failure.

**Plaintext secrets.** Keys and tokens in cleartext — in a server's `env`, its args, its request `headers` (including a literal `Bearer <token>` with no vendor prefix), a URL query parameter, or a database connection string — real values, not `${VAR}` references or `*_KEY_HERE`-style placeholders, which it leaves alone. It knows the common shapes (OpenAI/Anthropic, Stripe, GitHub, GitLab, AWS, Slack incl. `xapp-`, Google, HuggingFace). A secret in a *disabled* server is still on disk, so it's still reported.

**Untrusted commands.** A server launched through an interpreter that runs a command string rather than a file — `bash -c` / `-lc`, `powershell -Command` / `-ec` / `-EncodedCommand` / a bare string, `node -e` / `--eval=` / `-pe`, `python -c` / `-Ic`, `ruby`/`perl -e`, including behind a `wsl`/`env` prefix — or from a binary in a temp/downloads directory. The documented `cmd /c npx …` Windows wrapper is unwrapped and its *real* command audited (its `/d /s /q` switches and glued `/c` are handled): a benign `cmd /c npx` is pin-checked, not flagged, but `cmd /d /c powershell -ec …` is flagged on the inner shell. A flag that belongs to the launched *script* rather than the interpreter (`node server.js -p 3000`) is not mistaken for an eval flag.

**Startup helper commands.** A `headersHelper` (Claude Code) or `http_headers_helper` (Codex) runs a local command at connection time to mint auth headers — real code execution even on a `url`-only server. mcpscope reads it on both the JSON and TOML paths and grades it like any launched command: an inline shell, a temp/downloads path, or an unpinned package runner is high; a plain local binary (the documented Kerberos/SSO use) is medium.

**Insecure and exposed remotes.** Remotes over plain `http://` (the token travels in the clear), and URLs at bare IPs, `0.0.0.0`, or the AI-service ports botnets hunt (Ollama 11434, ComfyUI 8188, n8n 5678, Gradio 7860). Loopback (`localhost`, `127.0.0.0/8`, `::1`) is exempt from both — it never leaves the machine, and it's where local tools like Figma and Playwright run. An all-interfaces bind (`0.0.0.0`) and `host.docker.internal` don't get the plaintext-HTTP finding (nothing travels the wire in the clear) but `0.0.0.0` is still reported as exposed, since it's reachable.

**Auto-approved tools.** `autoApprove` (Cline), `alwaysAllow` (Roo), `trust: true` (Gemini CLI), or a Codex `approval_mode`/`default_tools_approval_mode` of `approve` (the mode that skips the prompt for every call — not `auto`, which still prompts for risky tools) — anything that runs a server's tools with no confirmation prompt, so a poisoned or rug-pulled tool executes silently.

**Config that hides a server.** A planted config can try to slip a payload past an auditor with a key the *host* ignores. mcpscope reads a server's fields by exact case (so a `"Command":"npx"` can't shadow the real `"command":"bash"`), audits a `command` even when a `url` sits beside it, and only skips a `disabled`/`enabled:false` server on the few hosts that actually honor the field (Cline, Roo, Kiro, Codex) — everywhere else, and in any untrusted repo config, it's still audited.

## The safety stance

mcpscope never spawns your MCP servers. That matters: launching a stdio MCP server *is* running its `command` as a subprocess, so a malicious server executes code before it answers a single request. Any tool that enumerates servers by starting them is running untrusted code to check whether it's trustworthy. mcpscope stays static — it reads the config, never the running process.

## Limits and what's next

- v0.1 audits the config layer. The deeper checks — scanning a server's live tool descriptions for prompt-injection / tool-poisoning, and rug-pull detection (snapshotting tool definitions and diffing them over time) — require connecting to the servers, so they'll land behind an explicit opt-in `--live` flag (sandboxed) in a later version rather than being on by default.
- Continue.dev's config is YAML rather than JSON and isn't parsed yet.
- Known gaps a config could be written to exploit (none seen in the real configs tested): a few non-canonical launcher spellings (`node -C`, `env --split-string=`, `wsl --shell-type … bash -c`, `cmd /c start …`), the docker/runner flag tables, some secret-rule edges, Codex `bearer_token`/`env_http_headers`, and a `mcp_servers` block of the wrong TOML *shape* (a non-table) reading as a clean empty scan where the JSON path fails loud.
- It flags config-level risk, not runtime behavior — a clean report means nothing wrong on these axes, not that a server is safe.

## License

MIT

## Author

Chaosuu — t.me/chaosuudev. More tools at github.com/NotChaosuu.
