package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/NotChaosuu/mcpscope/pkg/model"
)

type Host struct {
	App    string
	Path   string
	Key    string
	Format string // "" (JSON) or "toml"
	// Settings marks a general settings file (Zed, Gemini, ~/.claude.json, Claude
	// Desktop) that legitimately has no MCP section — there, a missing block is 0
	// servers, not an unreadable file. A dedicated MCP file still fails closed.
	Settings bool
}

func candidates() []Host {
	cfg, _ := os.UserConfigDir()
	home, _ := os.UserHomeDir()
	j := filepath.Join

	hosts := []Host{
		{App: "Claude Desktop", Path: j(cfg, "Claude", "claude_desktop_config.json"), Key: "mcpServers", Settings: true},
		{App: "Claude Code", Path: j(home, ".claude.json"), Key: "mcpServers", Settings: true}, // + per-project, see Parse
		{App: "Cursor", Path: j(home, ".cursor", "mcp.json"), Key: "mcpServers"},
		{App: "Windsurf", Path: j(home, ".codeium", "windsurf", "mcp_config.json"), Key: "mcpServers"},
		{App: "VS Code", Path: j(cfg, "Code", "User", "mcp.json"), Key: "servers"},
		{App: "VS Code Insiders", Path: j(cfg, "Code - Insiders", "User", "mcp.json"), Key: "servers"},
		{App: "Cline", Path: j(cfg, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), Key: "mcpServers"},
		{App: "Roo Code", Path: j(cfg, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), Key: "mcpServers"},
		{App: "LM Studio", Path: j(home, ".lmstudio", "mcp.json"), Key: "mcpServers"},
		{App: "Gemini CLI", Path: j(home, ".gemini", "settings.json"), Key: "mcpServers", Settings: true},
		{App: "Copilot CLI", Path: j(home, ".copilot", "mcp-config.json"), Key: "mcpServers"},
		{App: "Kiro", Path: j(home, ".kiro", "settings", "mcp.json"), Key: "mcpServers"},
		{App: "Codex", Path: j(home, ".codex", "config.toml"), Format: "toml"},
	}

	// Zed reads ~/.config/zed on macOS and Linux; Go's UserConfigDir is
	// ~/Library/Application Support on macOS, which is wrong for Zed.
	zed := j(cfg, "zed", "settings.json")
	if runtime.GOOS == "darwin" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = j(home, ".config")
		}
		zed = j(base, "zed", "settings.json")
	}
	hosts = append(hosts, Host{App: "Zed", Path: zed, Key: "context_servers", Settings: true})

	// Some Claude Desktop MSIX builds read the config from the package cache while
	// "Edit Config" opens %APPDATA%; check both.
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			hosts = append(hosts, Host{App: "Claude Desktop (MSIX)",
				Path: j(la, "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"),
				Key:  "mcpServers"})
		}
	}
	return hosts
}

func KnownHosts() []Host {
	var out []Host
	for _, h := range candidates() {
		if info, err := os.Stat(h.Path); err == nil && !info.IsDir() {
			out = append(out, h)
		}
	}
	return out
}

// projectConfigs are the per-repo MCP config locations an attacker plants — the
// files behind the 2025–26 "MCPoison" and Claude Code trust-dialog CVEs.
var projectConfigs = []Host{
	{App: "project", Path: ".mcp.json", Key: "mcpServers"},
	{App: "project", Path: filepath.Join(".cursor", "mcp.json"), Key: "mcpServers"},
	{App: "project", Path: filepath.Join(".vscode", "mcp.json"), Key: "servers"},
	{App: "project", Path: filepath.Join(".github", "mcp.json"), Key: "mcpServers"}, // Copilot CLI
	{App: "project", Path: filepath.Join(".amazonq", "mcp.json"), Key: "mcpServers"},
	{App: "project", Path: filepath.Join(".roo", "mcp.json"), Key: "mcpServers"},
	{App: "project", Path: filepath.Join(".kiro", "settings", "mcp.json"), Key: "mcpServers"},
	{App: "project", Path: filepath.Join(".gemini", "settings.json"), Key: "mcpServers", Settings: true},
	{App: "project", Path: filepath.Join(".zed", "settings.json"), Key: "context_servers", Settings: true},
	{App: "project", Path: filepath.Join(".codex", "config.toml"), Format: "toml"},
}

// ProjectHosts returns the project-level configs present under dir, so a repo can
// be audited before it's trusted.
func ProjectHosts(dir string) []Host {
	var out []Host
	for _, h := range projectConfigs {
		p := filepath.Join(dir, h.Path)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			out = append(out, Host{App: h.App, Path: p, Key: h.Key, Format: h.Format, Settings: h.Settings})
		}
	}
	return out
}

// Every field is a lenient type: an unexpected JSON shape in one field is ignored
// rather than failing the server. That way one odd value never silently drops a
// whole file (a genuinely broken servers block is still surfaced as an error).
type rawServer struct {
	Command     json.RawMessage    `json:"command"` // string, or Zed's legacy {path,args,env}
	Args        flexList           `json:"args"`
	Env         map[string]flexVal `json:"env"`
	EnvFile     string             `json:"envFile"`
	URL         string             `json:"url"`
	ServerURL   string             `json:"serverUrl"`
	HTTPUrl     string             `json:"httpUrl"` // Gemini streamable-HTTP endpoint
	Type        string             `json:"type"`
	Headers     map[string]flexVal `json:"headers"`
	Disabled    flexBool           `json:"disabled"`
	AutoApprove flexList           `json:"autoApprove"`
	AlwaysAllow flexList           `json:"alwaysAllow"` // Roo Code's spelling
	Trust       flexBool           `json:"trust"`       // Gemini CLI
	HelperCmd   []string           `json:"-"`           // Codex http_headers_helper (a command run at startup)
}

// flexVal accepts a JSON string, number, or bool and stores it as a string, so
// one odd value (a numeric env like "PORT": 3000) never fails the whole file.
type flexVal struct{ s string }

func (f *flexVal) UnmarshalJSON(b []byte) error {
	b = trimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		return json.Unmarshal(b, &f.s)
	}
	f.s = string(b) // number/bool/other -> its literal text
	return nil
}

// flexList accepts a JSON array (of any scalars), a bare string, or anything else
// (which it ignores) — never an error.
type flexList struct{ v []string }

func (f *flexList) UnmarshalJSON(b []byte) error {
	b = trimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var vs []flexVal
		if json.Unmarshal(b, &vs) == nil {
			f.v = flatten(vs)
		}
		return nil
	}
	if b[0] == '"' {
		var s string
		if json.Unmarshal(b, &s) == nil {
			f.v = []string{s}
		}
	}
	return nil
}

// flexBool accepts a JSON bool, "true"/"false", or 1/0 — never an error.
type flexBool struct{ v bool }

func (f *flexBool) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	f.v = s == "true" || s == "1"
	return nil
}

func flatten(vs []flexVal) []string {
	if vs == nil {
		return nil
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.s
	}
	return out
}

func flattenMap(m map[string]flexVal) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v.s
	}
	return out
}

// parseCommand handles both the plain `"command": "npx"` form and Zed's legacy
// `"command": {"path": "npx", "args": [...], "env": {...}}` object.
func parseCommand(raw json.RawMessage) (cmd string, args []string, env map[string]string) {
	raw = trimSpace(raw)
	if len(raw) == 0 {
		return "", nil, nil
	}
	if raw[0] == '"' {
		_ = json.Unmarshal(raw, &cmd)
		return cmd, nil, nil
	}
	var o struct {
		Path    string             `json:"path"`
		Command string             `json:"command"`
		Args    []flexVal          `json:"args"`
		Env     map[string]flexVal `json:"env"`
	}
	_ = json.Unmarshal(raw, &o)
	cmd = o.Path
	if cmd == "" {
		cmd = o.Command
	}
	return cmd, flatten(o.Args), flattenMap(o.Env)
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func Parse(h Host) ([]model.Server, error) {
	data, err := os.ReadFile(h.Path)
	if err != nil {
		return nil, err
	}
	if h.Format == "toml" {
		return parseTOML(h, data)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONComments(data), &top); err != nil {
		return nil, err
	}
	out, err := serversFromBlock(top[h.Key], h)
	if err != nil {
		return nil, err
	}
	// Claude Code also nests per-project (local-scope) servers under
	// projects[path].mcpServers — walk them regardless of the top-level key, which
	// is often absent on a real ~/.claude.json.
	if h.App == "Claude Code" {
		out = append(out, claudeProjectServers(data, h.Path)...)
	}
	// Some hosts accept a config under a different (or no) wrapper key than the one
	// we expect (VS Code / Copilot CLI read a bare .mcp.json). If the expected key
	// was absent, try the other known keys, then the wrapper-less form.
	if len(out) == 0 && len(top[h.Key]) == 0 {
		fb, ferr := fallbackBlock(top, h)
		if ferr != nil {
			// A general settings file (Zed, Gemini, ~/.claude.json, Claude Desktop) with
			// no MCP section is a clean empty scan, not an unreadable file.
			if h.Settings {
				return out, nil
			}
			return nil, ferr
		}
		out = fb
	}
	return out, nil
}

func claudeProjectServers(data []byte, path string) []model.Server {
	// Decode projects as raw entries and read each one best-effort, so a single
	// non-object entry (a legacy string) can't drop every other project's servers.
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if json.Unmarshal(stripJSONComments(data), &doc) != nil {
		return nil
	}
	var out []model.Server
	for p, raw := range doc.Projects {
		var proj struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		if json.Unmarshal(raw, &proj) != nil {
			continue // a non-object project entry
		}
		ph := Host{App: "Claude Code", Path: path + " [" + p + "]", Key: "mcpServers"}
		sv, _ := serversFromBlock(proj.MCPServers, ph)
		out = append(out, sv...)
	}
	return out
}

// wrapperKeys are the recognized top-level keys a host uses to hold its servers.
// OpenCode's `mcp` key is deliberately absent: its server shape (array command,
// `environment`) differs enough that reading it as one of these would misparse it
// and certify it clean, so an opencode.json fails closed instead.
var wrapperKeys = []string{"mcpServers", "servers", "context_servers"}

// fallbackBlock is reached when the expected wrapper key is absent. It tries the
// other known keys, then treats the whole document as a wrapper-less server map
// (VS Code and Copilot CLI accept a bare .mcp.json). It never returns nil,nil:
// a document with no interpretable servers is an error, so a repo whose config
// the tool couldn't read is never certified clean.
func fallbackBlock(top map[string]json.RawMessage, h Host) ([]model.Server, error) {
	for _, k := range wrapperKeys {
		if b, ok := top[k]; ok {
			return serversFromBlock(b, h)
		}
	}
	if looksLikeServerMap(top) {
		block, _ := json.Marshal(top)
		return serversFromBlock(block, h)
	}
	return nil, errNoServerBlock
}

var errNoServerBlock = &parseError{"no recognizable MCP server block (no mcpServers/servers/context_servers key, and the top level isn't a server map)"}

type parseError struct{ msg string }

func (e *parseError) Error() string { return e.msg }

// looksLikeServerMap reports whether a top-level object is itself a map of servers
// (wrapper-less): every member is an object carrying a command or url/serverUrl.
func looksLikeServerMap(top map[string]json.RawMessage) bool {
	if len(top) == 0 {
		return false
	}
	for _, v := range top {
		var probe struct {
			Command json.RawMessage `json:"command"`
			URL     string          `json:"url"`
			SrvURL  string          `json:"serverUrl"`
		}
		if json.Unmarshal(v, &probe) != nil {
			return false
		}
		if len(probe.Command) == 0 && probe.URL == "" && probe.SrvURL == "" {
			return false
		}
	}
	return true
}

// serversFromBlock decodes the servers map. A block that isn't a JSON object is a
// surfaced error (so the caller fails closed); a single malformed server is
// decoded best-effort and kept, never dropping its siblings.
func serversFromBlock(block json.RawMessage, h Host) ([]model.Server, error) {
	if len(block) == 0 {
		return nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(block, &raw); err != nil {
		return nil, err
	}
	out := make([]model.Server, 0, len(raw))
	for name, rsRaw := range raw {
		out = append(out, normalize(name, h, decodeRawServer(rsRaw)))
	}
	return out, nil
}

// decodeRawServer reads a server object by EXACT-case keys. Go's encoding/json
// folds case, so a struct decode lets a planted "Command":"npx" override the real
// "command":"bash" (the last match wins). Looking keys up in a raw map matches how
// the hosts (Cline/zod, Codex/Zed/serde, Gemini) actually read the file. A bad
// field is skipped, never dropping the server.
func decodeRawServer(rsRaw json.RawMessage) rawServer {
	var m map[string]json.RawMessage
	if json.Unmarshal(rsRaw, &m) != nil {
		return rawServer{}
	}
	var rs rawServer
	if v, ok := m["command"]; ok {
		rs.Command = v
	}
	get := func(key string, dst any) {
		if v, ok := m[key]; ok {
			_ = json.Unmarshal(v, dst)
		}
	}
	get("args", &rs.Args)
	get("env", &rs.Env)
	get("envFile", &rs.EnvFile)
	get("url", &rs.URL)
	get("serverUrl", &rs.ServerURL)
	get("httpUrl", &rs.HTTPUrl) // Gemini streamable-HTTP endpoint
	get("type", &rs.Type)
	get("headers", &rs.Headers)
	get("disabled", &rs.Disabled)
	get("autoApprove", &rs.AutoApprove)
	get("alwaysAllow", &rs.AlwaysAllow)
	get("trust", &rs.Trust)
	// headersHelper (Claude Code's analogue of Codex's http_headers_helper) runs a
	// local command at connection time, so even a url-only entry can execute code.
	// It's a string or an array of strings.
	if v, ok := m["headersHelper"]; ok {
		rs.HelperCmd = decodeStringOrList(v)
	}
	return rs
}

// decodeStringOrList reads a JSON value that may be a single string or an array of
// strings into a []string, so a helper command written either way is captured.
func decodeStringOrList(v json.RawMessage) []string {
	var list []string
	if json.Unmarshal(v, &list) == nil {
		return list
	}
	var s string
	if json.Unmarshal(v, &s) == nil && s != "" {
		return []string{s}
	}
	return nil
}

func ParseFile(path string) ([]model.Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h := Host{App: "file", Path: path}
	if strings.HasSuffix(strings.ToLower(path), ".toml") {
		return parseTOML(h, data)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONComments(data), &top); err != nil {
		return nil, err
	}
	for _, key := range wrapperKeys {
		if block, ok := top[key]; ok {
			h.Key = key
			return serversFromBlock(block, h)
		}
	}
	// No wrapper key: accept a bare server map, else fail closed rather than
	// certify a file we couldn't interpret as clean.
	return fallbackBlock(top, h)
}

const (
	maxTOMLBytes = 8 << 20 // a Codex config.toml is tiny; a huge one is an attack
	maxTOMLDepth = 100     // deeply nested inline tables make the parser OOM
)

// parseTOML reads the MCP servers from Codex's config.toml with a real TOML parser,
// so every valid spelling — escapes, multi-line and literal strings, quoted or
// inline tables, dotted keys — is read the way Codex itself reads it, and any
// invalid TOML is a surfaced error (the scan fails closed, never certifying a file
// it couldn't parse). It decodes into a generic map, not a struct, so a key is
// resolved by EXACT case the way Codex does — a planted "Command" can't shadow the
// real "command". Tables other than [mcp_servers…] are ignored, not rejected.
func parseTOML(h Host, data []byte) ([]model.Server, error) {
	if len(data) > maxTOMLBytes {
		return nil, &parseError{"TOML config too large to scan safely: " + h.Path}
	}
	if tomlNestingDepth(data) > maxTOMLDepth {
		return nil, &parseError{"TOML config nests inline tables too deeply: " + h.Path}
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, &parseError{"invalid TOML in " + h.Path + ": " + err.Error()}
	}
	servers, ok := doc["mcp_servers"].(map[string]any)
	if !ok {
		return nil, nil // no MCP section — a clean empty scan
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names) // TOML maps are unordered in Go; sort for stable output
	out := make([]model.Server, 0, len(names))
	for _, name := range names {
		st, _ := servers[name].(map[string]any)
		out = append(out, normalize(name, h, tomlMapToRaw(st)))
	}
	return out, nil
}

func tomlMapToRaw(st map[string]any) rawServer {
	var rs rawServer
	if v, ok := st["command"].(string); ok && v != "" {
		rs.Command = json.RawMessage(strconvQuote(v))
	}
	if v, ok := st["args"]; ok {
		rs.Args = flexList{v: anySliceToStrings(v)}
	}
	if v, ok := st["env"].(map[string]any); ok {
		rs.Env = anyMapToFlex(v)
	}
	if v, ok := st["url"].(string); ok {
		rs.URL = v
	}
	if v, ok := st["http_headers"].(map[string]any); ok {
		rs.Headers = anyMapToFlex(v)
	}
	if v, ok := st["enabled"].(bool); ok && !v {
		rs.Disabled = flexBool{v: true} // Codex honors enabled=false
	}
	if v, ok := st["default_tools_approval_mode"].(string); ok && isCodexApprove(v) {
		rs.AutoApprove.v = append(rs.AutoApprove.v, "default")
	}
	if tools, ok := st["tools"].(map[string]any); ok {
		for _, tv := range tools {
			if tm, ok := tv.(map[string]any); ok {
				if am, ok := tm["approval_mode"].(string); ok && isCodexApprove(am) {
					rs.AutoApprove.v = append(rs.AutoApprove.v, "approve")
				}
			}
		}
	}
	// http_headers_helper / headersHelper runs a local command at startup, so even a
	// url-only entry can be code execution — surface the command to the audit.
	for _, k := range []string{"http_headers_helper", "headersHelper"} {
		if hc := anySliceToStrings(st[k]); len(hc) > 0 {
			rs.HelperCmd = hc
		}
	}
	return rs
}

// tomlNestingDepth is the maximum unescaped { or [ nesting depth outside strings,
// used to reject a pathologically nested config before the parser allocates on it.
func tomlNestingDepth(data []byte) int {
	depth, max := 0, 0
	inBasic, inLiteral, esc := false, false, false
	for _, b := range data {
		switch {
		case esc:
			esc = false
		case inBasic && b == '\\':
			esc = true
		case inBasic:
			if b == '"' {
				inBasic = false
			}
		case inLiteral:
			if b == '\'' {
				inLiteral = false
			}
		case b == '"':
			inBasic = true
		case b == '\'':
			inLiteral = true
		case b == '{' || b == '[':
			depth++
			if depth > max {
				max = depth
			}
		case b == '}' || b == ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return max
}

func anySliceToStrings(v any) []string {
	s, ok := v.([]any)
	if !ok {
		if str, ok := v.(string); ok {
			return []string{str}
		}
		return nil
	}
	out := make([]string, 0, len(s))
	for _, e := range s {
		out = append(out, anyToString(e))
	}
	return out
}

// isCodexApprove is true only for "approve" — the one Codex mode that skips the
// prompt for every call. "auto" is the default and still prompts for risky tools,
// so it is not auto-approval.
func isCodexApprove(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "approve")
}

func anyMapToFlex(m map[string]any) map[string]flexVal {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]flexVal, len(m))
	for k, v := range m {
		out[k] = flexVal{s: anyToString(v)}
	}
	return out
}

func anyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func normalize(name string, h Host, rs rawServer) model.Server {
	cmd, cmdArgs, cmdEnv := parseCommand(rs.Command)

	args := append(cmdArgs, rs.Args.v...)
	env := flattenMap(rs.Env)
	for k, v := range cmdEnv {
		if env == nil {
			env = map[string]string{}
		}
		if _, ok := env[k]; !ok {
			env[k] = v
		}
	}
	auto := append(append([]string{}, rs.AutoApprove.v...), rs.AlwaysAllow.v...) // Roo's spelling counts too

	s := model.Server{
		Name:        name,
		Host:        h.App,
		ConfigPath:  h.Path,
		Args:        args,
		Env:         env,
		EnvFile:     rs.EnvFile,
		Headers:     flattenMap(rs.Headers),
		Disabled:    rs.Disabled.v,
		AutoApprove: auto,
		Trust:       rs.Trust.v,
		HelperCmd:   rs.HelperCmd,
	}
	// A command is always audited when present: most hosts launch it regardless of
	// a co-present url/type, so an entry with both command and url must not hide the
	// command behind the URL. The URL is still recorded for the secret and
	// remote checks.
	if cmd != "" {
		s.Command = cmd
		s.Transport = model.Stdio
	}
	// Gemini connects to httpUrl before url; audit that one so the endpoint the host
	// actually reaches isn't the one left unchecked.
	if url := firstNonEmpty(rs.HTTPUrl, rs.ServerURL, rs.URL); url != "" {
		s.URL = url
		if cmd == "" {
			s.Transport = transport(rs.Type, true)
		}
	}
	if s.Transport == "" {
		s.Transport = model.Unknown
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func transport(t string, remote bool) model.Transport {
	switch strings.ReplaceAll(strings.ToLower(t), "-", "") {
	case "stdio":
		return model.Stdio
	case "http", "streamablehttp":
		return model.HTTP
	case "sse":
		return model.SSE
	}
	if remote {
		return model.HTTP
	}
	return model.Unknown
}

// Some hosts (VS Code, Zed) accept JSONC — JSON with // and /* */ comments and
// trailing commas. Strip those so the config still parses as plain JSON.
func stripJSONComments(data []byte) []byte {
	var b strings.Builder
	s := string(data)
	inStr, inLine, inBlock := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inLine {
			if c == '\n' {
				inLine = false
				b.WriteByte(c)
			}
			continue
		}
		if inBlock {
			if c == '*' && i+1 < len(s) && s[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		}
		if inStr {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i++
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			b.WriteByte(c)
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			inLine = true
			i++
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			inBlock = true
			i++
		default:
			b.WriteByte(c)
		}
	}
	return []byte(stripTrailingCommas(b.String()))
}

// stripTrailingCommas is string-aware so it never touches a comma inside a string
// literal (e.g. an arg like "pkg, ]"). A comma is dropped only when the next
// non-space character is a closing brace or bracket.
func stripTrailingCommas(s string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i++
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
