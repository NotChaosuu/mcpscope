package audit

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/NotChaosuu/mcpscope/pkg/model"
)

func Audit(servers []model.Server) []model.Finding {
	var out []model.Finding
	for _, s := range servers {
		out = append(out, ServerFindings(s)...)
	}
	return out
}

// hostHonorsDisabled reports whether a host actually skips a server marked
// disabled. Only these do; everywhere else (and in an untrusted project config,
// where Host is "project") a disabled entry still launches, so it's still audited.
func hostHonorsDisabled(host string) bool {
	switch host {
	case "Cline", "Roo Code", "Kiro", "Codex":
		return true
	}
	return false
}

func ServerFindings(s model.Server) []model.Finding {
	var out []model.Finding
	add := func(rule string, sev model.Severity, title, detail string) {
		out = append(out, model.Finding{
			Server: s.Name, Host: s.Host, Rule: rule, Severity: sev, Title: title, Detail: detail,
		})
	}

	// A secret written to a config is exposed even if the server is disabled — the
	// bytes are on disk — so the secret scan runs regardless.
	out = append(out, secretFindings(s)...)
	// `disabled: true` only skips the rest for the few hosts that honor the field
	// (Cline, Roo, Kiro). Claude Code, VS Code, Cursor, Gemini, Codex and Zed have no
	// such field and launch the server anyway, so on those (and any untrusted repo
	// config) a disabled entry is still audited — otherwise one key hides a payload.
	if s.Disabled && hostHonorsDisabled(s.Host) {
		return out
	}

	if pkg, ok := unpinnedInstall(s); ok {
		runner, _ := effectiveInstall(s)
		add("unpinned-install", model.Medium, "Unpinned package install",
			"Launches "+baseCommand(runner)+" with an unpinned package ("+pkg+"). It's resolved fresh on every run, so a typosquat, a hallucinated name, or a malicious new version is pulled and executed automatically. Pin an exact version.")
	}

	if reason, ok := untrusted(s); ok {
		add("untrusted-command", model.Medium, "Server launched from an untrusted command", reason)
	}

	envInjection(s, add)

	if s.Remote() {
		cleaned := substituteURLTemplates(s.URL)
		// A URL whose host can't be determined — e.g. the whole thing is a ${VAR}
		// default — is left unclassified, so it can't produce a false alarm.
		if host := urlHost(cleaned); host != "" {
			// Plaintext HTTP only matters when traffic leaves the machine; a local bind
			// (loopback, 0.0.0.0, host.docker.internal) travels nowhere in the clear.
			if !hostIsLocal(host) && strings.HasPrefix(strings.ToLower(cleaned), "http://") {
				add("insecure-remote", model.High, "Remote server over plaintext HTTP",
					"The server URL uses http:// — traffic, including any auth token, is unencrypted. Use https://.")
			}
			// Exposure is about reachability, so an all-interfaces bind still counts even
			// though it's "local" for the HTTP rule; true loopback does not.
			if !isTrueLoopback(host) {
				if risk := riskyHost(cleaned); risk != "" {
					add("exposed-remote", model.Medium, "Remote server on an exposed/bare host",
						"The URL points at "+risk+", a bare IP, all-interfaces bind, or a known AI-service port hunted by botnets (Ollama 11434, ComfyUI 8188, n8n 5678, Gradio 7860).")
				}
			}
		}
	}

	if len(s.AutoApprove) > 0 {
		add("auto-approve", model.Medium, "Tools auto-approved",
			"This server auto-approves its tools, so they run with no confirmation prompt — a poisoned or rug-pulled tool would execute silently.")
	}
	if s.Trust {
		add("auto-approve", model.Medium, "All tool confirmation bypassed",
			"trust is set (Gemini CLI), so every tool on this server runs without a confirmation prompt.")
	}

	// A headers-helper command (Codex http_headers_helper / Claude Code headersHelper)
	// runs a local command at connection time, so even a url-only server executes code.
	// Take the severity from what the command actually is, not its mere presence: the
	// key exists for Kerberos/SSO header generation, so a plain local binary is MEDIUM,
	// while an inline-shell, temp-dir, or unpinned-package helper is graded like any
	// launched command. Reuse the same classifiers via a synthetic stdio server.
	if len(s.HelperCmd) > 0 {
		cmd, args := s.HelperCmd[0], s.HelperCmd[1:]
		// A string-form helper ("bash -c '…'") arrives as one token; split it so the
		// interpreter grammar can see the -c / -enc behind the base command.
		if len(s.HelperCmd) == 1 && strings.ContainsAny(cmd, " \t") {
			fields := strings.Fields(cmd)
			cmd, args = fields[0], fields[1:]
		}
		hs := model.Server{Transport: model.Stdio, Command: cmd, Args: args}
		joined := strings.Join(s.HelperCmd, " ")
		if reason, ok := untrusted(hs); ok {
			add("untrusted-command", model.High, "Server runs a dangerous helper command at startup",
				"The headers-helper runs `"+joined+"` at connection time. "+reason)
		} else {
			add("untrusted-command", model.Medium, "Server runs a helper command at startup",
				"The headers-helper runs `"+joined+"` locally before any request — code execution at connection time. Confirm it's the intended auth-header generator (Kerberos/SSO), not attacker-controlled.")
		}
		if pkg, ok := unpinnedInstall(hs); ok {
			add("unpinned-install", model.Medium, "Unpinned helper package",
				"The headers-helper resolves "+pkg+" fresh on every start (`"+joined+"`), so a typosquat or malicious new version runs at connection time. Pin an exact version.")
		}
	}

	return out
}

// ---- secrets -------------------------------------------------------------

func secretFindings(s model.Server) []model.Finding {
	var out []model.Finding
	seen := map[string]bool{}
	mk := func(where, kind string) {
		if seen[where] {
			return
		}
		seen[where] = true
		out = append(out, model.Finding{
			Server: s.Name, Host: s.Host, Rule: "plaintext-secret", Severity: model.High,
			Title:  "Plaintext secret in config",
			Detail: "A " + kind + " is stored in cleartext in " + where + ". Move it to a secret store or a ${VAR} reference.",
		})
	}
	for k, v := range s.Env {
		if kind, ok := secretInEnv(k, v); ok {
			mk("env ("+k+")", kind)
		}
	}
	for i, a := range s.Args {
		if kind, ok := scanSecret(a); ok {
			mk("a command argument", kind)
		}
		// A --header/-H "Name: value" arg (mcp-remote, curl-style) carries a header,
		// so apply the header rule to it.
		if (a == "--header" || a == "-H") && i+1 < len(s.Args) {
			if hk, hv, ok := strings.Cut(s.Args[i+1], ":"); ok {
				if kind, ok := scanHeaderSecret(strings.TrimSpace(hk), strings.TrimSpace(hv)); ok {
					mk("a --header argument", kind)
				}
			}
		}
	}
	for hk, hv := range s.Headers {
		if kind, ok := scanHeaderSecret(hk, hv); ok {
			mk("header ("+hk+")", kind)
		}
	}
	if s.URL != "" {
		if kind, ok := scanURLSecret(s.URL); ok {
			mk("the server URL", kind)
		}
	}
	return out
}

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"OpenAI/Anthropic-style key", regexp.MustCompile(`\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)},
	{"Stripe key", regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{50,}`)},
	{"AWS access key id", regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)},
	{"Slack token", regexp.MustCompile(`xox[baprsecd]-[A-Za-z0-9-]{10,}`)},
	{"Slack app token", regexp.MustCompile(`xapp-[0-9]-[A-Za-z0-9-]{10,}`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"HuggingFace token", regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`)},
	{"GitLab token", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
}

var secretKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|access[_-]?key|auth[_-]?token)`)

// Any URL scheme (including SQLAlchemy dialects like postgresql+psycopg2) with a
// user:password@ authority. The password is captured to test it for placeholders.
var connStringRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^:@/\s]*:([^@/\s]+)@`)

// Whole-token placeholder words for a connection-string password — matched as
// tokens so "here" doesn't hit inside "where"/"sphere".
var dsnPlaceholders = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pwd": true,
	"username": true, "user": true, "changeme": true, "example": true,
	"placeholder": true, "your_password": true, "secret": true, "redacted": true,
}

func vendorPattern(v string) (string, bool) {
	for _, p := range secretPatterns {
		if p.re.MatchString(v) {
			return p.name, true
		}
	}
	return "", false
}

// connString reports an embedded, non-placeholder password. It judges the password
// token itself, so a "sample"/"todo" database name elsewhere in the DSN — which
// would trip the value-wide example filter — doesn't hide a real credential.
func connString(v string) (string, bool) {
	if m := connStringRe.FindStringSubmatch(v); m != nil && !isDSNPlaceholderPassword(m[1]) {
		return "database connection string with an embedded password", true
	}
	return "", false
}

func isDSNPlaceholderPassword(pw string) bool {
	low := strings.ToLower(strings.Trim(pw, "<>{}[]"))
	if low == "" || dsnPlaceholders[low] {
		return true
	}
	return isEnvRef(pw) || strings.Contains(pw, "${") ||
		strings.Contains(low, "your") || strings.Contains(low, "example") ||
		strings.Contains(low, "placeholder") || strings.Contains(low, "xxxx")
}

// scanSecret checks a raw value. A ${VAR} reference or an obvious placeholder is
// never a secret, but a value that matches a real vendor format always is — even
// an all-caps one like an AWS key id — so the vendor match runs first.
func scanSecret(v string) (string, bool) {
	if isEnvRef(v) {
		return "", false
	}
	// Conn-strings judge their own password token, so they run before the value-wide
	// example filter that a "sample"/"todo" database name would otherwise trip.
	if name, ok := connString(v); ok {
		return name, true
	}
	if isExampleSecret(v) {
		return "", false
	}
	return vendorPattern(v)
}

var headerSecretName = regexp.MustCompile(`(?i)(authorization|x-api-key|api[_-]?key|[_-]?token|secret|apikey)`)

// scanHeaderSecret checks a request header. A vendor-shaped value is always a
// secret; otherwise an auth/key/token header carrying a literal credential (≥16
// chars, not a ${VAR} or placeholder) is one too — a bare "Bearer <hex>".
func scanHeaderSecret(name, value string) (string, bool) {
	if kind, ok := scanSecret(value); ok {
		return kind, true
	}
	if isEnvRef(value) || isPlaceholder(value) {
		return "", false
	}
	if !headerSecretName.MatchString(name) {
		return "", false
	}
	cred := strings.TrimSpace(value)
	for _, scheme := range []string{"Bearer ", "bearer ", "Basic ", "basic ", "token ", "Token "} {
		cred = strings.TrimPrefix(cred, scheme)
	}
	cred = strings.TrimSpace(cred)
	// Count runes, not bytes — a short CJK placeholder is well under 16 characters
	// even when it exceeds 16 bytes.
	if len([]rune(cred)) >= 16 && !isEnvRef(cred) && !isPlaceholder(cred) && !strings.Contains(cred, "${") {
		return "credential in a request header", true
	}
	return "", false
}

func secretInEnv(key, value string) (string, bool) {
	if isEnvRef(value) {
		return "", false
	}
	if name, ok := scanSecret(value); ok { // vendor formats + conn-strings
		return name, true
	}
	// Generic key-name rule: KEY=<value>. Here an ALL_CAPS_REF value is the name of
	// another secret, not the secret, so it's excluded; a real vendor value would
	// already have matched above.
	if secretKeyRe.MatchString(key) && len(strings.TrimSpace(value)) >= 8 &&
		!isPlaceholder(value) && !isAllCapsRef(value) {
		return "secret value", true
	}
	return "", false
}

func scanURLSecret(url string) (string, bool) {
	if name, ok := scanSecret(url); ok { // conn-string userinfo, or a token anywhere in it
		return name, true
	}
	if i := strings.IndexByte(url, '?'); i >= 0 {
		for _, kv := range strings.Split(url[i+1:], "&") {
			k, v, ok := strings.Cut(kv, "=")
			if ok && secretKeyRe.MatchString(k) && len(v) >= 8 &&
				!isEnvRef(v) && !isPlaceholder(v) && !strings.Contains(v, "${") {
				return "credential in a URL query parameter", true
			}
		}
	}
	return "", false
}

// isEnvRef is true for a value that isn't a literal secret but a reference to one:
// ${VAR}, $VAR, %VAR% (Windows), {env:VAR}/{input:VAR}, {{VAULT_KEY}}, or a 1Password
// op:// URI.
func isEnvRef(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "op://") {
		return true
	}
	if strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%") && len(v) > 2 {
		return true
	}
	if strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "{env:") || strings.HasPrefix(v, "{input:") {
		return true
	}
	return false
}

var placeholderWords = []string{"your", "example", "placeholder", "changeme", "xxxx", "<", "todo", "here", "****", "optional", "sample", "dummy", "redacted", "...",
	"您的", "你的", "请填写", "请输入", "替换", "示例", "填写"} // common CJK "your / please fill / replace / example"

// isExampleSecret is true for a value that spells out that it's a template —
// "your-token", "AKIA…EXAMPLE", "changeme". A real credential never contains one
// of these words, so this can gate even the vendor-format match without hiding a
// live key.
func isExampleSecret(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	for _, ph := range placeholderWords {
		if strings.Contains(low, ph) {
			return true
		}
	}
	return false
}

// isPlaceholder covers the ways a template writes "put your key here" — the
// biggest false-positive source for the generic key-name rule.
func isPlaceholder(v string) bool {
	return isExampleSecret(v)
}

// isAllCapsRef reports whether a value is an ALL_CAPS_IDENTIFIER naming another
// secret (API_KEY=COPILOT_MCP_TOKEN) rather than a secret itself. It requires an
// underscore, so real all-caps key formats (an AWS AKIA… id) are not mistaken for
// a reference.
func isAllCapsRef(v string) bool {
	v = strings.TrimSpace(v)
	if !strings.Contains(v, "_") {
		return false
	}
	hasLetter := false
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9' || r == '_':
		default:
			return false
		}
	}
	return hasLetter
}

// ---- installs ------------------------------------------------------------

// Per-runner flag tables. The two families differ: uv/pipx take -p as --python and
// pin on any exact version after @, while npx/bunx take -p as --package and need a
// full major.minor.patch. A spec flag names the package explicitly.
var npmSpecFlags = map[string]bool{"-p": true, "--package": true}
var npmValueFlags = map[string]bool{"--registry": true, "--prefix": true, "--userconfig": true, "-c": true, "--call": true}
var uvSpecFlags = map[string]bool{"--from": true, "--spec": true}
var uvValueFlags = map[string]bool{
	"-p": true, "--python": true, "--with": true, "--with-requirements": true,
	"--index-url": true, "--index": true, "--extra-index-url": true,
	"--refresh-package": true, "--reinstall-package": true, "--python-preference": true,
}

// docker run flags that consume the following token. -i/-t/-d/--rm and other
// booleans are deliberately absent (from the docker CLI reference).
var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true,
	"--name": true, "--network": true, "--mount": true, "-p": true, "--publish": true,
	"--user": true, "-u": true, "--add-host": true, "--entrypoint": true, "-w": true,
	"--workdir": true, "--label": true, "-l": true, "--platform": true, "--pull": true,
	"-m": true, "--memory": true, "--tmpfs": true, "--device": true, "--security-opt": true,
	"--gpus": true, "--cap-add": true, "--cap-drop": true, "-h": true, "--hostname": true,
	"--restart": true, "--health-cmd": true, "--ulimit": true, "--sysctl": true,
}

func unpinnedInstall(s model.Server) (string, bool) {
	if s.Transport != model.Stdio {
		return "", false
	}
	cmd, args := effectiveInstall(s)
	base := baseCommand(cmd)

	// Container runtimes: docker/podman/nerdctl. A tagless `run` image resolves to
	// :latest; `compose run` isn't a fresh image install.
	if base == "docker" || base == "podman" || base == "nerdctl" {
		if len(args) > 0 && args[0] == "compose" {
			return "", false
		}
		if img, ok := dockerImage(args); ok && !dockerPinned(img) {
			return img, true
		}
		return "", false
	}

	family, rest, ok := runnerArgs(base, args)
	if !ok {
		return "", false
	}
	pkg := firstPackage(family, rest)
	if pkg == "" || isPinned(family, pkg) {
		return "", false
	}
	return pkg, true
}

// runnerArgs identifies the package-runner family ("npm" or "uv") and returns the
// args after the run subcommand. It normalizes aliases: `npm x` = `npm exec`,
// `uv tool run` = `uvx`, `pipx run`, `pnpm/yarn dlx`.
func runnerArgs(base string, args []string) (family string, rest []string, ok bool) {
	switch base {
	case "npx", "bunx", "pnpx":
		return "npm", args, true
	case "uvx":
		return "uv", args, true
	case "npm":
		if i := indexOfAny(args, "exec", "x"); i >= 0 {
			rest = args[i+1:]
			if indexOf(rest, "--no") >= 0 || indexOf(rest, "--no-install") >= 0 {
				return "", nil, false // `npm exec --no` never installs
			}
			return "npm", rest, true
		}
	case "pnpm", "yarn":
		if i := indexOf(args, "dlx"); i >= 0 {
			return "npm", args[i+1:], true
		}
	case "uv":
		if i := indexOfSeq(args, "tool", "run"); i >= 0 {
			return "uv", args[i+2:], true
		}
	case "pipx":
		if i := indexOf(args, "run"); i >= 0 {
			return "uv", args[i+1:], true
		}
	}
	return "", nil, false
}

// firstPackage returns the package spec a runner will execute. A spec flag
// (--from/--package/-p, in space or = form) names it explicitly and wins; otherwise
// it's the first bare argument, with value-flag values skipped.
func firstPackage(family string, args []string) string {
	spec, value := npmSpecFlags, npmValueFlags
	if family == "uv" {
		spec, value = uvSpecFlags, uvValueFlags
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if name, v, ok := strings.Cut(a, "="); ok && spec[name] {
			return v
		}
		if spec[a] && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "-") {
			if name, _, ok := strings.Cut(a, "="); ok && value[name] {
				continue // self-contained --python=3.12
			}
			if value[a] {
				i++ // skip the flag's value token
			}
			continue
		}
		return a
	}
	return ""
}

// isPinned is true only when a spec names an exact version. npm-family runners need
// a full major.minor.patch (per node-semver, @1 and @1.2 are ranges); uv/pipx pin
// on any concrete version after @ (uv resolves @1 to that exact release).
func isPinned(family, pkg string) bool {
	p := pkg
	if strings.HasPrefix(p, "@") { // strip npm scope @scope/
		if i := strings.IndexByte(p, '/'); i >= 0 {
			p = p[i+1:]
		}
	}
	if i := strings.LastIndex(p, "=="); i >= 0 { // Python ==2025.4.7
		return exactVersion(p[i+2:])
	}
	if i := strings.LastIndexByte(p, '@'); i >= 0 {
		if family == "uv" {
			return exactVersion(p[i+1:])
		}
		return exactSemver(p[i+1:])
	}
	return false
}

func indexOfAny(xs []string, wants ...string) int {
	for i, x := range xs {
		for _, w := range wants {
			if x == w {
				return i
			}
		}
	}
	return -1
}

func indexOfSeq(xs []string, a, b string) int {
	for i := 0; i+1 < len(xs); i++ {
		if xs[i] == a && xs[i+1] == b {
			return i
		}
	}
	return -1
}

// exactVersion accepts any concrete version (Python's == accepts calendar and
// two-part versions), rejecting tags and ranges.
func exactVersion(v string) bool {
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "latest", "next", "beta", "alpha", "canary", "rc", "stable", "dev", "nightly", "edge":
		return false
	}
	if strings.ContainsAny(v, "^~*<>|xX ") {
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}

// exactSemver is exactVersion plus the npm rule that only a full major.minor.patch
// is pinned: per node-semver, @1 and @1.2 are ranges (>=1.0.0 <2.0.0, etc.).
func exactSemver(v string) bool {
	if !exactVersion(v) {
		return false
	}
	core := v
	if i := strings.IndexAny(core, "-+"); i >= 0 { // strip prerelease/build metadata
		core = core[:i]
	}
	return strings.Count(core, ".") >= 2
}

func dockerImage(args []string) (string, bool) {
	i := indexOf(args, "run")
	if i < 0 {
		return "", false
	}
	for j := i + 1; j < len(args); j++ {
		a := args[j]
		if strings.HasPrefix(a, "-") {
			if dockerValueFlags[a] {
				j++
			}
			continue
		}
		return a, true // first bare arg after "run" is the image
	}
	return "", false
}

func dockerPinned(img string) bool {
	if strings.Contains(img, "@sha256:") {
		return true
	}
	if i := strings.LastIndexByte(img, ':'); i >= 0 {
		tag := img[i+1:]
		if strings.Contains(tag, "/") { // it was a registry:port, not a tag
			return false
		}
		return tag != "" && strings.ToLower(tag) != "latest"
	}
	return false
}

// ---- untrusted command ---------------------------------------------------

// effectiveInstall unwraps the documented `cmd /c <command> ...` Windows wrapper
// so the real command (an npx, node, ...) is what gets audited. cmd's own leading
// switches (/d /q /s /v:on /e:on) are skipped, /r is an alias of /c, and /c may be
// glued to the command (`/cnpx`).
func effectiveInstall(s model.Server) (string, []string) {
	cmd, args := s.Command, s.Args
	// Unwrap repeatedly so a nested `cmd /c "cmd /c <payload>"` reaches the payload.
	for i := 0; i < 8 && baseCommand(cmd) == "cmd"; i++ {
		c, a, ok := unwrapCmd(args)
		if !ok {
			break
		}
		cmd, args = c, a
	}
	return cmd, args
}

// unwrapCmd strips one `cmd [/switches] /c <command> ...` layer. Its leading
// switches (/d /q /s /v:on /e:on) are skipped, /r is an alias of /c, and /c may be
// glued to the command (`/cnpx`).
func unwrapCmd(args []string) (string, []string, bool) {
	for len(args) > 0 {
		a := strings.ToLower(args[0])
		switch {
		case a == "/c" || a == "/k" || a == "/r":
			c, rest := splitCmdArgs(args[1:])
			return c, rest, true
		case strings.HasPrefix(a, "/c") && len(a) > 2: // glued: /cnpx -y pkg
			c, rest := splitCmdArgs(append([]string{args[0][2:]}, args[1:]...))
			return c, rest, true
		case strings.HasPrefix(a, "/"): // another cmd switch
			args = args[1:]
		default:
			return "", nil, false
		}
	}
	return "", nil, false
}

// splitCmdArgs turns the args after cmd's /c into (command, args). A single quoted
// arg (`cmd /c "npx -y pkg"`) packs the whole command, so it's split on whitespace.
func splitCmdArgs(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	if len(args) == 1 && strings.ContainsAny(args[0], " \t") {
		if fields := strings.Fields(args[0]); len(fields) > 0 {
			return fields[0], fields[1:]
		}
	}
	return args[0], args[1:]
}

func untrusted(s model.Server) (string, bool) {
	// Audit the effective command: cmd /c <real> is unwrapped so a shell payload
	// hidden behind it (cmd /c powershell -c "…") is still checked, not cleared.
	ecmd, eargs := effectiveInstall(s)
	if base, ok := inlineCodeLauncher(ecmd, eargs); ok {
		return "Launched via " + base + " running an inline command string, which can chain arbitrary commands.", true
	}
	// A cmd /c "<single string>" that carries shell metacharacters is a command
	// string too, even without an inner shell. After unwrap the string may be the
	// effective command itself (one quoted arg) or spread across the args.
	if baseCommand(s.Command) == "cmd" && looksLikeShellString(append([]string{ecmd}, eargs...)) {
		return "cmd /c runs a command string with shell operators, which can chain arbitrary commands.", true
	}
	// A path inside a temp or downloads directory — the raw command, the effective
	// command, or the script argument of an interpreter.
	for _, p := range []string{s.Command, ecmd, scriptArg(ecmd, eargs)} {
		if fromUntrustedDir(p) {
			return "Runs from a temporary or downloads directory (" + p + "), an untrusted location.", true
		}
	}
	return "", false
}

// Options that take a value in space-separated form, per interpreter. Knowing
// these lets the scan skip a value like `Bypass` in `-ExecutionPolicy Bypass` and
// keep looking, instead of stopping at it and missing the `-EncodedCommand` behind.
var psValueOpts = map[string]bool{"executionpolicy": true, "windowstyle": true, "workingdirectory": true, "configurationname": true, "outputformat": true, "inputformat": true, "psconsolefile": true, "version": true, "settingsfile": true, "custompipename": true}
var shValueOpts = map[string]bool{"o": true, "init-file": true, "rcfile": true}
var nodeValueOpts = map[string]bool{"r": true, "require": true, "import": true, "loader": true, "experimental-loader": true, "title": true, "input-type": true, "conditions": true, "c": false}

func launcherValueOpts(base string) map[string]bool {
	switch base {
	case "powershell", "pwsh":
		return psValueOpts
	case "sh", "bash", "zsh", "dash", "ksh", "ash", "busybox":
		return shValueOpts
	case "node", "deno", "bun":
		return nodeValueOpts
	case "ruby", "perl":
		return map[string]bool{"i": true}
	}
	return nil
}

// inlineCodeLauncher reports whether cmd+args invokes an interpreter that runs a
// command string rather than a file — bash -c, powershell -Command / -ec /
// -EncodedCommand / a bare string, node -e / --eval / --import data:, python -c /
// -Ic, ruby/perl -e — unwrapping wsl, env and cmd start/call. It parses argv by
// each interpreter's grammar: a value-taking option's value is skipped (so a code
// flag behind it is still found), and a terminator (-File, -m, --) or the script
// positional ends the scan.
func inlineCodeLauncher(cmd string, args []string) (string, bool) {
	base := launcherBase(cmd)
	if base == "wsl" || base == "env" {
		if rest := unwrapExecWrapper(base, args); len(rest) > 0 {
			return inlineCodeLauncher(rest[0], rest[1:])
		}
		return "", false
	}
	if base == "call" || base == "start" { // cmd builtins that run another command
		if rest := unwrapCmdBuiltin(base, args); len(rest) > 0 {
			return inlineCodeLauncher(rest[0], rest[1:])
		}
		return "", false
	}
	valueOpts := launcherValueOpts(base)
	sawFile := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break // the script / code positional
		}
		short := !strings.HasPrefix(a, "--")
		raw := strings.ToLower(strings.TrimLeft(a, "-/"))
		opt, val, hasEq := strings.Cut(raw, "=")

		if base == "python" && short {
			switch kind, valueNext := pythonCluster(opt); kind {
			case "code":
				return base, true
			case "term":
				return "", false // -m runs a module
			case "value":
				if valueNext {
					i++
				}
				continue
			}
			continue
		}
		if isLauncherCodeFlag(base, opt, short, hasEq, val, args, i) {
			return base, true
		}
		takesValue := valueOpts[opt]
		switch base {
		case "powershell", "pwsh":
			if isPrefixOf(opt, "file") { // -f / -fi / -file: running a script file
				sawFile = true
				return "", false
			}
			// PowerShell accepts any unambiguous abbreviation, so a full-name table
			// can't be right. Default the other way: anything that isn't a known
			// boolean switch consumes the next token, so an abbreviated value option
			// (-ep, -w) can't leave its value to end the scan.
			takesValue = !psBoolean(opt)
		case "python":
			if opt == "m" {
				return "", false // -m runs a module
			}
		}
		// Skip the option's value — but never a token that is itself a code flag, so
		// `-ep -enc <b64>` still catches -enc.
		if !hasEq && takesValue && i+1 < len(args) && !tokenIsCodeFlag(base, args[i+1]) {
			i++
		}
	}
	// powershell.exe (not pwsh, whose default positional is -File) runs a bare
	// trailing positional as -Command.
	if base == "powershell" && !sawFile {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && strings.ContainsAny(a, " ;|&") {
				return base, true
			}
		}
	}
	return "", false
}

// psBooleanSwitches are PowerShell parameters that take no value; any other
// parameter (including an abbreviation) is treated as consuming its value.
var psBooleanSwitches = []string{"noprofile", "noninteractive", "nologo", "noexit", "sta", "mta", "login", "interactive", "noprofileloadtime"}

// psValueSwitches are PowerShell parameters that take a value. -Command,
// -EncodedCommand and -File are matched earlier as code / file flags, so they're
// not listed here; this table exists only to disambiguate an abbreviation that
// prefixes both a boolean and a value-taking name (e.g. -i: -Interactive vs
// -InputFormat).
var psValueSwitches = []string{"psconsolefile", "version", "inputformat", "outputformat", "windowstyle", "configurationname", "executionpolicy", "custompipename", "encodedarguments", "settingsfile", "workingdirectory"}

// psBoolean reports whether opt names a value-less switch. An abbreviation counts
// as boolean only when it's unambiguous — a prefix of some boolean switch and of
// no value-taking one. An ambiguous abbreviation (e.g. -i) defaults to
// value-taking so its argument can't be left to end the scan before -enc.
func psBoolean(opt string) bool {
	if opt == "" {
		return false
	}
	boolMatch := false
	for _, sw := range psBooleanSwitches {
		if strings.HasPrefix(sw, opt) {
			boolMatch = true
			break
		}
	}
	if !boolMatch {
		return false
	}
	for _, sw := range psValueSwitches {
		if strings.HasPrefix(sw, opt) {
			return false // prefixes a value-taker too: ambiguous, so take a value
		}
	}
	return true
}

// tokenIsCodeFlag reports whether a raw argv token is itself an inline-code flag —
// used so a value-option's skip never swallows the code flag that follows it.
func tokenIsCodeFlag(base, tok string) bool {
	if !strings.HasPrefix(tok, "-") {
		return false
	}
	short := !strings.HasPrefix(tok, "--")
	raw := strings.ToLower(strings.TrimLeft(tok, "-/"))
	opt, val, hasEq := strings.Cut(raw, "=")
	if base == "python" && short {
		k, _ := pythonCluster(opt)
		return k == "code"
	}
	return isLauncherCodeFlag(base, opt, short, hasEq, val, nil, 0)
}

// isLauncherCodeFlag reports whether opt is an inline-code flag for base.
func isLauncherCodeFlag(base, opt string, short, hasEq bool, val string, args []string, i int) bool {
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "ash", "busybox":
		return opt == "c" || (short && strings.Contains(opt, "c"))
	case "fish":
		return opt == "c" || opt == "command"
	case "powershell", "pwsh":
		return opt == "ec" || isPrefixOf(opt, "command") || isPrefixOf(opt, "encodedcommand")
	case "node", "deno", "bun":
		if opt == "e" || opt == "eval" || opt == "p" || opt == "print" || opt == "pe" {
			return true
		}
		// --import / --require of a data: URI is itself inline code.
		if opt == "import" || opt == "require" || opt == "loader" || opt == "experimental-loader" {
			next := ""
			if hasEq {
				next = val
			} else if i+1 < len(args) {
				next = strings.ToLower(args[i+1])
			}
			return strings.HasPrefix(next, "data:")
		}
	case "ruby", "perl":
		return short && rubyPerlCode(opt)
	}
	return false
}

// rubyPerlCode is true when a bundled short cluster runs inline code (-e) before a
// value-taking letter (-r library, -I dir, -M module) consumes the rest — so
// `-rbundler/setup` (require) is not mistaken for -e because it contains an 'e'.
func rubyPerlCode(cluster string) bool {
	for i := 0; i < len(cluster); i++ {
		switch cluster[i] {
		case 'e':
			return true
		case 'r', 'i', 'm', 'c':
			return false
		}
	}
	return false
}

// pythonCluster classifies a bundled short-option cluster ("Ic", "wignore", "mfoo"):
// "code" if a -c precedes any value-taking letter, "term" for -m, "value" for
// -W/-X/-Q (valueNext true when the letter is last, so the value is the next token).
func pythonCluster(opt string) (kind string, valueNext bool) {
	for i := 0; i < len(opt); i++ {
		switch opt[i] {
		case 'c':
			return "code", false
		case 'm':
			return "term", false
		case 'W', 'X', 'Q', 'w', 'x', 'q':
			return "value", i == len(opt)-1
		}
	}
	return "", false
}

// unwrapCmdBuiltin strips `call` / `start [/b] [/wait] ["title"]` down to the
// command they launch.
func unwrapCmdBuiltin(base string, args []string) []string {
	i := 0
	if base == "start" {
		for i < len(args) {
			a := strings.ToLower(args[i])
			if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "-") {
				i++
				continue
			}
			// A quoted first token is the window title, not the command.
			if i == 0 && strings.HasPrefix(args[i], `"`) {
				i++
				continue
			}
			break
		}
	}
	if i < len(args) {
		return args[i:]
	}
	return nil
}

// launcherBase normalizes an interpreter name: python3, python3.12 and py all read
// as "python"; a version suffix on node/ruby is likewise stripped.
func launcherBase(cmd string) string {
	base := baseCommand(cmd)
	switch {
	case base == "py" || strings.HasPrefix(base, "python"):
		return "python"
	case strings.HasPrefix(base, "node") && base != "nodemon":
		return "node"
	}
	return base
}

// unwrapExecWrapper strips a wsl/env prefix down to the command it execs: env's
// VAR=val assignments and -i/-u X/-S/-C X options, and wsl's -e/--exec/-d Distro.
func unwrapExecWrapper(base string, args []string) []string {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case base == "env" && (a == "-S" || a == "--split-string") && i+1 < len(args):
			return strings.Fields(args[i+1]) // env -S "cmd args" runs a split string
		case base == "env" && strings.HasPrefix(a, "-S") && len(a) > 2:
			return strings.Fields(a[2:]) // glued -S"cmd args"
		case base == "env" && strings.Contains(a, "=") && !strings.HasPrefix(a, "-"):
			i++ // VAR=val assignment
		case base == "env" && (a == "-u" || a == "--unset" || a == "-C" || a == "--chdir"):
			i += 2 // option that takes a value
		case base == "env" && strings.HasPrefix(a, "-"):
			i++ // -i, -0, ...
		case base == "wsl" && (a == "-e" || a == "--exec"):
			i++
		case base == "wsl" && (a == "-d" || a == "--distribution" || a == "-u" || a == "--user" || a == "--cd"):
			i += 2
		case base == "wsl" && strings.HasPrefix(a, "-"):
			i++
		default:
			return args[i:]
		}
	}
	return nil
}

func isPrefixOf(s, full string) bool {
	return s != "" && strings.HasPrefix(full, s)
}

func looksLikeShellString(args []string) bool {
	for _, a := range args {
		if strings.ContainsAny(a, "|&>") || strings.Contains(a, "%TEMP%") || strings.Contains(strings.ToLower(a), "%temp%") {
			return true
		}
	}
	return false
}

func scriptArg(cmd string, args []string) string {
	switch baseCommand(cmd) {
	case "node", "python", "python3", "deno", "bun", "ts-node", "tsx":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return a
			}
		}
	}
	return ""
}

func fromUntrustedDir(p string) bool {
	low := strings.ToLower(p)
	for _, dir := range []string{"/tmp/", "\\temp\\", "\\downloads\\", "/downloads/", "appdata\\local\\temp"} {
		if strings.Contains(low, dir) {
			return true
		}
	}
	return false
}

// ---- env injection -------------------------------------------------------

// Env vars that make an interpreter load and run code before the server's own
// code — LD_PRELOAD is the classic; BASH_ENV works for non-interactive bash only.
// GIT_SSH_COMMAND runs an arbitrary shell command on any git transport.
var codeInjectionEnv = map[string]bool{
	"LD_PRELOAD": true, "LD_AUDIT": true, "DYLD_INSERT_LIBRARIES": true, "BASH_ENV": true,
	"JAVA_TOOL_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "DOTNET_STARTUP_HOOKS": true,
	"PERL5OPT": true, "RUBYOPT": true, "GIT_SSH_COMMAND": true, "PS4": true,
}

// Env vars that redirect where code, packages, trust or LLM traffic comes from.
// These are dual-use — a corporate npm mirror or LLM gateway is a legitimate use of
// most of them — so they're reported at LOW: worth seeing, never a gate failure.
var redirectEnv = map[string]bool{
	"NPM_CONFIG_REGISTRY": true, "NPM_CONFIG_YES": true, "UV_INDEX_URL": true,
	"UV_INDEX": true, "UV_DEFAULT_INDEX": true, "UV_EXTRA_INDEX_URL": true, "PIP_INDEX_URL": true,
	"PIP_EXTRA_INDEX_URL": true, "ANTHROPIC_BASE_URL": true, "OPENAI_BASE_URL": true,
	"SHELLOPTS": true, "BASHOPTS": true, "PYTHONWARNINGS": true, "NODE_EXTRA_CA_CERTS": true,
}

func envInjection(s model.Server, add func(string, model.Severity, string, string)) {
	for k, v := range mergedEnv(s) {
		up := strings.ToUpper(k)
		switch {
		case codeInjectionEnv[up]:
			add("env-injection", model.High, "Code-injection environment variable",
				k+" makes the process load and run attacker-controlled code before the server does anything.")
		case up == "NODE_OPTIONS":
			if flag := nodeOptionsInjection(v); flag != "" {
				add("env-injection", model.High, "Code-injection via NODE_OPTIONS",
					"NODE_OPTIONS carries "+flag+", which runs code before the server (the CVE-2026-44995 shape).")
			}
		case up == "NODE_TLS_REJECT_UNAUTHORIZED" && strings.TrimSpace(v) == "0":
			add("env-injection", model.High, "TLS verification disabled",
				"NODE_TLS_REJECT_UNAUTHORIZED=0 turns off certificate checking, opening the server's outbound calls to interception.")
		case up == "PYTHONPATH" && worldWritablePath(v):
			// A project-relative or normal checkout PYTHONPATH is how Python MCP READMEs
			// run from source; only a temp / world-writable prefix is an injection point.
			add("env-injection", model.High, "Code-injection via PYTHONPATH",
				"PYTHONPATH points at a world-writable location ("+v+"); a sitecustomize.py there runs at interpreter startup.")
		case redirectEnv[up]:
			add("env-injection", model.Low, "Environment variable redirects code or package sources",
				k+" overrides where the server fetches packages, code, trust, or LLM traffic from — usually a mirror or gateway, occasionally an exfiltration or supply-chain redirect.")
		}
	}
	if s.EnvFile != "" {
		add("env-injection", model.Medium, "Server loads environment from an external file",
			"envFile pulls in "+s.EnvFile+" — variables outside this config, which can include the code-injection env vars above.")
	}
}

// mergedEnv is the server's env plus any VAR=val assignments carried on an `env`
// wrapper command (`env NODE_OPTIONS=… npx …`), so a payload smuggled through the
// wrapper is audited too.
func mergedEnv(s model.Server) map[string]string {
	if baseCommand(s.Command) != "env" {
		return s.Env
	}
	out := map[string]string{}
	for k, v := range s.Env {
		out[k] = v
	}
	for i := 0; i < len(s.Args); i++ {
		a := s.Args[i]
		if a == "-u" || a == "--unset" || a == "-C" || a == "--chdir" {
			i++ // this option consumes the next token as its value
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue // other env option (-i, -0, -S, …)
		}
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			break // reached the command being wrapped
		}
		out[k] = v
	}
	return out
}

// worldWritablePath is true for a temp / world-writable prefix, where a planted
// sitecustomize.py is the real risk — unlike a normal absolute checkout path, which
// is how Python MCP servers legitimately run from source.
func worldWritablePath(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	for _, p := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "%temp%", "\\temp\\", "\\downloads\\", "/downloads/", "appdata\\local\\temp"} {
		if strings.Contains(low, p) || low == strings.TrimSuffix(p, "/") {
			return true
		}
	}
	return false
}

// nodeOptionsInjection returns the offending flag in a NODE_OPTIONS value, or "".
// It normalizes the way Node's own parser does — dropping every double-quote in a
// token and mapping `_` to `-` in the flag name — so quoted and underscore
// spellings (`"--require"`, `--req"uire"`, `--experimental_loader`) don't slip past.
func nodeOptionsInjection(v string) string {
	for _, tok := range strings.Fields(v) {
		tok = strings.ReplaceAll(tok, `"`, "")
		name := tok
		if i := strings.IndexAny(name, "=:"); i >= 0 {
			name = name[:i]
		}
		name = strings.ReplaceAll(name, "_", "-")
		switch name {
		case "-r", "--require", "--import", "--loader", "--experimental-loader",
			"--snapshot-blob", "--build-snapshot", "--test-reporter":
			return name
		}
		if name == "--inspect" || name == "--inspect-brk" || name == "--inspect-wait" {
			if i := strings.IndexAny(tok, "=:"); i >= 0 && bindsNonLoopback(tok[i+1:]) {
				return name
			}
		}
	}
	return ""
}

// bindsNonLoopback is true when an --inspect value exposes the debugger on a
// non-loopback address. A port-only value (`--inspect=9229`) binds 127.0.0.1, so
// it is not exposed.
func bindsNonLoopback(v string) bool {
	v = strings.Trim(v, `"`)
	if !strings.Contains(v, ":") && !strings.ContainsAny(v, ".") {
		return false // bare port (or empty) → loopback default
	}
	host := v
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i] // strip :port
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return false
	}
	return true
}

// ---- remote host classification ------------------------------------------

var portTemplateRe = regexp.MustCompile(`:\$\{[^}]*\}`)

// substituteURLTemplates replaces a ${...} that sits in the port position with :1,
// so `http://127.0.0.1:${env:PORT}/mcp` still parses and keeps its loopback
// classification. A template in the host position (`http://${MCP_HOST}/mcp`) is left
// in place, so urlHost can't determine a host and the URL goes unclassified.
func substituteURLTemplates(rawURL string) string {
	return portTemplateRe.ReplaceAllString(rawURL, ":1")
}

// urlHost returns the lowercased hostname (no port, no userinfo, brackets
// stripped) from a URL. A host that still carries a ${...}/{...} template is
// undetermined and returns "" so no rule fires on a guess.
func urlHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h == "" || strings.ContainsAny(h, "${}") {
		return ""
	}
	return h
}

func isLoopback(rawURL string) bool {
	return hostIsLocal(urlHost(rawURL))
}

// isTrueLoopback is loopback proper (localhost, 127/8, ::1) but not an
// all-interfaces bind, which is reachable and so still "exposed".
func isTrueLoopback(h string) bool {
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	return ipIsLoopback(strings.Trim(h, "[]"))
}

// ipIsLoopback covers all of 127.0.0.0/8 — including short forms like 127.1 that
// resolve to a loopback address — and IPv6 ::1. Done by hand rather than with
// net.ParseIP so the binary never imports net, keeping the offline guarantee easy
// to verify with `go list -deps`.
func ipIsLoopback(ip string) bool {
	if strings.HasPrefix(ip, "127.") && allNumericDotted(ip) {
		return true
	}
	switch ip {
	case "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	return false
}

func allNumericDotted(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func ipIsUnspecified(ip string) bool {
	switch ip {
	case "0.0.0.0", "::", "0:0:0:0:0:0:0:0":
		return true
	}
	return false
}

func isDottedQuad(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// hostIsLocal is true for a host that never leaves the machine: localhost, a
// loopback IP, or the Docker host alias. 0.0.0.0 is treated as local for the
// plaintext-HTTP rule (nothing leaves in transit) but stays "exposed" separately.
func hostIsLocal(h string) bool {
	switch h {
	case "localhost", "0.0.0.0", "host.docker.internal", "::", "[::]":
		return true
	}
	if strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := strings.Trim(h, "[]")
	return ipIsLoopback(ip) || ipIsUnspecified(ip)
}

var riskyPortNames = map[string]string{"11434": "Ollama", "8188": "ComfyUI", "5678": "n8n", "7860": "Gradio"}

// riskyHost names why a remote host is exposed: an AI-service port botnets hunt
// (matched exactly, so :56780 isn't mistaken for :5678) or a bare IP.
func riskyHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if name, ok := riskyPortNames[u.Port()]; ok {
		return name + " port " + u.Port()
	}
	if h := u.Hostname(); isDottedQuad(h) {
		return h
	}
	return ""
}

func baseCommand(cmd string) string {
	cmd = strings.ReplaceAll(cmd, "\\", "/")
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		cmd = cmd[i+1:]
	}
	cmd = strings.TrimSuffix(strings.ToLower(cmd), ".exe")
	cmd = strings.TrimSuffix(cmd, ".cmd")
	return cmd
}

func indexOf(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}
