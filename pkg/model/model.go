package model

type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
	Info   Severity = "info"
)

var severityRank = map[Severity]int{High: 0, Medium: 1, Low: 2, Info: 3}

func (s Severity) Rank() int { return severityRank[s] }

type Transport string

const (
	Stdio   Transport = "stdio"
	HTTP    Transport = "http"
	SSE     Transport = "sse"
	Unknown Transport = ""
)

type Server struct {
	Name        string            `json:"name"`
	Host        string            `json:"host"`
	ConfigPath  string            `json:"config_path"`
	Transport   Transport         `json:"transport"`
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	EnvFile     string            `json:"env_file,omitempty"`
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Disabled    bool              `json:"disabled"`
	AutoApprove []string          `json:"auto_approve,omitempty"`
	Trust       bool              `json:"trust,omitempty"`      // Gemini CLI: bypasses all tool confirmation
	HelperCmd   []string          `json:"helper_cmd,omitempty"` // Codex http_headers_helper: a command run at startup
}

func (s Server) Remote() bool { return s.URL != "" }

type Finding struct {
	Server   string   `json:"server"`
	Host     string   `json:"host"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
}
