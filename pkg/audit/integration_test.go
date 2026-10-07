package audit

import (
	"path/filepath"
	"testing"

	"github.com/NotChaosuu/mcpscope/pkg/config"
	"github.com/NotChaosuu/mcpscope/pkg/model"
)

func TestAuditEvilConfigEndToEnd(t *testing.T) {
	servers, err := config.ParseFile(filepath.Join("testdata", "evil_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 5 {
		t.Fatalf("want 5 servers parsed, got %d", len(servers))
	}
	findings := Audit(servers)

	byServer := map[string]map[string]model.Severity{}
	for _, f := range findings {
		if byServer[f.Server] == nil {
			byServer[f.Server] = map[string]model.Severity{}
		}
		byServer[f.Server][f.Rule] = f.Severity
	}

	if byServer["filesystem"]["unpinned-install"] != model.Medium {
		t.Error("filesystem: expected unpinned-install")
	}
	if byServer["leaky"]["plaintext-secret"] != model.High {
		t.Error("leaky: expected plaintext-secret high")
	}
	if byServer["risky-remote"]["insecure-remote"] != model.High {
		t.Error("risky-remote: expected insecure-remote high (http)")
	}
	if byServer["risky-remote"]["exposed-remote"] != model.Medium {
		t.Error("risky-remote: expected exposed-remote (Ollama port / bare IP)")
	}
	if byServer["shell"]["untrusted-command"] != model.Medium {
		t.Error("shell: expected untrusted-command")
	}
	if len(byServer["safe"]) != 0 {
		t.Errorf("safe server should be clean, got %+v", byServer["safe"])
	}
}
