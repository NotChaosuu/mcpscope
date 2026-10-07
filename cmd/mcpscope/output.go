package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/NotChaosuu/mcpscope/pkg/model"
)

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var color = useColor()

func c(code, s string) string {
	if !color {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func sevBadge(s model.Severity) string {
	switch s {
	case model.High:
		return c("91;1", "HIGH  ")
	case model.Medium:
		return c("93;1", "MEDIUM")
	case model.Low:
		return c("96", "LOW   ")
	default:
		return c("2", "INFO  ")
	}
}

func filterSeverity(f []model.Finding, min string) []model.Finding {
	if min == "" {
		return f
	}
	cut, ok := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}[strings.ToLower(min)]
	if !ok {
		return f
	}
	var out []model.Finding
	for _, x := range f {
		if x.Severity.Rank() <= cut {
			out = append(out, x)
		}
	}
	return out
}

func sortFindings(f []model.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity.Rank() != f[j].Severity.Rank() {
			return f[i].Severity.Rank() < f[j].Severity.Rank()
		}
		if f[i].Server != f[j].Server {
			return f[i].Server < f[j].Server
		}
		return f[i].Rule < f[j].Rule
	})
}

func counts(f []model.Finding) (high, medium, low int) {
	for _, x := range f {
		switch x.Severity {
		case model.High:
			high++
		case model.Medium:
			medium++
		case model.Low:
			low++
		}
	}
	return
}

func sourceLabels(sources []Source) []string {
	var out []string
	for _, s := range sources {
		label := s.Path
		if s.Host != "" {
			label = s.Host
		}
		if s.Error != "" {
			out = append(out, label+" (unreadable)")
		} else {
			out = append(out, fmt.Sprintf("%s (%d)", label, s.Servers))
		}
	}
	return out
}

func printReport(servers []model.Server, sources []Source, findings []model.Finding, verbose bool, errCount int) {
	bold := func(s string) string { return c("1", s) }
	dim := func(s string) string { return c("2", s) }

	labels := sourceLabels(sources)
	if len(labels) == 0 {
		labels = []string{"no configs"}
	}
	fmt.Printf("  %s  %s  —  %d servers\n", bold("Scanned:"), strings.Join(labels, ", "), len(servers))
	high, medium, low := counts(findings)
	if len(findings) == 0 {
		if errCount > 0 {
			fmt.Printf("  %s  no risks found, but the scan was INCOMPLETE (see warnings above)\n\n", bold("Findings:"))
		} else {
			fmt.Printf("  %s  no risks found\n\n", bold("Findings:"))
		}
		return
	}
	fmt.Printf("  %s  %s, %s, %s\n\n", bold("Findings:"),
		c("91", fmt.Sprintf("%d high", high)),
		c("93", fmt.Sprintf("%d medium", medium)),
		c("96", fmt.Sprintf("%d low", low)))

	for _, f := range findings {
		where := f.Server
		if f.Host != "" && f.Host != "file" {
			where += dim(" (" + f.Host + ")")
		}
		fmt.Printf("  %s  %s  %s\n", sevBadge(f.Severity), bold(where), f.Title)
		if verbose {
			fmt.Printf("          %s\n", dim(f.Rule))
			fmt.Printf("          %s\n", wrap(f.Detail, 72, "          "))
		}
	}
	fmt.Println()
	if !verbose {
		fmt.Printf("  %s\n\n", dim("run with -v for full detail on each finding"))
	}
}

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	line := 0
	for i, w := range words {
		if line > 0 && line+len(w)+1 > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}

func emitJSON(servers []model.Server, sources []Source, findings []model.Finding, errCount int) {
	if findings == nil {
		findings = []model.Finding{} // never marshal null — `jq '.findings[]'` must work
	}
	if sources == nil {
		sources = []Source{}
	}
	high, medium, low := counts(findings)
	out := struct {
		Tool     string          `json:"tool"`
		Version  string          `json:"version"`
		Complete bool            `json:"complete"`
		Errors   int             `json:"errors"`
		Sources  []Source        `json:"sources"`
		Servers  int             `json:"servers_scanned"`
		Summary  map[string]int  `json:"summary"`
		Findings []model.Finding `json:"findings"`
	}{
		Tool: "mcpscope", Version: version,
		// A parser can tell "clean" from "couldn't read a config" without stderr.
		Complete: errCount == 0,
		Errors:   errCount,
		Sources:  sources,
		Servers:  len(servers),
		Summary:  map[string]int{"high": high, "medium": medium, "low": low},
		Findings: findings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
