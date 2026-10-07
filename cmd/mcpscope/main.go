package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/NotChaosuu/mcpscope/pkg/audit"
	"github.com/NotChaosuu/mcpscope/pkg/config"
	"github.com/NotChaosuu/mcpscope/pkg/model"
)

const version = "0.1.0"

// Source is one config location that was looked at, and why it did or didn't
// yield servers. An Error here means the file couldn't be read — which is not the
// same as "clean".
type Source struct {
	Path    string `json:"path"`
	Host    string `json:"host,omitempty"`
	Servers int    `json:"servers"`
	Error   string `json:"error,omitempty"`
}

func main() {
	quiet := flag.Bool("q", false, "suppress banner and progress")
	verbose := flag.Bool("v", false, "show every finding with full detail")
	asJSON := flag.Bool("json", false, "emit JSON report to stdout")
	minSev := flag.String("min-severity", "", "only show findings at or above this severity (high|medium|low)")
	exitCode := flag.Bool("exit-code", false, "exit non-zero on findings (1) or an incomplete scan (2)")
	showVersion := flag.Bool("version", false, "print version and exit")

	// Go's flag package stops at the first positional, so flags after a path — the
	// natural `mcpscope configs/*.json --exit-code` — would be dropped, and a second
	// path would be ignored. Partition args ourselves: flags anywhere are parsed,
	// every positional is audited.
	flags, paths := partitionArgs(os.Args[1:])
	if err := flag.CommandLine.Parse(flags); err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println("mcpscope", version)
		return
	}
	if *minSev != "" && !validSeverity(*minSev) {
		fmt.Fprintf(os.Stderr, "mcpscope: unknown -min-severity %q (use high, medium, or low)\n", *minSev)
		os.Exit(2)
	}

	q := *quiet || *asJSON
	status := func(msg string) {
		if !q {
			fmt.Fprint(os.Stderr, msg)
		}
	}
	warn := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }

	if !q {
		fmt.Fprintf(os.Stderr, "\n  mcpscope %s  —  MCP server config audit (offline)\n\n", version)
	}

	servers, sources := gatherAll(paths, status)
	errCount := 0
	for _, s := range sources {
		if s.Error != "" {
			errCount++
		}
	}
	if errCount > 0 {
		warn("  WARNING: %d config(s) could not be read — this scan is INCOMPLETE, not clean\n", errCount)
	}

	findings := filterSeverity(audit.Audit(servers), *minSev)
	sortFindings(findings)

	if *asJSON {
		emitJSON(servers, sources, findings, errCount)
	} else {
		printReport(servers, sources, findings, *verbose, errCount)
	}

	if *exitCode {
		if errCount > 0 {
			os.Exit(2) // an incomplete scan is not a passing scan
		}
		for _, f := range findings {
			if f.Severity == model.High || f.Severity == model.Medium {
				os.Exit(1)
			}
		}
	}
}

// valueFlagNames are the flags that take a following value, so a partition doesn't
// mistake that value for a positional path. --min-severity is the only one.
var valueFlagNames = map[string]bool{"-min-severity": true, "--min-severity": true}

// partitionArgs splits argv into flags (with their values) and positional paths,
// regardless of order. `--flag=value` and `--min-severity high` both stay together.
func partitionArgs(argv []string) (flags, paths []string) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" { // everything after -- is a positional path
			paths = append(paths, argv[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			if valueFlagNames[a] && !strings.Contains(a, "=") && i+1 < len(argv) {
				i++
				flags = append(flags, argv[i])
			}
			continue
		}
		paths = append(paths, a)
	}
	return flags, paths
}

func gatherAll(paths []string, status func(string)) ([]model.Server, []Source) {
	if len(paths) == 0 {
		return gatherHosts(config.KnownHosts(), "", status)
	}
	var servers []model.Server
	var sources []Source
	for _, p := range paths {
		sv, src := gather(p, status)
		servers = append(servers, sv...)
		sources = append(sources, src...)
	}
	return servers, sources
}

func gather(path string, status func(string)) ([]model.Server, []Source) {
	if path == "" {
		// An empty path argument (e.g. `mcpscope "$CONFIG"` with CONFIG unset) must
		// not silently fall through to a whole-machine scan and pass — fail closed.
		status("  empty path argument — nothing to scan\n")
		return nil, []Source{{Path: "(empty argument)", Error: "empty path argument"}}
	}
	info, err := os.Stat(path)
	if err != nil {
		status(fmt.Sprintf("  could not read %s: %v\n", path, err))
		return nil, []Source{{Path: path, Error: err.Error()}}
	}
	if info.IsDir() {
		return gatherHosts(config.ProjectHosts(path), path, status)
	}
	servers, perr := config.ParseFile(path)
	src := Source{Path: path, Servers: len(servers)}
	if perr != nil {
		src.Error = perr.Error()
		status(fmt.Sprintf("  could not read %s: %v\n", path, perr))
	}
	return servers, []Source{src}
}

func gatherHosts(hosts []config.Host, base string, status func(string)) ([]model.Server, []Source) {
	if len(hosts) == 0 {
		if base != "" {
			return nil, []Source{{Path: base, Servers: 0}}
		}
		return nil, nil
	}
	var out []model.Server
	var sources []Source
	for _, h := range hosts {
		servers, err := config.Parse(h)
		src := Source{Path: h.Path, Host: h.App, Servers: len(servers)}
		if err != nil {
			src.Error = err.Error()
			status(fmt.Sprintf("  %s: could not read %s: %v\n", h.App, h.Path, err))
		}
		out = append(out, servers...)
		sources = append(sources, src)
	}
	return out, sources
}

func validSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "high", "medium", "low", "info":
		return true
	}
	return false
}
