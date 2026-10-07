package main

import (
	"reflect"
	"testing"
)

// Flags must be recognized wherever they sit, and every positional path is
// collected — a second path (or a glob expansion) must not turn the flags off.
func TestPartitionArgs(t *testing.T) {
	cases := []struct {
		argv        []string
		wantFlags   []string
		wantPaths   []string
		description string
	}{
		{[]string{"-q", "evil.json", "--exit-code"}, []string{"-q", "--exit-code"}, []string{"evil.json"}, "flag after path"},
		{[]string{"-q", "clean.json", "evil.json", "--exit-code"}, []string{"-q", "--exit-code"}, []string{"clean.json", "evil.json"}, "two paths keep flags"},
		{[]string{"-q", "--exit-code", "a.json", "b.json"}, []string{"-q", "--exit-code"}, []string{"a.json", "b.json"}, "flags first, two paths"},
		{[]string{"g/a.json", "g/b.json", "--exit-code"}, []string{"--exit-code"}, []string{"g/a.json", "g/b.json"}, "glob then flag"},
		{[]string{"--min-severity", "high", "repo"}, []string{"--min-severity", "high"}, []string{"repo"}, "value flag keeps its value"},
		{[]string{"--min-severity=high", "repo"}, []string{"--min-severity=high"}, []string{"repo"}, "value flag with ="},
		{[]string{"-q", "--", "evil.json", "--exit-code"}, []string{"-q"}, []string{"evil.json", "--exit-code"}, "everything after -- is a path"},
	}
	for _, tc := range cases {
		flags, paths := partitionArgs(tc.argv)
		if !reflect.DeepEqual(flags, tc.wantFlags) {
			t.Errorf("%s: flags = %v, want %v", tc.description, flags, tc.wantFlags)
		}
		if !reflect.DeepEqual(paths, tc.wantPaths) {
			t.Errorf("%s: paths = %v, want %v", tc.description, paths, tc.wantPaths)
		}
	}
}
