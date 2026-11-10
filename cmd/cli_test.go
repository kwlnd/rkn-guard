package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSourceRef(t *testing.T) {
	for in, want := range map[string]sourceRef{"3": {id: 3}, "b1": {base: true, id: 1}, "B12": {base: true, id: 12}} {
		got, err := parseSourceRef(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "b", "b0", "-1", "x2", "1.5"} {
		if _, err := parseSourceRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v2.4.0", "v2.3.5", true},
		{"v2.3.5", "v2.3.5", false},
		{"v2.3.10", "v2.3.9", true},
		{"v2.3.4", "v2.4.0", false},
		{"v2.4.0", "dev", true},
		{"garbage", "v1.0.0", false},
	}
	for _, c := range cases {
		if got := newerVersion(c.latest, c.current); got != c.want {
			t.Errorf("%s vs %s: %v", c.latest, c.current, got)
		}
	}
}

func TestCommandTree(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{
		{"install"}, {"uninstall"}, {"upgrade"}, {"update"}, {"status"}, {"stats"}, {"logs"},
		{"ban"}, {"unban"}, {"bans"}, {"schedule", "daily"}, {"schedule", "every"}, {"schedule", "off"},
		{"sources", "add"}, {"sources", "enable"}, {"sources", "disable"}, {"sources", "remove"},
		// Старые установки и юниты systemd вызывают эти команды.
		{"full"}, {"setup-logging"}, {"restore"}, {"build-info"},
	} {
		cmd, rest, err := root.Find(path)
		if err != nil || len(rest) != 0 || cmd.Name() != path[len(path)-1] {
			t.Errorf("%v: not found (%v)", path, err)
		}
	}
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"full", "setup-logging", "restore", "build-info"} {
		if strings.Contains(out.String(), "\n  "+hidden+" ") {
			t.Errorf("hidden command %s shown in help", hidden)
		}
	}
}

func TestOldUpdateFlagsAccepted(t *testing.T) {
	root := newRootCommand()
	cmd, _, _ := root.Find([]string{"update"})
	if err := cmd.ParseFlags([]string{"-u", "https://example.org/a", "--managed-lists", "--sources-file", "/x"}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		t.Fatalf("leftover args %v: %v", cmd.Flags().Args(), err)
	}
}
