package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOpSummaryNeverKeepsArguments(t *testing.T) {
	for _, c := range []struct {
		args []string
		what string
		refs []string
	}{
		{[]string{"item", "create", "--category", "login", "password=hunter2", "--title", "x"}, "op item create", nil},
		{[]string{"item", "get", "Cloudflare DNS token", "--fields", "credential"}, "op item get", nil},
		{[]string{"inject", "-i", "tpl", "--", "{{ op://Agents/a/b }}"}, "op inject", []string{"op://Agents/a/b"}},
		{[]string{"--version"}, "op --version", nil},
		{[]string{"whoami"}, "op whoami", nil},
	} {
		what, refs := opSummary(c.args)
		if what != c.what || !slices.Equal(refs, c.refs) {
			t.Errorf("%v: %q %v", c.args, what, refs)
		}
		if strings.Contains(what, "hunter2") {
			t.Fatal("an argument leaked into the summary")
		}
	}
}

func auditEvents(t *testing.T, path string) []auditLine {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []auditLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var l auditLine
		json.Unmarshal(sc.Bytes(), &l)
		out = append(out, l)
	}
	return out
}

func TestRoutesAndKeyUsesInHistory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	e := newEnv(t)
	e.b.cfg.AuditLog = filepath.Join(t.TempDir(), "audit.jsonl")
	e.b.audit = &Audit{path: e.b.cfg.AuditLog}
	sock := filepath.Join(t.TempDir(), "s.sock")
	go e.b.serveSocket(sock)
	for i := 0; i < 50 && !serviceUp(Config{Socket: sock}); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cfg := defaultConfig()
	cfg.Socket = sock

	// auto mode, owner at the Mac, 1Password answers: recorded as the Touch ID route
	t.Setenv("OPGATE_SOCKET", sock)
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, false))
	t.Setenv("OPGATE_MODE", ModeAuto)
	t.Setenv("OPGATE_PRESENCE", "present")
	if _, err := resolve(cfg, []string{"op://Agents/Cloudflare/credential"}, "list zones via Touch ID", ""); err != nil {
		t.Fatal(err)
	}
	recordRoute(cfg, RouteOpPassthrough, nil, "op item list")
	recordRoute(cfg, RouteOpAway, nil, "op item get")
	recordRoute(cfg, "made-up", nil, "should be ignored")
	e.b.keyUsed(keyMeta{Ref: "op://Agents/opgate build key/private key", Loaded: time.Now()}, "SHA256:m",
		procsFromArgs([]string{"/usr/bin/ssh nas true", "-zsh"}))
	e.b.upstreamUsed("owner@example SSH", procsFromArgs([]string{"/usr/bin/ssh tablet uptime", "-zsh"}))

	var routed []string
	for _, l := range auditEvents(t, e.b.cfg.AuditLog) {
		if l.Event == "routed" {
			routed = append(routed, l.By)
			if len(l.Caller) == 0 {
				t.Error("routed event without the kernel's process chain")
			}
		}
	}
	if !slices.Equal(routed, []string{Route1Password, RouteOpPassthrough, RouteOpAway}) {
		t.Fatalf("routed %v", routed)
	}
	items := e.b.history(100)
	var got []string
	for _, it := range items {
		got = append(got, it.Type+"/"+it.Status+"/"+it.Title)
	}
	for _, want := range []string{"1password/touchid/Cloudflare", "op/passed/op item list", "key/used/Build key", "key/touchid/1Password: owner@example SSH", "op/failed/op item get"} {
		if !slices.Contains(got, want) {
			t.Errorf("history lacks %s: %v", want, got)
		}
	}
	if items[0].Title != "1Password: owner@example SSH" {
		t.Errorf("not newest first: %v", got)
	}
}
