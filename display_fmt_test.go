package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnwrapShellKeepsQuotes(t *testing.T) {
	// Claude Code writes a quote inside the eval'd command as '"'"' (bash itself as '\'')
	in := `/bin/bash -c source /x/shell-snapshots/s.sh && eval 'opgate ssh-add --reason "Point at the iPad Air'"'"'s MAC" --ttl 15m' < /dev/null && pwd -P >| /tmp/c`
	if got, want := unwrapShell(in), `opgate ssh-add --reason "Point at the iPad Air's MAC" --ttl 15m`; got != want {
		t.Errorf("unwrapShell = %q, want %q", got, want)
	}
}

func TestSplitReason(t *testing.T) {
	why, runs := splitReason("Deploy commit c82b90c to preview (runs: /opt/homebrew/bin/node scripts/deploy.ts preview)")
	if why != "Deploy commit c82b90c to preview" || runs != "/opt/homebrew/bin/node scripts/deploy.ts preview" {
		t.Errorf("splitReason = %q, %q", why, runs)
	}
	if why, runs := splitReason("Restart dnsmasq (owner OK)"); why != "Restart dnsmasq (owner OK)" || runs != "" {
		t.Errorf("a reason without the suffix changed: %q, %q", why, runs)
	}
}

func TestCommandsKeepTheirLines(t *testing.T) {
	// a script sent over ssh: ps writes its newlines as \012
	chain := []string{`/usr/bin/ssh router echo "== uptime"\012uptime\012\012echo done`, "/bin/bash -c source /x/shell-snapshots/s.sh && eval 'x'", "claude"}
	if got, want := keyUseCommand(chain), "ssh router echo \"== uptime\"\nuptime\necho done"; got != want {
		t.Errorf("keyUseCommand = %q, want %q", got, want)
	}
	if got := firstLine("ssh router echo a\nuptime"); got != "ssh router echo a …" {
		t.Errorf("firstLine = %q", got)
	}
}

// History ties uses and reuses to the approval that allowed them, and marks the autoloaded key's uses as routine.
func TestHistoryLinksUsesToApprovals(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.AuditLog = filepath.Join(t.TempDir(), "audit.jsonl")
	router := []string{"op://Agents/opgate server key/private key"}
	ts := time.Date(2026, 11, 8, 12, 54, 0, 0, time.Local).Format(time.RFC3339)
	lines := []string{
		`{"time":"` + ts + `","id":"a1","event":"asked","kind":"ssh","refs":["` + router[0] + `"],"ttl":"15m0s","reason":"Restart dnsmasq on the router","caller":["opgate ssh-add"]}`,
		`{"time":"` + ts + `","id":"a1","event":"approved","kind":"ssh","refs":["` + router[0] + `"],"reason":"Restart dnsmasq on the router","by":"phone","detail":"loaded for 15 min"}`,
		`{"time":"` + ts + `","id":"use","event":"key-used","kind":"ssh","refs":["` + router[0] + `"],"caller":["ssh router uptime"]}`,
		`{"time":"` + ts + `","id":"use","event":"key-used","kind":"ssh","refs":["op://Agents/opgate build key/private key"],"caller":["git commit -m x"]}`,
		`{"time":"` + ts + `","id":"g1","event":"asked","kind":"secrets","refs":["op://Agents/P/x"],"reason":"Run pulumi preview (runs: node pulumi.ts preview)","caller":["opgate run"]}`,
		`{"time":"` + ts + `","id":"g1","event":"approved","kind":"secrets","refs":["op://Agents/P/x"],"reason":"Run pulumi preview (runs: node pulumi.ts preview)","by":"phone"}`,
		`{"time":"` + ts + `","id":"g2","event":"granted","kind":"secrets","refs":["op://Agents/P/x"],"reason":"Run pulumi up (runs: node pulumi.ts up --yes)","caller":["opgate run"]}`,
	}
	os.WriteFile(e.b.cfg.AuditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	items := e.b.history(10)
	if len(items) != 5 {
		t.Fatalf("got %d items", len(items))
	}
	reuse, agentKey, use := items[0], items[2], items[3]
	if !strings.Contains(reuse.Under, "approval: Run pulumi preview") || reuse.Runs != "node pulumi.ts up --yes" || reuse.Reason != "Run pulumi up" {
		t.Errorf("reuse: under %q, runs %q, reason %q", reuse.Under, reuse.Runs, reuse.Reason)
	}
	if !agentKey.Routine || use.Routine {
		t.Errorf("routine: agent key %v, router %v", agentKey.Routine, use.Routine)
	}
	if !strings.Contains(use.Under, "12:54 approval: Restart dnsmasq on the router") {
		t.Errorf("router key use under %q", use.Under)
	}
}

// A key use says how its key was loaded ("by"); the item's name doesn't matter.
func TestHistoryKeyUseByLoadRoute(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.AuditLog = filepath.Join(t.TempDir(), "audit.jsonl")
	ts := time.Now().Format(time.RFC3339)
	use := func(item, by string) string {
		return `{"time":"` + ts + `","id":"use","event":"key-used","kind":"ssh","refs":["op://Agents/` + item + `/private key"],"by":"` + by + `"}`
	}
	os.WriteFile(e.b.cfg.AuditLog, []byte(use("router key", KeyAutoload)+"\n"+use("laptop key", KeyApproval)+"\n"), 0o600)
	items := e.b.history(10)
	if len(items) != 2 {
		t.Fatalf("got %d items", len(items))
	}
	if laptop, router := items[0], items[1]; !router.Routine || router.Reason != "loaded without approval" || laptop.Routine || laptop.Reason != "approved earlier" {
		t.Errorf("router %v %q, laptop %v %q", router.Routine, router.Reason, laptop.Routine, laptop.Reason)
	}

	// keyUsed writes the route: an autoloaded key (no end) and an approved one (an end)
	e.b.keyUsed(keyMeta{Ref: "op://Agents/a/k", Loaded: time.Now()}, "SHA256:a", nil)
	e.b.keyUsed(keyMeta{Ref: "op://Agents/b/k", Loaded: time.Now(), Until: time.Now().Add(time.Hour)}, "SHA256:b", nil)
	b, _ := os.ReadFile(e.b.cfg.AuditLog)
	if !strings.Contains(string(b), `"by":"autoload"`) || !strings.Contains(string(b), `"by":"approval"`) {
		t.Errorf("audit:\n%s", b)
	}
}

func TestFirstLineHidesTheReason(t *testing.T) {
	for in, want := range map[string]string{
		`opgate ssh-add --reason "Restart dnsmasq on \"router\"" --ttl 15m op://a/b`: `opgate ssh-add --reason … --ttl 15m op://a/b`,
		"opgate run --reason='x y' -- deploy\nnext":                                  "opgate run --reason=… -- deploy …",
		"OPGATE_REASON=why ./x":                                                      "OPGATE_REASON=… ./x",
		"ls -la":                                                                     "ls -la",
	} {
		if got := firstLine(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestPushCmdReadsStepByStep(t *testing.T) {
	tmp := "/private/tmp/claude-501/-Users-me-Development-webapp/a9189031-2b1b-4eab-beef-5bf443cb6193/"
	for in, want := range map[string]string{
		"ssh -o BatchMode=yes -o ConnectTimeout=10 router uptime; nvram get x && echo \"a; b\" | head -2": "ssh router uptime\nnvram get x\n&& echo \"a; b\"\n| head -2",
		"node scripts/pulumi.ts up --plan " + tmp + "plan.json --yes > " + tmp + "up.log 2>&1":            "node scripts/pulumi.ts up --plan …/plan.json --yes > …/up.log 2>&1",
		`/opt/homebrew/bin/opgate ssh-add --reason "why; really" op://Agents/k/private key`:               "opgate ssh-add --reason … op://Agents/k/private key",
		"echo $(date; uptime) > /Users/someone/x.log":                                                     "echo $(date; uptime) > ~/x.log",
		"a\nb\nc\nd\ne\nf\ng":             "a\nb\nc\nd\n… 3 more steps",
		"git commit -m \"title\n\nbody\"": "git commit -m \"title …",
	} {
		if got := pushCmd(in, 5); got != want {
			t.Errorf("%q:\n%s\nwant\n%s", in, got, want)
		}
	}
	if why, _ := splitReason("Run pulumi up --plan " + tmp + "plan.json (runs: x)"); why != "Run pulumi up --plan …/plan.json" {
		t.Errorf("reason: %q", why)
	}
}
