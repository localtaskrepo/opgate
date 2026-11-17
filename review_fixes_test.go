package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Another local process sees an enrollment's ID (opgate status), but without the link's key it can't register.
func TestEnrollNeedsTheLinkKey(t *testing.T) {
	e := newEnv(t)
	r, err := e.b.Submit(RequestIn{Kind: KindEnroll, Name: "phone"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.b.URL(r), "?k="+r.enrollKey) || r.enrollKey == "" {
		t.Fatalf("enroll link without its key: %s", e.b.URL(r))
	}
	for _, q := range []string{"", "?k=", "?k=wrong"} {
		if code, _ := e.post("/enroll/"+r.ID+"/options"+q, nil); code != http.StatusNotFound {
			t.Errorf("options%s: %d", q, code)
		}
		if _, page := e.getPage("/enroll/" + r.ID + q); !strings.Contains(page, "Nothing to decide") {
			t.Errorf("page%s shows the enrollment", q)
		}
	}
	if code, _ := e.post("/enroll/"+r.ID+"/options?k="+r.enrollKey, nil); code != 200 {
		t.Errorf("with the key: %d", code)
	}
}

// A same-again reuse whose secret can't be read is an error, not a use (and no use notice).
func TestFailedReuseIsAnError(t *testing.T) {
	e := overviewEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	if code, body := e.approve(a, r, "15m", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	e.b.Wait(context.Background(), r)
	e.store.mu.Lock()
	delete(e.store.v, "op://Agents/Cloudflare/credential")
	e.store.mu.Unlock()
	before := len(e.note.done)
	r2 := e.ask(cfReq)
	if res := e.b.Wait(context.Background(), r2); res.Status != "error" {
		t.Fatalf("reuse result %+v", res)
	}
	if len(e.note.done) != before {
		t.Errorf("use notice for a reuse that delivered nothing: %v", e.note.done[before:])
	}
	log, _ := os.ReadFile(e.b.cfg.AuditLog)
	if strings.Count(string(log), `"event":"granted"`) != 0 || !strings.Contains(string(log), `"event":"error"`) {
		t.Errorf("audit:\n%s", log)
	}
}

// Revoking the notice of an expired grant must not end a newer grant for the same thing.
func TestRevokeOldGrantKeepsNewer(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	e.approve(a, r, "15m", 0x05)
	e.b.Wait(context.Background(), r)
	reuse := e.ask(cfReq) // a use: creates the grant's activity
	e.b.Wait(context.Background(), reuse)
	var old Activity
	e.b.mu.Lock()
	for _, act := range e.b.activity {
		old = *act
	}
	k := grantKey(r)
	e.b.grants[k].Until = e.b.grants[k].Until.Add(time.Hour) // stands for a newer approval of the same request
	e.b.mu.Unlock()
	if _, _, err := e.b.Revoke(old.Tag, false); err != nil {
		t.Fatal(err)
	}
	e.b.mu.Lock()
	_, still := e.b.grants[k]
	e.b.mu.Unlock()
	if !still {
		t.Error("revoking the old notice ended the newer grant")
	}
}

// A malformed audit line (any process can write the file) must not take the pages down.
func TestMalformedAuditLine(t *testing.T) {
	e := overviewEnv(t)
	long := strings.Repeat("x", 3<<20) // longer than any scanner buffer
	lines := []string{`{"id":"x","event":"asked","kind":"ssh"}`, `{"id":"y","event":"asked","kind":"restore"}`,
		fmt.Sprintf(`{"time":%q,"id":"big","event":"asked","kind":"secrets","refs":["op://Agents/a/b"],"reason":%q}`, time.Now().Format(time.RFC3339), long),
		fmt.Sprintf(`{"time":%q,"id":"after","event":"asked","kind":"secrets","refs":["op://Agents/After/b"],"reason":"after the long line"}`, time.Now().Format(time.RFC3339))}
	os.WriteFile(e.b.cfg.AuditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	for _, p := range []string{"/", "/history"} {
		code, page := e.getPage(p)
		if code != 200 {
			t.Fatalf("%s: %d", p, code)
		}
		if p == "/history" && !strings.Contains(page, "after the long line") {
			t.Error("the history stopped at the long line")
		}
	}
}

// New lines can't get that long: reason and command lines are capped.
func TestAuditCapsLines(t *testing.T) {
	dir := t.TempDir()
	a := &Audit{path: filepath.Join(dir, "audit.jsonl")}
	a.Log(&Request{RequestIn: RequestIn{Kind: KindSecrets, Reason: strings.Repeat("r", 5000)}, ID: "x",
		Caller: []string{strings.Repeat("c", 100000)}}, "asked", "", "")
	if st, _ := os.Stat(a.path); st.Size() > 8000 {
		t.Errorf("audit line %d bytes", st.Size())
	}
	e := newEnv(t)
	if _, err := e.b.Submit(RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/a/b"}, Reason: strings.Repeat("why ", 400)}, nil); err == nil {
		t.Error("a 1600-character reason was accepted")
	}
}

// A typo in config.json (agents can write it) keeps the defaults instead of stopping opgate.
func TestBrokenConfigKeepsDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".config/opgate"), 0o700)
	os.WriteFile(filepath.Join(home, ".config/opgate/config.json"), []byte(`{"away_idle": "2m",`), 0o600)
	c, err := loadConfig()
	if err != nil || c.AwayIdle.Duration != defaultConfig().AwayIdle.Duration {
		t.Errorf("config %v, %v", c.AwayIdle, err)
	}
}

// The passkey list is read once a minute at most, and again right after a failed check.
func TestPasskeyCache(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	e.b.passkeyCache = time.Minute
	if _, err := e.b.passkeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.store.set("op://Agents/opgate/passkeys", "not json")
	if _, err := e.b.passkeys(context.Background()); err != nil {
		t.Error("read again within the minute")
	}
	e.b.dropPasskeys()
	if _, err := e.b.passkeys(context.Background()); err == nil {
		t.Error("cache not dropped")
	}
}

// One pending restore per revoked key, however often the page asks.
func TestRestoreOncePerKey(t *testing.T) {
	e := newEnv(t)
	ref := "op://Agents/opgate build key/private key"
	e.b.revokedRefs[ref] = true
	r1, err := e.b.requestRestore(ref)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := e.b.requestRestore(ref)
	if r1 != r2 || len(e.b.Pending()) != 1 {
		t.Errorf("restore asked %d times", len(e.b.Pending()))
	}
}

func TestScriptArgShellFlagClusters(t *testing.T) {
	for args, want := range map[string][2]string{
		"bash -lc ./run.sh && opgate read x": {}, "zsh -c foo": {}, "bash -x deploy.sh": {"deploy.sh"},
		"python3 -m http.server": {}, "bash --login run.sh": {"run.sh"},
		"node pulumi.ts --yes up": {"pulumi.ts", "\x00--yes up"}, "bash deploy.sh --dry-run": {"deploy.sh", "\x00--dry-run"},
	} {
		if s, sub := scriptArg(args); s != want[0] || sub != want[1] {
			t.Errorf("scriptArg(%q) = %q, %q, want %q", args, s, sub, want)
		}
	}
}

// Failed and blocked reads (Touch ID refused, nobody at the Mac) released nothing: no use.
func TestAuditUsesSkipsFailedRoutes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	os.WriteFile(p, []byte(`{"time":"2026-11-02T09:00:00-08:00","event":"routed","by":"1password-failed","refs":["op://Agents/X/c"]}
{"time":"2026-11-02T09:00:00-08:00","event":"routed","by":"op-away","refs":["op://Agents/X/c"]}
`), 0o600)
	if u := auditUses(p, testNow)[refKey("op://Agents/X")]; u.Count != 0 || !u.Last.IsZero() {
		t.Errorf("failed reads counted: %+v", u)
	}
}

// Probes answer with the first response: a redirect would carry custom auth headers elsewhere.
func TestProbesDontFollowRedirects(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = r.Header.Get("X-API-Key") != "" }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tok, []byte("secret"), 0o600)
	newProber().http(t.Context(), &Probe{Type: "http", URL: srv.URL, Auth: "header:X-API-Key", TokenFile: tok})
	if hit {
		t.Error("the probe followed the redirect with its API key")
	}
}
