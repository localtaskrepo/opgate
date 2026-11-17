package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secretValue = "s3cr3t-token-value-0123456789"

var testNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.Local)

func fixedProber() *prober {
	p := newProber()
	p.now = func() time.Time { return testNow }
	return p
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func cred(id string, probe *Probe) Cred {
	return Cred{ID: id, Title: id, Tier: "B", Store: "~/.config/x", UsedBy: []string{"test"}, Probe: probe}
}

// ---------- registry validation

func TestValidateRegistryRejectsBadEntries(t *testing.T) {
	for _, c := range []struct {
		name string
		cred Cred
		want string
	}{
		{"tier", Cred{ID: "a", Title: "a", Tier: "C", Store: "x", UsedBy: []string{"y"}}, "tier must be A or B"},
		{"required", Cred{ID: "a", Tier: "B"}, "title, store and used_by are required"},
		{"id", Cred{ID: "a b", Title: "a", Tier: "B", Store: "x", UsedBy: []string{"y"}}, "plain word"},
		{"date", Cred{ID: "a", Title: "a", Tier: "B", Store: "x", UsedBy: []string{"y"}, Expires: "2026-13-01"}, "not YYYY-MM-DD"},
		{"lifespan", Cred{ID: "a", Title: "a", Tier: "B", Store: "x", UsedBy: []string{"y"}, LifespanDays: 365}, "lifespan_days needs created"},
		{"probe type", cred("a", &Probe{Type: "ftp"}), "unknown probe type"},
		{"http url", cred("a", &Probe{Type: "http", Auth: "none"}), "needs url"},
		{"http auth", cred("a", &Probe{Type: "http", URL: "http://x", Auth: "magic"}), "http auth must be"},
		{"http token", cred("a", &Probe{Type: "http", URL: "http://x", Auth: "bearer"}), "needs token_file"},
		{"op ref", cred("a", &Probe{Type: "http", URL: "http://x", Auth: "bearer", TokenFile: "op://Agents/x/y"}), "never read tier A"},
		{"metric", cred("a", &Probe{Type: "metric", URL: "http://vm", Query: "x"}), "needs url, query and max_age"},
		{"command", cred("a", &Probe{Type: "command"}), "needs argv"},
	} {
		err := validateRegistry(Registry{Credentials: []Cred{c.cred}})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	tierA := cred("a", &Probe{Type: "http", URL: "http://x", Auth: "bearer", TokenFile: "~/.config/x"})
	tierA.Tier = "A"
	if err := validateRegistry(Registry{Credentials: []Cred{tierA}}); err == nil || !strings.Contains(err.Error(), "never read tier A") {
		t.Errorf("tier A with an authenticated probe must be refused: %v", err)
	}
	dup := Registry{Credentials: []Cred{cred("a", nil), cred("a", nil)}}
	if err := validateRegistry(dup); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("duplicate: %v", err)
	}
	if err := validateRegistry(Registry{Credentials: []Cred{cred("a", nil), cred("b", &Probe{Type: "tls", Address: "h:443"})}}); err != nil {
		t.Errorf("valid registry refused: %v", err)
	}
}

func TestLoadRegistryRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "r.json", `{"credentials":[{"id":"a","title":"a","tier":"B","store":"x","used_by":["y"],"secret":"no"}]}`)
	if _, err := loadRegistry(p); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown field must be refused (a value pasted into the registry): %v", err)
	}
}

// ---------- probes

func TestHTTPProbe(t *testing.T) {
	dir := t.TempDir()
	tok := writeFile(t, dir, "tok", secretValue+"\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bearer":
			if r.Header.Get("Authorization") != "Bearer "+secretValue {
				w.WriteHeader(401)
			}
		case "/header":
			if r.Header.Get("X-API-Key") != secretValue {
				w.WriteHeader(403)
			}
		case "/template":
			if r.Header.Get("Authorization") != `MediaBrowser Token="`+secretValue+`"` {
				w.WriteHeader(401)
			}
		case "/basic":
			if u, p, ok := r.BasicAuth(); !ok || u != "joplin" || p != secretValue {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(207)
		case "/broken":
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	pr := fixedProber()
	for _, c := range []struct {
		probe Probe
		valid *bool
	}{
		{Probe{Type: "http", URL: srv.URL + "/bearer", Auth: "bearer", TokenFile: tok}, boolp(true)},
		{Probe{Type: "http", URL: srv.URL + "/header", Auth: "header:X-API-Key", TokenFile: tok}, boolp(true)},
		{Probe{Type: "http", URL: srv.URL + "/template", Auth: `header:Authorization:MediaBrowser Token="{value}"`, TokenFile: tok}, boolp(true)},
		{Probe{Type: "http", URL: srv.URL + "/basic", Auth: "basic:joplin", TokenFile: tok, Expect: []int{207}}, boolp(true)},
		{Probe{Type: "http", URL: srv.URL + "/bearer", Auth: "header:X-API-Key", TokenFile: tok}, boolp(false)}, // 401
		{Probe{Type: "http", URL: srv.URL + "/broken", Auth: "none"}, nil},                                      // 500: unknown
		{Probe{Type: "http", URL: srv.URL + "/bearer", Auth: "bearer", TokenFile: filepath.Join(dir, "missing")}, boolp(false)},
	} {
		f := pr.run(t.Context(), cred("x", &c.probe))
		if (f.Valid == nil) != (c.valid == nil) || (f.Valid != nil && *f.Valid != *c.valid) {
			t.Errorf("%s %s: valid %v, want %v (%s)", c.probe.URL, c.probe.Auth, f.Valid, c.valid, f.Detail)
		}
		if strings.Contains(f.Detail, secretValue) {
			t.Errorf("detail shows the value: %s", f.Detail)
		}
	}
}

func TestTLSProbeReadsExpiry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	pr := fixedProber()
	pr.roots = x509.NewCertPool()
	pr.roots.AddCert(srv.Certificate())
	addr := strings.TrimPrefix(srv.URL, "https://")
	f := pr.run(t.Context(), cred("cert", &Probe{Type: "tls", Address: addr, ServerName: "example.com"}))
	if f.Valid == nil || !*f.Valid || !f.Expires.Equal(srv.Certificate().NotAfter) {
		t.Errorf("valid %v expires %v (want %v): %s", f.Valid, f.Expires, srv.Certificate().NotAfter, f.Detail)
	}
	pr.roots = x509.NewCertPool() // untrusted
	if f = pr.run(t.Context(), cred("cert", &Probe{Type: "tls", Address: addr, ServerName: "example.com"})); f.Valid == nil || *f.Valid {
		t.Errorf("an untrusted certificate must be invalid: %+v", f)
	}
}

func TestRDAPProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/domain/example.net" {
			fmt.Fprint(w, `{"events":[{"eventAction":"registration","eventDate":"2010-01-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2027-04-25T10:00:00Z"}]}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	old := rdapBase
	rdapBase = srv.URL + "/domain/"
	defer func() { rdapBase = old }()
	pr := fixedProber()
	f := pr.run(t.Context(), cred("d", &Probe{Type: "rdap", Domain: "example.net"}))
	if f.Expires.Format("2006-01-02") != "2027-04-25" || f.Valid != nil {
		t.Errorf("got %+v", f)
	}
	if f = pr.run(t.Context(), cred("d", &Probe{Type: "rdap", Domain: "other.example"})); !f.Expires.IsZero() || !strings.Contains(f.Detail, "404") {
		t.Errorf("missing domain: %+v", f)
	}
}

func TestGrafanaServiceAccountProbe(t *testing.T) {
	dir := t.TempDir()
	pw := writeFile(t, dir, "pw", secretValue)
	exp1, exp2 := "2027-01-01T00:00:00Z", "2027-11-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != secretValue {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/serviceaccounts/search":
			fmt.Fprint(w, `{"serviceAccounts":[{"id":3,"name":"mac-agents"},{"id":4,"name":"mac-agents-old"},{"id":5,"name":"off","isDisabled":true}]}`)
		case "/api/serviceaccounts/3/tokens":
			fmt.Fprintf(w, `[{"name":"old","expiration":%q,"lastUsedAt":"2026-11-02T08:00:00Z"},{"name":"new","expiration":%q,"lastUsedAt":"2026-11-01T08:00:00Z"},{"name":"dead","expiration":"2026-01-01T00:00:00Z","hasExpired":true}]`, exp1, exp2)
		case "/api/serviceaccounts/5/tokens":
			fmt.Fprint(w, `[]`)
		}
	}))
	defer srv.Close()
	pr := fixedProber()
	f := pr.run(t.Context(), cred("g", &Probe{Type: "grafana_sa", URL: srv.URL, Account: "mac-agents", PasswordFile: pw}))
	if f.Valid == nil || !*f.Valid || f.Expires.Format(time.RFC3339) != exp2 || f.LastUsed.Format("2006-01-02") != "2026-11-02" {
		t.Errorf("got %+v", f)
	}
	if f = pr.run(t.Context(), cred("g", &Probe{Type: "grafana_sa", URL: srv.URL, Account: "off", PasswordFile: pw})); f.Valid == nil || *f.Valid {
		t.Errorf("disabled account must be invalid: %+v", f)
	}
	if f = pr.run(t.Context(), cred("g", &Probe{Type: "grafana_sa", URL: srv.URL, Account: "nobody", PasswordFile: pw})); f.Valid == nil || *f.Valid {
		t.Errorf("missing account must be invalid: %+v", f)
	}
	wrong := writeFile(t, dir, "wrong", "nope")
	if f = pr.run(t.Context(), cred("g", &Probe{Type: "grafana_sa", URL: srv.URL, Account: "mac-agents", PasswordFile: wrong})); f.Valid != nil {
		t.Errorf("a failed admin login says nothing about the token: %+v", f)
	}
}

func TestMetricProbe(t *testing.T) {
	var value string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value == "" {
			fmt.Fprint(w, `{"data":{"result":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"data":{"result":[{"metric":{},"value":[1,%q]}]}}`, value)
	}))
	defer srv.Close()
	pr := fixedProber()
	p := &Probe{Type: "metric", URL: srv.URL, Query: "x", MaxAge: Duration{48 * time.Hour}}
	value = fmt.Sprint(testNow.Add(-2 * time.Hour).Unix())
	if f := pr.run(t.Context(), cred("m", p)); f.Valid == nil || !*f.Valid || f.LastUsed.Unix() != testNow.Add(-2*time.Hour).Unix() {
		t.Errorf("fresh: %+v", f)
	}
	value = fmt.Sprint(testNow.Add(-72 * time.Hour).Unix())
	if f := pr.run(t.Context(), cred("m", p)); f.Valid == nil || *f.Valid {
		t.Errorf("stale must be invalid: %+v", f)
	}
	value = "0"
	if f := pr.run(t.Context(), cred("m", p)); f.Valid == nil || *f.Valid {
		t.Errorf("never succeeded must be invalid: %+v", f)
	}
	value = ""
	if f := pr.run(t.Context(), cred("m", p)); f.Valid != nil {
		t.Errorf("no data is unknown, not invalid: %+v", f)
	}
	value = "soon"
	if f := pr.run(t.Context(), cred("m", p)); f.Valid != nil || !strings.Contains(f.Detail, "not a timestamp") {
		t.Errorf("a value that is no number is unknown, not invalid: %+v", f)
	}
}

func TestCommandProbe(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "good.sh", `#!/bin/sh
echo "`+secretValue+`" >&2
echo '{"valid": true, "expires": "2027-02-03", "last_used": "2026-11-01T10:00:00Z", "detail": "ok"}'`)
	bad := writeFile(t, dir, "bad.sh", "#!/bin/sh\necho not json\n")
	fail := writeFile(t, dir, "fail.sh", "#!/bin/sh\nexit 3\n")
	slow := writeFile(t, dir, "slow.sh", "#!/bin/sh\nsleep 5\n")
	for _, p := range []string{good, bad, fail, slow} {
		os.Chmod(p, 0o700)
	}
	pr := fixedProber()
	f := pr.run(t.Context(), cred("c", &Probe{Type: "command", Argv: []string{good}}))
	if f.Valid == nil || !*f.Valid || f.Expires.Format("2006-01-02") != "2027-02-03" || f.LastUsed.IsZero() {
		t.Errorf("good: %+v", f)
	}
	if strings.Contains(f.Detail, secretValue) {
		t.Error("stderr leaked into the detail")
	}
	if f = pr.run(t.Context(), cred("c", &Probe{Type: "command", Argv: []string{bad}})); f.Valid != nil || !strings.Contains(f.Detail, "not JSON") {
		t.Errorf("bad: %+v", f)
	}
	if f = pr.run(t.Context(), cred("c", &Probe{Type: "command", Argv: []string{fail}})); f.Valid != nil || !strings.Contains(f.Detail, "failed") {
		t.Errorf("fail: %+v", f)
	}
	start := time.Now()
	if f = pr.run(t.Context(), cred("c", &Probe{Type: "command", Argv: []string{slow}, Timeout: Duration{300 * time.Millisecond}})); f.Valid != nil || time.Since(start) > 3*time.Second {
		t.Errorf("timeout: %+v after %s", f, time.Since(start))
	}
}

// ---------- opgate usage and evaluation

func TestAuditUses(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"time":"2026-11-02T09:00:00-08:00","event":"granted","refs":["op://Agents/Cloudflare DNS token/credential"]}`,
		`{"time":"2026-11-03T09:00:00-08:00","event":"asked","refs":["op://Agents/Cloudflare DNS token/credential"]}`,
		`{"time":"2026-11-03T08:00:00-08:00","event":"denied","refs":["op://Agents/Cloudflare DNS token/credential"]}`,
		`{"time":"2026-09-01T09:00:00-08:00","event":"key-used","refs":["op://Agents/opgate server key/private key"]}`,
		`{"time":"2026-11-01T09:00:00-08:00","event":"routed","refs":["op://Agents/App oauth2.txt?document"]}`,
		`{"time":"2026-11-01T10:00:00-08:00","event":"approved","refs":["op://Agents/Backup bucket S3/access key id"]}`,
		`not json`,
	}
	p := writeFile(t, dir, "audit.jsonl", strings.Join(lines, "\n")+"\n")
	u := auditUses(p, testNow)
	cf := u[refKey("op://Agents/Cloudflare DNS token")]
	if cf.Count != 1 || cf.Last.Format("2006-01-02") != "2026-11-02" {
		t.Errorf("asked/denied must not count as uses: %+v", cf)
	}
	if r := u[refKey("op://Agents/opgate server key")]; r.Count != 0 || r.Last.IsZero() {
		t.Errorf("old use: last kept, not counted in 30 days: %+v", r)
	}
	if u[refKey("op://Agents/App oauth2.txt")].Count != 1 {
		t.Error("document refs normalize to the item")
	}
	if u[refKey("op://Agents/Backup bucket (S3)/access key id")].Count != 1 {
		t.Error("a use without the parentheses should count for the item with them")
	}
	if len(auditUses(filepath.Join(dir, "missing"), testNow)) != 0 {
		t.Error("a missing audit log is no uses")
	}
}

func TestEvaluateStatusAndSources(t *testing.T) {
	uses := map[string]struct {
		Last  time.Time
		Count int
	}{refKey("op://Agents/item"): {testNow.Add(-time.Hour), 4}}
	declared := Cred{ID: "d", Tier: "A", Store: "op://Agents/item/credential", Expires: "2026-11-20", Created: "2026-01-01", LifespanDays: 30}
	for _, c := range []struct {
		name   string
		cred   Cred
		f      Finding
		status string
		src    string
	}{
		{"invalid beats expiry", declared, Finding{Valid: boolp(false)}, "invalid", "declared"},
		{"declared expiring", declared, Finding{}, "expiring", "declared"},
		{"probe expiry wins", declared, Finding{Expires: testNow.AddDate(1, 0, 0)}, "ok", "probe"},
		{"expired", declared, Finding{Expires: testNow.Add(-time.Minute)}, "expired", "probe"},
		{"lifespan", Cred{ID: "l", Tier: "B", Store: "x", Created: "2026-10-01", LifespanDays: 365}, Finding{}, "ok", "lifespan"},
		{"lifespan ran out", Cred{ID: "l", Tier: "B", Store: "x", Created: "2025-10-01", LifespanDays: 365}, Finding{}, "expired", "lifespan"},
		{"unknown", Cred{ID: "u", Tier: "B", Store: "x"}, Finding{}, "unknown", ""},
		{"valid only", Cred{ID: "v", Tier: "B", Store: "x"}, Finding{Valid: boolp(true)}, "ok", ""},
		{"warn days", Cred{ID: "w", Tier: "B", Store: "x", Expires: "2027-01-15", WarnDays: 90}, Finding{}, "expiring", "declared"},
	} {
		r := evaluate(c.cred, c.f, uses, testNow)
		if r.Status != c.status || r.ExpiresSrc != c.src {
			t.Errorf("%s: status %s src %s, want %s %s", c.name, r.Status, r.ExpiresSrc, c.status, c.src)
		}
	}
	r := evaluate(declared, Finding{LastUsed: testNow.Add(-48 * time.Hour)}, uses, testNow)
	if r.LastSrc != "opgate" || r.Uses30d != 4 {
		t.Errorf("the newer opgate use must win: %+v", r)
	}
	r = evaluate(declared, Finding{LastUsed: testNow.Add(-time.Minute)}, uses, testNow)
	if r.LastSrc != "probe" {
		t.Errorf("a newer probe use must win: %+v", r)
	}
}

func TestCheckAllWithoutProbes(t *testing.T) {
	reg := Registry{Credentials: []Cred{cred("a", nil), {ID: "b", Title: "b", Tier: "B", Store: "x", UsedBy: []string{"y"}, Expires: "2030-01-01"}}}
	reports := checkAll(t.Context(), reg, fixedProber(), filepath.Join(t.TempDir(), "none"))
	if reports[0].Status != "unknown" || reports[1].Status != "ok" || reports[0].ID != "a" {
		t.Errorf("order or status wrong: %+v", reports)
	}
}

// ---------- outputs

func TestMetricsText(t *testing.T) {
	reports := []Report{
		{ID: "a", Tier: "B", Status: "ok", Expires: time.Unix(2000, 0), LastUsed: time.Unix(1000, 0)},
		{ID: "b", Tier: "A", Status: "unknown"},
	}
	text := metricsText(reports, time.Unix(3000, 0))
	for _, want := range []string{
		`opgate_credential_status{id="a",tier="B"} 0`,
		`opgate_credential_expiry_timestamp_seconds{id="a",tier="B"} 2000`,
		`opgate_credential_last_used_timestamp_seconds{id="a",tier="B"} 1000`,
		`opgate_credential_status{id="b",tier="A"} -1`,
		`opgate_creds_last_run_timestamp_seconds 3000`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, `expiry_timestamp_seconds{id="b"`) {
		t.Error("no expiry line without an expiry")
	}
}

func TestPushMetrics(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/import/prometheus" {
			w.WriteHeader(404)
			return
		}
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	if err := pushMetrics(t.Context(), http.DefaultClient, srv.URL+"/", "x 1\n"); err != nil || got != "x 1\n" {
		t.Errorf("push: %v %q", err, got)
	}
	if err := pushMetrics(t.Context(), http.DefaultClient, srv.URL+"/nope", "x 1\n"); err == nil {
		t.Error("a failed import must be an error")
	}
}

func TestLogChangesOnlyLogsChanges(t *testing.T) {
	dir := t.TempDir()
	logp, state := filepath.Join(dir, "creds.jsonl"), filepath.Join(dir, "state.json")
	r1 := []Report{{ID: "a", Status: "ok", Expires: time.Unix(2000000000, 0)}, {ID: "b", Status: "unknown"}}
	if n, err := logChanges(logp, state, r1, testNow); err != nil || n != 2 {
		t.Fatalf("first run logs everything: %d %v", n, err)
	}
	if n, _ := logChanges(logp, state, r1, testNow); n != 0 {
		t.Errorf("unchanged run logged %d lines", n)
	}
	r2 := []Report{{ID: "a", Status: "expiring", Expires: time.Unix(2000000000, 0)}}
	if n, _ := logChanges(logp, state, r2, testNow); n != 2 { // a changed, b removed
		t.Errorf("change + removal: %d", n)
	}
	b, _ := os.ReadFile(logp)
	if !strings.Contains(string(b), `"status":"removed"`) || !strings.Contains(string(b), `"previous":"ok `) {
		t.Errorf("log content:\n%s", b)
	}
	if st, _ := os.Stat(logp); st.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v", st.Mode().Perm())
	}
}

func TestCompareLifecycle(t *testing.T) {
	dir := t.TempDir()
	csv := writeFile(t, dir, "lifecycle.csv", "id,title,last_done,interval_days,due,warn_days,auto,how\n"+
		"good,t,,,2027-11-01,30,no,x\nbad,t,,,2027-06-01,30,no,x\nempty,t,,,,30,no,x\n"+
		"interval,t,2026-11-01,365,,30,no,x\n")
	exp := time.Date(2027, 11, 1, 0, 0, 0, 0, time.Local)
	reports := []Report{
		{ID: "a", Cred: Cred{Lifecycle: "good"}, Expires: exp},
		{ID: "b", Cred: Cred{Lifecycle: "bad"}, Expires: exp, ExpiresSrc: "probe"},
		{ID: "c", Cred: Cred{Lifecycle: "empty"}, Expires: exp},
		{ID: "d", Cred: Cred{Lifecycle: "missing"}, Expires: exp},
		{ID: "e", Cred: Cred{Lifecycle: "good"}},                   // no expiry: nothing to compare
		{ID: "f", Cred: Cred{Lifecycle: "interval"}, Expires: exp}, // last_done + interval = 2027-11-01: matches
	}
	out, err := compareLifecycle(csv, reports)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(out, "\n")
	if len(out) != 3 || !strings.Contains(joined, "b: calendar row bad is due 2027-06-01") ||
		!strings.Contains(joined, "c: calendar row empty has no due date") || !strings.Contains(joined, "d: calendar row missing does not exist") {
		t.Errorf("got:\n%s", joined)
	}
}

// ---------- the command end to end

func TestCredsMainEndToEnd(t *testing.T) {
	dir := t.TempDir()
	tok := writeFile(t, dir, "tok", secretValue)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secretValue {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	reg := Registry{Credentials: []Cred{
		{ID: "api", Title: "API token", Tier: "B", Store: tok, UsedBy: []string{"scripts/x.py"}, Rotate: "skills/x.md",
			Probe: &Probe{Type: "http", URL: srv.URL, Auth: "bearer", TokenFile: tok}},
		{ID: "wrong", Title: "Wrong token", Tier: "B", Store: "x", UsedBy: []string{"y"},
			Probe: &Probe{Type: "http", URL: srv.URL, Auth: "header:X-API-Key", TokenFile: tok}},
		{ID: "tierA", Title: "Tier A", Tier: "A", Store: "op://Agents/cf/credential", UsedBy: []string{"z"}, Expires: "2026-11-10"},
	}}
	b, _ := json.Marshal(reg)
	regPath := writeFile(t, dir, "credentials.json", string(b))
	writeFile(t, dir, "audit.jsonl", `{"time":"2026-11-02T09:00:00-08:00","event":"granted","refs":["op://Agents/cf/credential"]}`+"\n")
	t.Setenv("OPGATE_CREDS_DIR", dir)
	old := credsNow
	credsNow = func() time.Time { return testNow }
	defer func() { credsNow = old }()

	out, code := capture(t, func() int { return credsMain([]string{"--json", "--file", regPath}) })
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, secretValue) {
		t.Fatal("the value appears in the output")
	}
	var reports []Report
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, r := range reports {
		got[r.ID] = r.Status
	}
	if got["api"] != "ok" || got["wrong"] != "invalid" || got["tierA"] != "expiring" {
		t.Errorf("statuses %v", got)
	}
	if reports[2].LastSrc != "opgate" {
		t.Errorf("tier A last use should come from the audit log: %+v", reports[2])
	}
	logb, _ := os.ReadFile(filepath.Join(dir, "creds.jsonl"))
	if strings.Count(string(logb), "\n") != 3 || bytes.Contains(logb, []byte(secretValue)) {
		t.Errorf("change log:\n%s", logb)
	}
	// the overview page's snapshot: every credential, no value, the facts `show` prints
	snapb, _ := os.ReadFile(filepath.Join(dir, "creds-latest.json"))
	snap, err := readSnapshot(filepath.Join(dir, "creds-latest.json"))
	if err != nil || len(snap.Credentials) != 3 || bytes.Contains(snapb, []byte(secretValue)) || !snap.Time.Equal(testNow) {
		t.Fatalf("snapshot (%v):\n%s", err, snapb)
	}
	if c := snap.Credentials[0]; c.ID != "api" || c.Status != "ok" || c.Rotate != "skills/x.md" || c.UsedBy[0] != "scripts/x.py" || c.Title != "API token" {
		t.Errorf("snapshot entry %+v", c)
	}
	if st, _ := os.Stat(filepath.Join(dir, "creds-latest.json")); st.Mode().Perm() != 0o600 {
		t.Errorf("snapshot mode %v", st.Mode())
	}

	out, code = capture(t, func() int { return credsMain([]string{"show", "api", "--file", regPath}) })
	if code != 0 || !strings.Contains(out, "rotate   skills/x.md") || !strings.Contains(out, "used by  scripts/x.py") || strings.Contains(out, secretValue) {
		t.Errorf("show (%d):\n%s", code, out)
	}
	out, code = capture(t, func() int { return credsMain([]string{"unused", "2", "--file", regPath}) })
	if code != 0 || !strings.Contains(out, "api") || strings.Contains(out, "tierA ") {
		t.Errorf("unused (%d):\n%s", code, out)
	}
	if _, code = capture(t, func() int { return credsMain([]string{"show", "nope", "--file", regPath}) }); code != 1 {
		t.Errorf("unknown id: exit %d", code)
	}
	out, code = capture(t, func() int { return credsMain([]string{"validate", "--file", regPath}) })
	if code != 0 || !strings.Contains(out, "3 credentials") {
		t.Errorf("validate (%d): %s", code, out)
	}
}

// Without a registry in the build (credsReg) opgate creds is off; with one, a ~/ path is the user's home.
func TestCredsRegistryBuildValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("OPGATE_CREDS_DIR", dir)
	saved := credsReg
	t.Cleanup(func() { credsReg = saved })
	credsReg = ""
	if _, code := capture(t, func() int { return credsMain([]string{"validate"}) }); code != 1 {
		t.Errorf("no registry: exit %d", code)
	}
	writeFile(t, dir, "reg.json", `{"credentials":[]}`)
	credsReg = "~/reg.json"
	if out, code := capture(t, func() int { return credsMain([]string{"validate"}) }); code != 0 || !strings.Contains(out, "0 credentials") {
		t.Errorf("registry from the build (%d): %s", code, out)
	}
}

// capture runs fn with stdout redirected and returns what it printed.
func capture(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := fn()
	w.Close()
	os.Stdout = old
	return <-done, code
}

func TestWaitReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	if !waitReachable(t.Context(), addr, time.Second) {
		t.Error("a listening server is not reachable")
	}
	srv.Close()
	start := time.Now()
	if waitReachable(t.Context(), addr, 500*time.Millisecond) || time.Since(start) > 10*time.Second {
		t.Error("a closed port counted as reachable, or the wait ignored its limit")
	}
	if waitReachable(t.Context(), "not a url", time.Second) {
		t.Error("garbage URL reachable")
	}
}
