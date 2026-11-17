package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Markers that may only appear on an unlocked overview page.
var hiddenFacts = []string{"STORE-op://Agents/Hidden", "USED-BY-marker", "ROTATE-marker", "REVOKE-marker", "PROBE-DETAIL-marker", "SCOPE-marker"}

// overviewEnv is newEnv with the snapshot and the audit log in temp folders.
func overviewEnv(t *testing.T) *env {
	e := newEnv(t)
	dir := t.TempDir()
	e.b.cfg.Socket = filepath.Join(dir, "opgate.sock")
	e.b.cfg.AuditLog = filepath.Join(dir, "audit.jsonl")
	e.b.audit = &Audit{path: e.b.cfg.AuditLog}
	return e
}

func writeTestSnapshot(t *testing.T, e *env, at time.Time) {
	reports := []Report{
		{Cred: Cred{ID: "broken", Title: "Broken token", Tier: "B", Store: hiddenFacts[0], UsedBy: []string{hiddenFacts[1]},
			Rotate: hiddenFacts[2], Revoke: hiddenFacts[3], Scope: hiddenFacts[5]}, ID: "broken", Tier: "B", Status: "invalid", Detail: hiddenFacts[4]},
		{Cred: Cred{ID: "soon", Title: "Soon token", Tier: "B", Store: "~/.config/x"}, ID: "soon", Tier: "B", Status: "expiring",
			Expires: at.Add(10 * 24 * time.Hour)},
		{Cred: Cred{ID: "fine", Title: "Fine token", Tier: "A", Store: "op://Agents/Fine/credential"}, ID: "fine", Tier: "A", Status: "ok",
			LastUsed: at.Add(-40 * 24 * time.Hour), LastSrc: "opgate"},
		{Cred: Cred{ID: "used", Title: "Used token", Tier: "A", Store: "op://Agents/Used/credential"}, ID: "used", Tier: "A", Status: "unknown",
			LastUsed: at.Add(-2 * 24 * time.Hour), LastSrc: "opgate"},
	}
	if err := writeSnapshot(snapshotPath(e.b.cfg), reports, at); err != nil {
		t.Fatal(err)
	}
}

func (e *env) getPage(path string, cookies ...*http.Cookie) (int, string) {
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

// unlock runs the passkey check like the page does and returns the response's cookies.
func (e *env) unlock(a *authenticator, flags byte) (int, string, []*http.Cookie) {
	code, opts := e.post("/unlock/options", nil)
	if code != 200 {
		return code, string(opts), nil
	}
	var o struct {
		ID string `json:"id"`
	}
	json.Unmarshal(opts, &o)
	resp, err := http.Post(e.srv.URL+"/unlock/finish?id="+o.ID, "application/json", bytes.NewReader(a.get(opts, flags)))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String(), resp.Cookies()
}

func TestOverviewLockedHidesCredentialDetails(t *testing.T) {
	e := overviewEnv(t)
	writeTestSnapshot(t, e, time.Now().Add(-time.Hour))
	code, page := e.getPage("/")
	if code != 200 {
		t.Fatalf("overview: %d", code)
	}
	for _, s := range []string{"Broken token: invalid", "Soon token: expires", "Fine token", "Unlock with passkey", "checked 60 min ago"} {
		if !strings.Contains(page, s) {
			t.Errorf("overview lacks %q", s)
		}
	}
	for _, s := range hiddenFacts {
		if strings.Contains(page, s) || strings.Contains(page, template_escape(s)) {
			t.Errorf("locked overview shows %q", s)
		}
	}
	// problems first, then by title; the unused list has only 1Password items without a use in 30 days
	if strings.Index(page, "Broken token") > strings.Index(page, "Fine token") || !strings.Contains(page, `id="cred-broken"`) || strings.Contains(page, `id="cred-fine"`) {
		t.Error("problems are not listed first")
	}
	unused := page[strings.Index(page, "no known use in 30 days"):]
	if !strings.Contains(unused, "Fine token") || strings.Contains(unused, "Used token") || strings.Contains(unused, "Soon token") {
		t.Errorf("unused list wrong:\n%s", unused[:min(len(unused), 800)])
	}
}

// template_escape is how html/template writes s into the page.
func template_escape(s string) string {
	return strings.NewReplacer("/", "&#x2F;", "+", "&#43;").Replace(s)
}

func TestUnlockShowsDetailsForTenMinutes(t *testing.T) {
	e := overviewEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	writeTestSnapshot(t, e, time.Now())
	code, body, cookies := e.unlock(a, 0x05)
	if code != 200 || len(cookies) != 1 {
		t.Fatalf("unlock: %d %s %v", code, body, cookies)
	}
	c := cookies[0]
	if c.Name != viewCookie || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 600 || len(c.Value) != 64 {
		t.Fatalf("cookie %+v", c)
	}
	_, page := e.getPage("/", c)
	for _, s := range hiddenFacts {
		if !strings.Contains(page, s) && !strings.Contains(page, template_escape(s)) {
			t.Errorf("unlocked overview lacks %q", s)
		}
	}
	if !strings.Contains(page, "Details unlocked until") {
		t.Error("no unlocked bar")
	}
	// the unlock is in the audit log and the history
	found := false
	for _, l := range auditEvents(t, e.b.cfg.AuditLog) {
		if l.Event == "unlocked" && l.By == "test" {
			found = true
		}
	}
	if !found {
		t.Error("unlock not audited")
	}
	if _, hist := e.getPage("/history"); !strings.Contains(hist, "Credential details") {
		t.Error("unlock not in the history")
	}
	// a made-up token, and the real one after 10 minutes, are locked
	if _, p := e.getPage("/", &http.Cookie{Name: viewCookie, Value: strings.Repeat("a", 64)}); strings.Contains(p, hiddenFacts[2]) {
		t.Error("a made-up token unlocked the details")
	}
	e.b.now = func() time.Time { return time.Now().Add(viewFor + time.Second) }
	if _, p := e.getPage("/", c); strings.Contains(p, hiddenFacts[2]) {
		t.Error("the unlock outlived 10 minutes")
	}
	e.b.now = time.Now
	// lock ends it at once
	req, _ := http.NewRequest("POST", e.srv.URL+"/lock", nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, p := e.getPage("/", c); strings.Contains(p, hiddenFacts[2]) {
		t.Error("still unlocked after Lock")
	}
}

func TestUnlockRefusals(t *testing.T) {
	e := overviewEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	writeTestSnapshot(t, e, time.Now())

	if code, _, cookies := e.unlock(a, 0x01); code == 200 || len(cookies) != 0 {
		t.Errorf("unlocked without user verification: %d", code)
	}
	stranger := newAuthenticator("approve.example")
	if code, _, cookies := e.unlock(stranger, 0x05); code == 200 || len(cookies) != 0 {
		t.Errorf("an unknown passkey unlocked: %d", code)
	}
	// each attempt counts once
	code, opts := e.post("/unlock/options", nil)
	if code != 200 {
		t.Fatal(string(opts))
	}
	var o struct{ ID string }
	json.Unmarshal(opts, &o)
	assertion := a.get(opts, 0x05)
	if code, body := e.post("/unlock/finish?id="+o.ID, assertion); code != 200 {
		t.Fatalf("first finish: %d %s", code, body)
	}
	if code, _ := e.post("/unlock/finish?id="+o.ID, assertion); code == 200 {
		t.Error("an unlock attempt was accepted twice")
	}
	// an approval's assertion can't unlock (other challenge)
	r := e.ask(cfReq)
	_, ropts := e.post("/r/"+r.ID+"/options", nil)
	_, uopts := e.post("/unlock/options", nil)
	json.Unmarshal(uopts, &o)
	if code, _ := e.post("/unlock/finish?id="+o.ID, a.get(ropts, 0x05)); code == 200 {
		t.Error("an approval's assertion unlocked the details")
	}
	// expired attempt
	_, uopts = e.post("/unlock/options", nil)
	json.Unmarshal(uopts, &o)
	e.b.now = func() time.Time { return time.Now().Add(unlockWait + time.Second) }
	if code, _ := e.post("/unlock/finish?id="+o.ID, a.get(uopts, 0x05)); code == 200 {
		t.Error("an expired unlock attempt was accepted")
	}
	e.b.now = time.Now
	// other sites can't start one
	req, _ := http.NewRequest("POST", e.srv.URL+"/unlock/options", nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site unlock: %d", resp.StatusCode)
	}
}

func TestUnlockAttemptsAreCapped(t *testing.T) {
	e := overviewEnv(t)
	e.enroll(newAuthenticator("approve.example"))
	for i := 0; i < maxUnlocks; i++ {
		if code, body := e.post("/unlock/options", nil); code != 200 {
			t.Fatalf("attempt %d: %d %s", i, code, body)
		}
	}
	if code, _ := e.post("/unlock/options", nil); code == 200 {
		t.Error("no cap on open unlock attempts")
	}
}

func TestOverviewActiveGrantsAndKeysLinkToRevoke(t *testing.T) {
	e := overviewEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	if code, body := e.approve(a, r, "15m", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	e.b.Wait(context.Background(), r)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "router")
	if err := e.b.keys.AddKey(string(pem.EncodeToMemory(block)), "op://Agents/opgate server key/private key", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	block2, _ := ssh.MarshalPrivateKey(priv2, "agent")
	e.b.keys.AddKey(string(pem.EncodeToMemory(block2)), "op://Agents/opgate build key/private key", 0)

	_, page := e.getPage("/")
	for _, s := range []string{"Secrets · same again", "Cloudflare", "Server key", "Build key", "SSH key · no approval", "min left"} {
		if !strings.Contains(page, s) {
			t.Errorf("overview lacks %q", s)
		}
	}
	var links [][]string
	for _, l := range regexp.MustCompile(`href="/u/([0-9a-f]{24})"`).FindAllStringSubmatch(page, -1) {
		if !slices.ContainsFunc(links, func(x []string) bool { return x[1] == l[1] }) {
			links = append(links, l)
		}
	}
	if len(links) != 3 {
		t.Fatalf("want 3 activity links, got %v", links)
	}
	// the same activities on a reload (no new tags), and each page offers Revoke
	_, again := e.getPage("/")
	for _, l := range links {
		if !strings.Contains(again, l[0]) {
			t.Error("activity tag changed on reload")
		}
		_, act := e.getPage("/u/" + l[1])
		if !strings.Contains(act, `id="revoke"`) {
			t.Errorf("activity page %s without Revoke", l[1])
		}
		if !resultLinksHome(act) {
			t.Errorf("activity page %s: no way to the overview after revoking", l[1])
		}
	}
	// revoking the grant from its page removes it from the overview and the next request asks again
	for _, l := range links {
		_, act := e.getPage("/u/" + l[1])
		if strings.Contains(act, "Secrets · same again") {
			if code, body := e.post("/u/"+l[1]+"/revoke", nil); code != 200 {
				t.Fatalf("revoke: %d %s", code, body)
			}
		}
	}
	if _, p := e.getPage("/"); strings.Contains(p, "Secrets · same again") {
		t.Error("revoked grant still listed")
	}
	if r2 := e.ask(cfReq); e.b.get(r2.ID) == nil {
		t.Error("the request rode on a revoked grant")
	}
}

func TestOverviewRestoreOnlyForRevokedKeys(t *testing.T) {
	e := overviewEnv(t)
	if code, _ := e.post("/restore", []byte(`{"ref":"op://Agents/opgate server key/private key"}`)); code == 200 {
		t.Error("restore offered for a key that isn't revoked")
	}
	e.b.revokedRefs["op://Agents/opgate build key/private key"] = true
	_, page := e.getPage("/")
	if !strings.Contains(page, "Build key is revoked") || !strings.Contains(page, `data-ref="op://Agents/opgate build key/private key"`) &&
		!strings.Contains(page, `data-ref="op:&#x2F;&#x2F;Agents&#x2F;opgate build key&#x2F;private key"`) {
		t.Error("revoked key not in Needs attention")
	}
	code, body := e.post("/restore", []byte(`{"ref":"op://Agents/opgate build key/private key"}`))
	var out struct{ URL string }
	json.Unmarshal(body, &out)
	if code != 200 || !strings.HasPrefix(out.URL, "/r/") || e.b.get(strings.TrimPrefix(out.URL, "/r/")) == nil {
		t.Fatalf("restore: %d %s", code, body)
	}
}

func TestOverviewNumbersAndProblemsFromTheAuditLog(t *testing.T) {
	e := overviewEnv(t)
	now := time.Now()
	ts := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	cf := `["op://Agents/Cloudflare/credential"]`
	lines := []string{
		// 40 days ago: outside the numbers
		fmt.Sprintf(`{"time":%q,"id":"old","event":"asked","kind":"secrets","refs":%s}`, ts(40*24*time.Hour), cf),
		fmt.Sprintf(`{"time":%q,"id":"a1","event":"asked","kind":"secrets","refs":%s}`, ts(10*24*time.Hour), cf),
		fmt.Sprintf(`{"time":%q,"id":"a1","event":"approved","kind":"secrets","refs":%s,"by":"phone"}`, ts(10*24*time.Hour-20*time.Second), cf),
		fmt.Sprintf(`{"time":%q,"id":"a2","event":"asked","kind":"ssh","refs":["op://Agents/opgate server key/private key"]}`, ts(3*time.Hour)),
		fmt.Sprintf(`{"time":%q,"id":"a2","event":"approved","kind":"ssh","refs":["op://Agents/opgate server key/private key"],"by":"phone"}`, ts(3*time.Hour-40*time.Second)),
		fmt.Sprintf(`{"time":%q,"id":"a3","event":"asked","kind":"secrets","refs":["op://Agents/Backup bucket (S3)/access key id"]}`, ts(2*time.Hour)),
		fmt.Sprintf(`{"time":%q,"id":"a3","event":"error","kind":"secrets","refs":["op://Agents/Backup bucket (S3)/access key id"],"detail":"reading op://Agents/Backup bucket (S3)/access key id: field not found"}`, ts(2*time.Hour-30*time.Second)),
		fmt.Sprintf(`{"time":%q,"id":"a4","event":"asked","kind":"secrets","refs":%s}`, ts(time.Hour), cf),
		fmt.Sprintf(`{"time":%q,"id":"a4","event":"error","kind":"secrets","refs":%s,"detail":"client went away"}`, ts(time.Hour-time.Second), cf),
		fmt.Sprintf(`{"time":%q,"id":"a5","event":"asked","kind":"secrets","refs":%s}`, ts(50*time.Minute), cf),
		fmt.Sprintf(`{"time":%q,"id":"a5","event":"denied","kind":"secrets","refs":%s}`, ts(49*time.Minute), cf),
		fmt.Sprintf(`{"time":%q,"id":"a5","event":"notify-failed","kind":"secrets","refs":%s,"detail":"no route to host"}`, ts(49*time.Minute), cf),
		fmt.Sprintf(`{"time":%q,"id":"g1","event":"granted","kind":"secrets","refs":%s}`, ts(40*time.Minute), cf),
		fmt.Sprintf(`{"time":%q,"id":"use","event":"key-used","kind":"ssh","refs":["op://Agents/opgate build key/private key"]}`, ts(30*time.Minute)),
		fmt.Sprintf(`{"time":%q,"id":"use","event":"key-used","kind":"ssh","refs":["1Password: owner SSH"],"by":"1password"}`, ts(20*time.Minute)),
		fmt.Sprintf(`{"time":%q,"id":"e1","event":"asked","kind":"enroll"}`, ts(10*time.Minute)),
		`not json`,
	}
	os.WriteFile(e.b.cfg.AuditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	st, attn := e.b.scanAudit(now, nil)
	if st.Requests != 5 || st.Approved != 2 || st.Denied != 1 || st.Failed != 1 || st.Cancelled != 1 || st.Reused != 1 || st.KeyUses != 1 || st.TouchID != 1 ||
		st.Outcomes != "2 approved · 1 denied · 1 failed · 1 cancelled" {
		t.Errorf("numbers %+v", st)
	}
	if st.MedianApprove != "40 s" {
		t.Errorf("median %q", st.MedianApprove)
	}
	if len(st.Top) == 0 || st.Top[0].Name != "Cloudflare" || st.Top[0].N != 4 {
		t.Errorf("top %+v", st.Top)
	}
	var titles []string
	for _, a := range attn {
		titles = append(titles, a.Title+" | "+a.Text+" | "+a.Raw)
	}
	all := strings.Join(titles, "\n")
	if !strings.Contains(all, "Approved, but nothing was delivered: Backup bucket (S3) | The item has no field with that name") ||
		!strings.Contains(all, "| reading op://Agents/Backup bucket (S3)/access key id: field not found") ||
		!strings.Contains(all, "Notifications failed 1× this week") || strings.Count(all, "nothing was delivered") != 1 {
		t.Errorf("attention:\n%s", all)
	}
	// no snapshot yet: says so
	_, page := e.getPage("/")
	if !strings.Contains(page, "No credential check yet") {
		t.Error("missing snapshot not flagged")
	}
	// a stale one too
	writeTestSnapshot(t, e, now.Add(-4*24*time.Hour))
	if _, page = e.getPage("/"); !strings.Contains(page, "Credential check not running") {
		t.Error("stale snapshot not flagged")
	}
}

func TestOverviewAllClear(t *testing.T) {
	e := overviewEnv(t)
	writeSnapshot(snapshotPath(e.b.cfg), []Report{{Cred: Cred{ID: "x", Title: "X", Tier: "B", Store: "~/.config/x"}, ID: "x", Tier: "B", Status: "ok"}}, time.Now())
	_, page := e.getPage("/")
	if !strings.Contains(page, "All clear") || !strings.Contains(page, "Nothing: no same-again grants and no loaded keys") {
		t.Errorf("empty overview:\n%s", page)
	}
}

func TestActivitiesWithoutUsesAreForgotten(t *testing.T) {
	e := overviewEnv(t)
	a := e.b.ensureActivity("k1", Activity{Kind: "grant", Title: "T"})
	if _, ok := e.b.getActivity(a.Tag); !ok {
		t.Fatal("activity not created")
	}
	e.b.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	e.b.ensureActivity("k2", Activity{Kind: "grant", Title: "U"})
	if _, ok := e.b.getActivity(a.Tag); ok {
		t.Error("an unused activity outlived a day")
	}
}

func TestDismissPastFailures(t *testing.T) {
	e := overviewEnv(t)
	writeTestSnapshot(t, e, time.Now())
	now := time.Now()
	line := func(d time.Duration, id, event, detail string) string {
		return fmt.Sprintf(`{"time":%q,"id":%q,"event":%q,"kind":"secrets","refs":["op://Agents/Backup bucket (S3)/key"],"detail":%q}`,
			now.Add(-d).Format(time.RFC3339), id, event, detail)
	}
	parse := "error resolving secret reference: the secret reference could not be parsed: invalid character in secret reference"
	os.WriteFile(e.b.cfg.AuditLog, []byte(line(3*time.Hour, "a", "error", parse)+"\n"+line(2*time.Hour, "b", "error", parse)+"\n"+
		line(time.Hour, "c", "notify-failed", "no route")+"\n"), 0o600)
	_, page := e.getPage("/")
	for _, want := range []string{"Approved, but nothing was delivered: Backup bucket (S3)", "2× · last", "asking again works",
		"Message from 1Password", `data-key="error:Backup bucket (S3)"`, `data-key="notify"`, "4 things need you"} {
		if !strings.Contains(page, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if code, _ := e.post("/dismiss", []byte(`{"key":"error:something else"}`)); code == 200 {
		t.Error("dismissed a key the page doesn't offer")
	}
	for _, k := range []string{"error:Backup bucket (S3)", "notify"} {
		if code, body := e.post("/dismiss", []byte(`{"key":"`+k+`"}`)); code != 200 {
			t.Fatalf("dismiss %s: %d %s", k, code, body)
		}
	}
	if _, page = e.getPage("/"); strings.Contains(page, "nothing was delivered") || strings.Contains(page, "notifications failed") {
		t.Error("dismissed failures still shown")
	}
	if !strings.Contains(page, "2 things need you") { // the snapshot's invalid and expiring credentials stay: not dismissable
		t.Error("headline should count what's left")
	}
	// the same failure again later shows again
	f, _ := os.OpenFile(e.b.cfg.AuditLog, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(line(-time.Minute, "d", "error", parse) + "\n")
	f.Close()
	if _, page = e.getPage("/"); !strings.Contains(page, "nothing was delivered: Backup bucket (S3)") {
		t.Error("a new failure after the dismissal is hidden")
	}
	if st, _ := os.Stat(e.b.dismissedPath()); st == nil || st.Mode().Perm() != 0o600 {
		t.Error("dismissed.json missing or not private")
	}
}

func TestOverviewStateAndHistory(t *testing.T) {
	e := overviewEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	state := func() string {
		code, body := e.getPage("/overview/state")
		var j struct{ Sig string }
		json.Unmarshal([]byte(body), &j)
		if code != 200 || len(j.Sig) != 16 {
			t.Fatalf("state: %d %s", code, body)
		}
		return j.Sig
	}
	s1 := state()
	if _, page := e.getPage("/"); !strings.Contains(page, `data-sig="`+s1+`"`) {
		t.Error("page and state disagree")
	}
	// routine uses of the autoloaded key change neither the signature nor the History tab's first page
	for i := 0; i < 3; i++ {
		e.b.keyUsed(keyMeta{Ref: "op://Agents/opgate build key/private key", Loaded: time.Now()}, "SHA256:m",
			procsFromArgs([]string{"/usr/bin/ssh git@github.com git-receive-pack", "git push", "-zsh"}))
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "agent")
	e.b.keys.AddKey(string(pem.EncodeToMemory(block)), "op://Agents/opgate build key/private key", 0)
	s2 := state()
	e.b.keyUsed(keyMeta{Ref: "op://Agents/opgate build key/private key", Loaded: time.Now()}, "SHA256:m",
		procsFromArgs([]string{"/usr/bin/ssh nas true", "-zsh"}))
	if state() != s2 {
		t.Error("an agent key use changed the page signature")
	}
	_, page := e.getPage("/")
	if strings.Contains(page, `class="ev"`) || !strings.Contains(page, "routine hidden") {
		t.Error("the history shows routine key uses")
	}
	// a request changes it and shows in Needs attention, and once decided in the history
	r := e.ask(cfReq)
	if state() == s2 {
		t.Error("a new request didn't change the signature")
	}
	e.approve(a, r, "", 0x05)
	e.b.Wait(context.Background(), r)
	if _, page = e.getPage("/"); !strings.Contains(page, `class="ev"`) || !strings.Contains(page, "Approved · test") {
		t.Error("the approved request isn't in the history")
	}
}

func TestOverviewUpcomingAndActions(t *testing.T) {
	e := overviewEnv(t)
	now := time.Now()
	// Noon 60 calendar days ahead: "in 60 days" at any time of day (now+60d+1h read "in 61 days" after 23:00).
	writeSnapshot(snapshotPath(e.b.cfg), []Report{
		{Cred: Cred{ID: "cert", Title: "Web certificate", Tier: "B", Store: "~/x"}, ID: "cert", Tier: "B", Status: "ok", Expires: time.Date(now.Year(), now.Month(), now.Day()+60, 12, 0, 0, 0, time.Local)},
		{Cred: Cred{ID: "far", Title: "Far token", Tier: "B", Store: "~/y"}, ID: "far", Tier: "B", Status: "ok", Expires: now.Add(300 * 24 * time.Hour)},
	}, now)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "router")
	e.b.keys.AddKey(string(pem.EncodeToMemory(block)), "op://Agents/opgate server key/private key", 30*time.Minute)
	_, page := e.getPage("/")
	up := page[strings.Index(page, "Expiring in the next 90 days"):]
	up = up[:strings.Index(up, "</ol>")]
	if !strings.Contains(up, "Web certificate") || !strings.Contains(up, "in 60 days") || strings.Contains(up, "Far token") {
		t.Errorf("upcoming:\n%s", up)
	}
	if !strings.Contains(page, `data-stop="1"`) || !strings.Contains(page, `class="minibtn revoke" data-tag="`) || !strings.Contains(page, "data-until=") {
		t.Error("router key without Revoke, Revoke + stop or countdown")
	}
	if !strings.Contains(page, "every request goes to your phone") && !strings.Contains(page, "Touch ID when you") && !strings.Contains(page, "1Password on the Mac only") {
		t.Error("mode not explained")
	}
}

func TestExplainErrorAndInDays(t *testing.T) {
	for detail, want := range map[string]string{
		"error resolving secret reference: invalid character in secret reference": "characters like ( )",
		`op: [ERROR] "Nope" isn't an item`:                                        "no item with that name",
		`no field "x (y)" in Item`:                                                "no field with that name",
		`several items match "Dup x": a, b; use the ID`:                           "more than one",
		"something else": "reading the value from 1Password failed",
	} {
		if got := explainError(detail); !strings.Contains(got, want) {
			t.Errorf("%q: %q", detail, got)
		}
	}
	now := time.Date(2026, 11, 5, 23, 0, 0, 0, time.Local)
	for d, want := range map[time.Duration]string{2 * time.Hour: "tomorrow", 30 * time.Minute: "today", 49 * time.Hour: "in 3 days", -25 * time.Hour: "yesterday", -49 * time.Hour: "2 days ago"} {
		if got := inDays(now, now.Add(d)); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

func TestHistoryPagesAndSearch(t *testing.T) {
	e := overviewEnv(t)
	now := time.Now()
	var lines []string
	for i := 45; i > 0; i-- {
		lines = append(lines, fmt.Sprintf(`{"time":%q,"id":"r%d","event":"routed","kind":"secrets","by":"op","reason":"op item get n%d"}`,
			now.Add(-time.Duration(i)*time.Minute).Format(time.RFC3339), i, i))
	}
	for i := 3; i > 0; i-- {
		lines = append(lines, fmt.Sprintf(`{"time":%q,"id":"m%d","event":"key-used","refs":["op://Agents/opgate build key/private key"]}`,
			now.Add(-time.Duration(i)*time.Second).Format(time.RFC3339), i))
	}
	os.WriteFile(e.b.cfg.AuditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	items := func(query string) (map[string]any, string) {
		code, body := e.getPage("/history/items?" + query)
		var j map[string]any
		if code != 200 || json.Unmarshal([]byte(body), &j) != nil {
			t.Fatalf("%s: %d %s", query, code, body)
		}
		return j, j["html"].(string)
	}
	j, html := items("")
	if strings.Count(html, `class="ev"`) != 20 || j["label"] != "1–20 of 45 · 3 routine hidden" || j["pages"] != 3.0 || !strings.Contains(html, "n1<") {
		t.Errorf("first page: %v %d", j["label"], strings.Count(html, `class="ev"`))
	}
	if j, html = items("page=99"); j["page"] != 3.0 || strings.Count(html, `class="ev"`) != 5 || !strings.Contains(html, "n45<") {
		t.Errorf("last page: %v", j["label"])
	}
	if j, _ = items("routine=1"); j["total"] != 48.0 {
		t.Errorf("with routine uses: %v", j["total"])
	}
	if j, html = items("q=N17"); j["total"] != 1.0 || !strings.Contains(html, "n17<") {
		t.Errorf("search: %v", j["label"])
	}
	if _, html = items("dir=asc"); !strings.HasPrefix(html[strings.Index(html, `class="what"`):], `class="what">op item get n45<`) {
		t.Error("oldest first doesn't start with the oldest")
	}
	// the overview has the first page; /history leads there
	if _, page := e.getPage("/"); strings.Count(page, `class="ev"`) != 20 || !strings.Contains(page, `id="tabs"`) {
		t.Error("the overview lacks the history's first page")
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/history", nil)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/#history" {
		t.Errorf("/history: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestIconsAreServedAndLinked(t *testing.T) {
	e := overviewEnv(t)
	for path, typ := range map[string]string{"/favicon.svg": "image/svg+xml", "/favicon.ico": "image/", "/favicon-32.png": "image/png", "/apple-touch-icon.png": "image/png"} {
		resp, err := http.Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), typ) {
			t.Errorf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	r := e.ask(cfReq)
	a := e.b.ensureActivity("k", Activity{Kind: "grant", Title: "T"})
	for _, p := range []string{"/", "/history", "/r/" + r.ID, "/u/" + a.Tag} {
		if _, page := e.getPage(p); !strings.Contains(page, `<link rel="icon" href="/favicon.svg"`) || !strings.Contains(page, "apple-touch-icon") {
			t.Errorf("%s doesn't link the icons", p)
		}
	}
}

// resultLinksHome reports whether the outcome screen (or the "nothing here" screen) links to the overview: the
// browser keeps a tab open that it didn't open for a notification, and the page's header is hidden by then.
func resultLinksHome(page string) bool {
	i := strings.Index(page, `id="result"`)
	if i < 0 {
		i = strings.Index(page, `class="empty"`)
	}
	if i < 0 {
		return false
	}
	end := len(page)
	for _, next := range []string{`<div class="bar"`, "<script"} {
		if j := strings.Index(page[i:], next); j >= 0 && i+j < end {
			end = i + j
		}
	}
	return strings.Contains(page[i:end], `class="btn home" href="/"`)
}

func TestDecidedPagesLinkToTheOverview(t *testing.T) {
	e := overviewEnv(t)
	r := e.ask(cfReq)
	for path, what := range map[string]string{"/r/" + r.ID: "request", "/r/nosuch": "decided request", "/u/nosuch": "gone activity"} {
		if _, page := e.getPage(path); !resultLinksHome(page) {
			t.Errorf("%s page (%s): no link to the overview", what, path)
		}
	}
}
