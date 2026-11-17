package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDumpPage writes a rendered approval page to $OPGATE_DUMP (manual visual check; skipped otherwise).
func TestDumpPage(t *testing.T) {
	out := os.Getenv("OPGATE_DUMP")
	if out == "" {
		t.Skip("set OPGATE_DUMP")
	}
	e := newEnv(t)
	r := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, TTL: time.Hour,
		Reason: "Read the dnsmasq config on the router to check the new approve.example.com name", Cwd: "/Users/me/Development/homelab"}, claudeChain...)
	sec := e.ask(RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/Cloudflare DNS token/credential", "op://Agents/Cloudflare DNS token/account id"},
		Reason: "Create the DNS record www.example.com pointing to Cloudflare Pages", Cwd: "/Users/me/Development/acme-shop"},
		"opgate read", "/bin/bash scripts/mac/cf-dns.sh POST /zones/{zone}/dns_records", claudeChain[1], claudeChain[2], claudeChain[3])
	for name, id := range map[string]string{"ssh": r.ID, "secrets": sec.ID} {
		_, page := e.getPage("/r/" + id)
		os.WriteFile(out+"-"+name+".html", []byte(page), 0o644)
	}
}

// TestDumpOverview writes the overview (locked and unlocked) with the stylesheet inlined to $OPGATE_DUMP.
func TestDumpOverview(t *testing.T) {
	out := os.Getenv("OPGATE_DUMP")
	if out == "" {
		t.Skip("set OPGATE_DUMP")
	}
	e := overviewEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	writeTestSnapshot(t, e, time.Now().Add(-3*time.Hour))
	r := e.ask(cfReq)
	e.approve(a, r, "15m", 0x05)
	e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, Reason: "Read the dnsmasq config on the router"})
	e.b.revokedRefs["op://Agents/opgate build key/private key"] = true
	css, _ := web.ReadFile("web/app.css")
	inline := func(p string) []byte {
		return bytes.Replace([]byte(p), []byte(`<link rel="stylesheet" href="/app.css">`), []byte("<style>"+string(css)+"</style>"), 1)
	}
	if real := os.Getenv("OPGATE_DUMP_REAL"); real != "" { // a folder with a copy of audit.jsonl and creds-latest.json
		for _, f := range []string{"audit.jsonl", "creds-latest.json"} {
			b, _ := os.ReadFile(filepath.Join(real, f))
			os.WriteFile(filepath.Join(filepath.Dir(e.b.cfg.Socket), f), b, 0o600)
		}
	}
	_, locked := e.getPage("/")
	os.WriteFile(out+"-overview.html", inline(locked), 0o644)
	_, _, cookies := e.unlock(a, 0x05)
	_, open := e.getPage("/", cookies...)
	os.WriteFile(out+"-overview-unlocked.html", inline(open), 0o644)
}

// TestDumpSettings writes the notification settings page (unlocked, one device) with the stylesheet and script
// inlined to $OPGATE_DUMP-settings.html.
func TestDumpSettings(t *testing.T) {
	out := os.Getenv("OPGATE_DUMP")
	if out == "" {
		t.Skip("set OPGATE_DUMP")
	}
	e, _, a := pushEnv(t)
	_, _, cookies := e.unlock(a, 0x05)
	br := newTestBrowser()
	e.postWith("/notify/subscribe", map[string]any{"endpoint": "https://fcm.googleapis.com/fcm/send/x",
		"p256dh": b64u.EncodeToString(br.key.PublicKey().Bytes()), "auth": b64u.EncodeToString(br.auth), "name": "Phone · Chrome", "mobile": true}, cookies)
	_, page := e.getPage("/settings", cookies...)
	css, _ := web.ReadFile("web/app.css")
	js, _ := web.ReadFile("web/app.js")
	page = strings.Replace(page, `<link rel="stylesheet" href="/app.css">`, "<style>"+string(css)+"</style>", 1)
	page = strings.Replace(page, `<script src="/app.js"></script>`, "<script>"+string(js)+"</script>", 1)
	os.WriteFile(out+"-settings.html", []byte(page), 0o644)
}
