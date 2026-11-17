package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const testOrigin = "https://approve.example"

// --- fakes ---

type fakeStore struct {
	mu      sync.Mutex
	v       map[string]string
	unknown map[string]bool                 // items Check refuses
	check   func(ctx context.Context) error // Check's answer for the other items (nil: they are there)
}

func (f *fakeStore) Check(ctx context.Context, ref string) error {
	p, _ := splitRef(ref)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unknown[p.Item] {
		return unknownRef(fmt.Sprintf("no item %q in %s", p.Item, p.Vault))
	}
	if f.check != nil {
		return f.check(ctx)
	}
	return nil
}

func (f *fakeStore) Resolve(_ context.Context, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.v[ref]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (f *fakeStore) set(ref, v string) { f.mu.Lock(); f.v[ref] = v; f.mu.Unlock() }

type fakeNotify struct {
	mu    sync.Mutex
	asked []string
	done  []string
}

func (n *fakeNotify) Ask(r *Request, url string) error {
	n.mu.Lock()
	n.asked = append(n.asked, url)
	n.mu.Unlock()
	return nil
}
func (n *fakeNotify) Used(a Activity, url string) error {
	n.mu.Lock()
	n.done = append(n.done, fmt.Sprintf("used %d", a.Count))
	n.mu.Unlock()
	return nil
}
func (n *fakeNotify) Revoked(a Activity) error {
	n.mu.Lock()
	n.done = append(n.done, "revoked "+a.Kind)
	n.mu.Unlock()
	return nil
}
func (n *fakeNotify) Done(r *Request, res Result) error {
	n.mu.Lock()
	n.done = append(n.done, res.Status)
	n.mu.Unlock()
	return nil
}

// authenticator is a software passkey (ES256, attestation "none").
type authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	rpID   string
	count  uint32
}

func newAuthenticator(rpID string) *authenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &authenticator{key: k, credID: id, rpID: rpID}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *authenticator) authData(flags byte, attested bool) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	var buf bytes.Buffer
	buf.Write(h[:])
	buf.WriteByte(flags)
	a.count++
	binary.Write(&buf, binary.BigEndian, a.count)
	if attested {
		buf.Write(make([]byte, 16)) // aaguid
		binary.Write(&buf, binary.BigEndian, uint16(len(a.credID)))
		buf.Write(a.credID)
		pub, _ := a.key.PublicKey.Bytes() // uncompressed point: 0x04, X, Y
		x, y := pub[1:33], pub[33:65]
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		buf.Write(cose)
	}
	return buf.Bytes()
}

func clientData(typ string, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return b
}

// create answers registration options (JSON from the server) with an attestation response.
func (a *authenticator) create(opts []byte) []byte {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	json.Unmarshal(opts, &o)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(0x45, true)})
	resp, _ := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(clientData("webauthn.create", o.PublicKey.Challenge, testOrigin)), "attestationObject": b64(att)}})
	return resp
}

// get answers assertion options with a signed assertion; flags 0x05 = user present + verified.
func (a *authenticator) get(opts []byte, flags byte) []byte {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	json.Unmarshal(opts, &o)
	cd := clientData("webauthn.get", o.PublicKey.Challenge, testOrigin)
	ad := a.authData(flags, false)
	h := sha256.Sum256(cd)
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, sha256Sum(append(ad, h[:]...)))
	resp, _ := json.Marshal(map[string]any{"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig), "userHandle": b64([]byte("opgate-owner"))}})
	return resp
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// --- harness ---

type env struct {
	t     *testing.T
	b     *Broker
	store *fakeStore
	note  *fakeNotify
	srv   *httptest.Server
}

func newEnv(t *testing.T) *env {
	cfg := defaultConfig()
	cfg.PublicURL, cfg.RPID, cfg.AuditLog = testOrigin, "approve.example", ""
	store := &fakeStore{v: map[string]string{
		"op://Agents/Cloudflare/credential": "cf-secret",
		"op://Agents/Cloudflare/account id": "acct-1",
		"op://Agents/opgate/passkeys":       "[]",
	}}
	note := &fakeNotify{}
	b, err := newBroker(cfg, store, note, newAgent("/nonexistent"), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(b.handler())
	t.Cleanup(srv.Close)
	return &env{t: t, b: b, store: store, note: note, srv: srv}
}

func (e *env) post(path string, body []byte) (int, []byte) {
	resp, err := http.Post(e.srv.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

// enroll registers a and stores it in the fake 1Password item, as the owner would.
func (e *env) enroll(a *authenticator) {
	r, err := e.b.Submit(RequestIn{Kind: KindEnroll, Name: "test"}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	code, opts := e.post("/enroll/"+r.ID+"/options?k="+r.enrollKey, nil)
	if code != 200 {
		e.t.Fatalf("enroll options: %d %s", code, opts)
	}
	if code, body := e.post("/enroll/"+r.ID+"/finish?k="+r.enrollKey, a.create(opts)); code != 200 {
		e.t.Fatalf("enroll finish: %d %s", code, body)
	}
	res := e.b.Wait(context.Background(), r)
	if res.Status != "approved" || len(res.Payload) == 0 {
		e.t.Fatalf("enroll result %+v", res)
	}
	var list []json.RawMessage
	cur, _ := e.store.Resolve(context.Background(), "op://Agents/opgate/passkeys")
	json.Unmarshal([]byte(cur), &list)
	list = append(list, res.Payload)
	out, _ := json.Marshal(list)
	e.store.set("op://Agents/opgate/passkeys", string(out))
}

func (e *env) ask(in RequestIn, caller ...string) *Request {
	if len(caller) == 0 {
		caller = []string{"opgate read", "/bin/bash scripts/mac/cf-dns.sh GET /zones", "claude"}
	}
	r, err := e.b.Submit(in, caller)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

var cfReq = RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/Cloudflare/credential"}, Reason: "list the zones to check DNS"}

func (e *env) approve(a *authenticator, r *Request, grant string, flags byte) (int, string) {
	code, opts := e.post("/r/"+r.ID+"/options", nil)
	if code != 200 {
		return code, string(opts)
	}
	code, body := e.post("/r/"+r.ID+"/approve?grant="+grant, a.get(opts, flags))
	return code, string(body)
}

// --- tests ---

func TestApprovalReleasesSecrets(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	if len(e.note.asked) != 2 || !strings.HasSuffix(e.note.asked[1], "/r/"+r.ID) {
		t.Fatalf("phone not asked with the request link: %v", e.note.asked)
	}
	if code, body := e.approve(a, r, "", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	res := e.b.Wait(context.Background(), r)
	if res.Status != "approved" || res.Secrets["op://Agents/Cloudflare/credential"] != "cf-secret" {
		t.Fatalf("result %+v", res)
	}
}

func TestAssertionOnlyApprovesItsOwnRequest(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r1, r2 := e.ask(cfReq), e.ask(cfReq)
	_, opts1 := e.post("/r/"+r1.ID+"/options", nil)
	e.post("/r/"+r2.ID+"/options", nil)
	// an assertion over r1's challenge must not approve r2
	if code, _ := e.post("/r/"+r2.ID+"/approve", a.get(opts1, 0x05)); code == 200 {
		t.Fatal("r1's assertion approved r2")
	}
	if e.b.get(r2.ID) == nil {
		t.Fatal("r2 should still be pending")
	}
}

func TestUnknownPasskeyCannotApprove(t *testing.T) {
	e := newEnv(t)
	e.enroll(newAuthenticator("approve.example"))
	stranger := newAuthenticator("approve.example") // registered nowhere (e.g. an agent's own software key)
	r := e.ask(cfReq)
	if code, _ := e.approve(stranger, r, "", 0x05); code == 200 {
		t.Fatal("a passkey that isn't in 1Password approved a request")
	}
}

func TestEnrolledButNotStoredCannotApprove(t *testing.T) {
	e := newEnv(t)
	e.enroll(newAuthenticator("approve.example"))
	// an agent runs `opgate enroll` with its own authenticator but can't write to 1Password
	sneaky := newAuthenticator("approve.example")
	r, _ := e.b.Submit(RequestIn{Kind: KindEnroll, Name: "sneaky"}, nil)
	_, opts := e.post("/enroll/"+r.ID+"/options?k="+r.enrollKey, nil)
	e.post("/enroll/"+r.ID+"/finish?k="+r.enrollKey, sneaky.create(opts))
	req := e.ask(cfReq)
	if code, _ := e.approve(sneaky, req, "", 0x05); code == 200 {
		t.Fatal("an enrolled-but-not-stored passkey approved a request")
	}
}

func TestUserVerificationRequired(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	if code, _ := e.approve(a, r, "", 0x01); code == 200 { // present, not verified
		t.Fatal("approved without user verification")
	}
}

func TestDenyAndExpire(t *testing.T) {
	e := newEnv(t)
	r := e.ask(cfReq)
	e.post("/r/"+r.ID+"/deny", nil)
	if res := e.b.Wait(context.Background(), r); res.Status != "denied" || res.Secrets != nil {
		t.Fatalf("deny: %+v", res)
	}
	e.b.cfg.PendingTTL = Duration{50 * time.Millisecond}
	r = e.ask(cfReq)
	if res := e.b.Wait(context.Background(), r); res.Status != "expired" {
		t.Fatalf("expire: %+v", res)
	}
}

func TestGrantCoversSameScriptOnly(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	if code, body := e.approve(a, r, "30m", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	e.b.Wait(context.Background(), r)
	again := e.ask(cfReq)
	if res := e.b.Wait(context.Background(), again); res.Status != "approved" || res.Secrets["op://Agents/Cloudflare/credential"] != "cf-secret" {
		t.Fatalf("grant not applied: %+v", res)
	}
	other := e.ask(cfReq, "opgate read", "/bin/bash /tmp/other.sh", "claude")
	if e.b.get(other.ID) == nil {
		t.Fatal("a different script rode on the grant")
	}
	more := e.ask(RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/Cloudflare/credential", "op://Agents/Cloudflare/account id"}, Reason: "list the zones to check DNS"})
	if e.b.get(more.ID) == nil {
		t.Fatal("more refs rode on the grant")
	}
}

func TestValidation(t *testing.T) {
	e := newEnv(t)
	for _, in := range []RequestIn{
		{Kind: KindSecrets, Refs: []string{"op://Agents/x/y"}, Reason: "short"},
		{Kind: KindSecrets, Refs: []string{"op://Agents/x/y"}, Reason: "test (runs: true)"},
		{Kind: KindSecrets, Refs: []string{"/etc/passwd"}, Reason: "a long enough reason"},
		{Kind: KindSSH, Refs: []string{"op://Agents/k/private key"}, TTL: 9 * time.Hour, Reason: "a long enough reason"},
		{Kind: "shell", Reason: "a long enough reason"},
	} {
		if _, err := e.b.Submit(in, nil); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.MaxPerHour = 2
	e.ask(cfReq)
	e.ask(cfReq)
	if _, err := e.b.Submit(cfReq, nil); err == nil {
		t.Fatal("rate limit not applied")
	}
}

func TestPageOnlyFromAllowedAddresses(t *testing.T) {
	e := newEnv(t)
	r := e.ask(cfReq)
	req := httptest.NewRequest("GET", "/r/"+r.ID, nil)
	req.RemoteAddr = "192.0.2.50:5555"
	rec := httptest.NewRecorder()
	e.b.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d from a LAN address that isn't Caddy", rec.Code)
	}
	_, page := e.getPage("/r/" + r.ID)
	if !strings.Contains(page, "list the zones to check DNS") || !strings.Contains(page, "cf-dns.sh") {
		t.Fatalf("page lacks reason or caller: %s", page)
	}
}

func TestSSHApprovalLoadsKeyWithLifetime(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "router")
	e.store.set("op://Agents/router key/private key", string(pem.EncodeToMemory(block)))
	r := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/router key/private key"}, TTL: time.Hour, Reason: "read the router's dnsmasq config"})
	if code, body := e.approve(a, r, "30m", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	if res := e.b.Wait(context.Background(), r); res.Status != "approved" || res.Secrets != nil {
		t.Fatalf("ssh result %+v", res)
	}
	keys := e.b.keys.Keys()
	if len(keys) != 1 || !strings.Contains(keys[0], "until") {
		t.Fatalf("keys %v", keys)
	}
	// no grant for ssh: the next load asks again
	r2 := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/router key/private key"}, TTL: time.Hour, Reason: "read the router's dnsmasq config"})
	if e.b.get(r2.ID) == nil {
		t.Fatal("ssh load rode on a grant")
	}
}

func TestAgentSignsOwnKeysAndIsReadOnly(t *testing.T) {
	ag := newAgent("/nonexistent")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "git")
	if err := ag.AddKey(string(pem.EncodeToMemory(block)), "op://Agents/git/private key", 0); err != nil {
		t.Fatal(err)
	}
	s := newSession(ag, nil)
	keys, _ := s.List()
	if len(keys) != 1 {
		t.Fatalf("keys %v", keys)
	}
	pk, _ := ssh.ParsePublicKey(keys[0].Blob)
	sig, err := s.Sign(pk, []byte("data"))
	if err != nil || pk.Verify([]byte("data"), sig) != nil {
		t.Fatalf("sign: %v", err)
	}
	if s.Add(agent.AddedKey{PrivateKey: priv}) == nil || s.RemoveAll() == nil || s.Lock([]byte("x")) == nil {
		t.Fatal("clients could change the agent")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	opk, _ := ssh.NewPublicKey(other)
	if _, err := s.Sign(opk, []byte("data")); err == nil {
		t.Fatal("signed with a key it doesn't hold")
	}
}

func TestAutoloadRefsWithSpaces(t *testing.T) {
	e := newEnv(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "agent")
	e.store.set("op://Agents/opgate build key/private key", string(pem.EncodeToMemory(block)))
	e.store.set("op://Agents/opgate/autoload", "op://Agents/opgate build key/private key\n# comment\n")
	e.b.autoload(context.Background())
	e.b.autoload(context.Background()) // twice: no duplicate
	if k := e.b.keys.Keys(); len(k) != 1 || !strings.Contains(k[0], "opgate build key/private key") {
		t.Fatalf("keys %v", k)
	}
}

// the chain Claude Code in VS Code produced
var claudeChain = []string{
	"/Users/me/.local/bin/opgate ssh-add --ttl 1h --reason Test op://Agents/opgate server key/private key",
	`/opt/homebrew/bin/bash -c source /Users/me/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && eval 'ssh -O exit router; ~/.local/bin/opgate ssh-add --ttl 1h --reason "it'\''s a test" "op://Agents/opgate server key/private key"' \< /dev/null && pwd -P >| /tmp/claude-cwd`,
	"/Users/me/.vscode/extensions/anthropic.claude-code-2.1.314-darwin-arm64/resources/native-binary/claude --output-format stream-json",
	"/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin) --type=utility",
}

func TestDescribeUnwrapsClaudeShell(t *testing.T) {
	a := describe(claudeChain)
	if a.Agent != "Claude Code (VS Code)" {
		t.Errorf("agent %q", a.Agent)
	}
	want := `ssh -O exit router; ~/.local/bin/opgate ssh-add --ttl 1h --reason "it's a test" "op://Agents/opgate server key/private key"`
	if a.Command != want || a.Script != "" {
		t.Errorf("command %q script %q", a.Command, a.Script)
	}
	r := &Request{RequestIn: RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, TTL: time.Hour}, Caller: claudeChain}
	if s := summary(r); s != "server key for 1 h" || pageTitle(r) != "Server key" {
		t.Errorf("summary %q", s)
	}
	script := describe([]string{"opgate read", "/bin/bash scripts/mac/cf-dns.sh GET /zones", claudeChain[1], claudeChain[2]})
	if script.Script != "cf-dns.sh" || script.Agent != "Claude Code (VS Code)" {
		t.Errorf("script chain: %+v", script)
	}
}

func TestGrantUseNotifiesQuietly(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	e.approve(a, r, "30m", 0x05)
	e.b.Wait(context.Background(), r)
	for i := 0; i < 2; i++ {
		e.b.Wait(context.Background(), e.ask(cfReq))
	}
	e.note.mu.Lock()
	defer e.note.mu.Unlock()
	if got := strings.Join(e.note.done, ","); !strings.Contains(got, "used 1,used 2") {
		t.Fatalf("notices %s", got)
	}
}

func TestPageGoParameter(t *testing.T) {
	e := newEnv(t)
	r := e.ask(cfReq)
	for q, want := range map[string]string{"?go=approve": `data-go="approve"`, "?go=deny": `data-go="deny"`, "?go=<x>": `data-go=""`} {
		if _, page := e.getPage("/r/" + r.ID + q); !strings.Contains(page, want) {
			t.Errorf("%s: missing %s", q, want)
		}
	}
}

func TestDocumentRefDisplay(t *testing.T) {
	r := &Request{RequestIn: RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/App oauth2.txt?document"}}}
	if got := summary(r); got != "App oauth2.txt (document)" {
		t.Fatalf("summary %q", got)
	}
	if got := pageTitle(r); got != "App oauth2.txt" {
		t.Fatalf("title %q", got)
	}
}

func TestKeyUseNotices(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	e.b.keys.OnUse = e.b.keyUsed
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "router")
	e.store.set("op://Agents/opgate server key/private key", string(pem.EncodeToMemory(block)))
	r := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, TTL: time.Hour, Reason: "check dnsmasq on the router"})
	e.approve(a, r, "", 0x05)
	e.b.Wait(context.Background(), r)
	s := newSession(e.b.keys, nil)
	keys, _ := s.List()
	pk, _ := ssh.ParsePublicKey(keys[0].Blob)
	for i := 0; i < 2; i++ {
		if _, err := s.Sign(pk, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		e.note.mu.Lock()
		got := strings.Join(e.note.done, ",")
		e.note.mu.Unlock()
		if strings.Contains(got, "used 1") && strings.Contains(got, "used 2") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no use notices: %v", e.note.done)
}

func TestAutoloadedKeyDailyNotice(t *testing.T) {
	e := newEnv(t)
	e.b.keys.OnUse = e.b.keyUsed
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "agent")
	e.b.keys.AddKey(string(pem.EncodeToMemory(block)), "op://Agents/opgate build key/private key", 0)
	s := newSession(e.b.keys, nil)
	keys, _ := s.List()
	pk, _ := ssh.ParsePublicKey(keys[0].Blob)
	for i := 0; i < 3; i++ {
		s.Sign(pk, []byte("x"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		e.note.mu.Lock()
		got := strings.Join(e.note.done, ",")
		e.note.mu.Unlock()
		if strings.Contains(got, "used 3") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no daily notices: %v", e.note.done)
}

func TestDurations(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "router")
	e.store.set("op://Agents/opgate server key/private key", string(pem.EncodeToMemory(block)))

	// ssh without --ttl: 15 min, preselected
	r := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, Reason: "check dnsmasq on the router"})
	if r.TTL != 15*time.Minute {
		t.Fatalf("default ttl %s", r.TTL)
	}
	opts := durationOptions(r)
	if len(opts) != 4 || !opts[0].Checked || opts[0].Label != "15 min" || opts[1].Label != "30 min" {
		t.Fatalf("ssh options %+v", opts)
	}
	// the agent asks 30 min: preselected; an odd duration (45 min) is added next to the fixed choices
	r30 := &Request{RequestIn: RequestIn{Kind: KindSSH, TTL: 30 * time.Minute}}
	if o := durationOptions(r30); len(o) != 4 || !o[1].Checked {
		t.Fatalf("ssh 30m options %+v", o)
	}
	r45 := &Request{RequestIn: RequestIn{Kind: KindSSH, TTL: 45 * time.Minute}}
	if o := durationOptions(r45); len(o) != 5 || !o[2].Checked || o[2].Label != "45 min" {
		t.Fatalf("ssh 45m options %+v", o)
	}
	// the owner picks 1 h on the page
	code, opt := e.post("/r/"+r.ID+"/options", nil)
	if code != 200 {
		t.Fatal(string(opt))
	}
	if code, body := e.post("/r/"+r.ID+"/approve?dur=1h0m0s", a.get(opt, 0x05)); code != 200 {
		t.Fatal(string(body))
	}
	e.b.Wait(context.Background(), r)
	e.b.keys.mu.Lock()
	var until time.Time
	for _, m := range e.b.keys.meta {
		until = m.Until
	}
	e.b.keys.mu.Unlock()
	if left := time.Until(until); left < 55*time.Minute || left > 61*time.Minute {
		t.Fatalf("key loaded for %s, want the owner's 1 h", left)
	}

	// secrets: 15 min preselected, "Once" first; a grant is capped at 1 h
	s := e.ask(cfReq)
	so := durationOptions(s)
	if len(so) != 4 || so[0].Label != "Once" || !so[1].Checked {
		t.Fatalf("secrets options %+v", so)
	}
	_, opt = e.post("/r/"+s.ID+"/options", nil)
	e.post("/r/"+s.ID+"/approve?dur=9h", a.get(opt, 0x05))
	e.b.Wait(context.Background(), s)
	e.b.mu.Lock()
	g := e.b.grants[grantKey(s)]
	e.b.mu.Unlock()
	if g == nil || time.Until(g.Until) > time.Hour+time.Minute {
		t.Fatalf("grant %+v", g)
	}
}

func TestAgentCommand(t *testing.T) {
	chain := []string{"/usr/bin/ssh-keygen -Y sign -n git -f /tmp/k -U /tmp/buf",
		"/bin/sh /Users/me/.local/bin/opgate-ssh-sign -Y sign",
		"git commit -m test",
		`/opt/homebrew/bin/bash -c source /Users/me/.claude/shell-snapshots/s.sh && eval 'cd /Users/me/Development/homelab && cd mac && git add -A && git commit -q -m "x"' \< /dev/null`,
		"/Users/me/.vscode/extensions/anthropic.claude-code/resources/native-binary/claude"}
	if got := agentCommand(chain); got != `git add -A && git commit -q -m "x"` {
		t.Fatalf("got %q", got)
	}
	if got := agentCommand([]string{"ssh router uptime", "-zsh"}); got != "ssh router uptime" {
		t.Fatalf("no agent: %q", got)
	}
}

func TestRevokeGrantAndKey(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	e.b.keys.OnUse = e.b.keyUsed

	// grant: used once more, revoked, then the same request asks again
	r := e.ask(cfReq)
	e.approve(a, r, "15m", 0x05)
	e.b.Wait(context.Background(), r)
	again := e.ask(cfReq)
	e.b.Wait(context.Background(), again)
	var tag string
	e.b.mu.Lock()
	for _, act := range e.b.activity {
		if act.Kind == "grant" {
			tag = act.Tag
		}
	}
	e.b.mu.Unlock()
	if code, body := e.post("/u/"+tag+"/revoke", nil); code != 200 {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if third := e.ask(cfReq); e.b.get(third.ID) == nil {
		t.Fatal("grant still active after revoke")
	}

	// approved ssh key: used, page shows the command, revoke + stop unloads it and ends the process
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "router")
	e.store.set("op://Agents/opgate server key/private key", string(pem.EncodeToMemory(block)))
	k := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, Reason: "check dnsmasq on the router"})
	e.approve(a, k, "", 0x05)
	e.b.Wait(context.Background(), k)
	keys := e.b.keys.Keys()
	fp := strings.Fields(keys[0])[0]
	sleeper := exec.Command("sleep", "30")
	sleeper.Start()
	defer sleeper.Process.Kill()
	ps := procsFromArgs([]string{"ssh router nvram get lan_ipaddr", "-zsh"})
	live, _, _ := procInfo(sleeper.Process.Pid)
	ps[0].PID, ps[0].Start = live.PID, live.Start
	loaded := e.b.keys.Loaded()[0].keyMeta // the load the agent reports (Revoke checks it is still this one)
	loaded.Uses = 1
	e.b.keyUsed(loaded, fp, ps)
	tag = ""
	e.b.mu.Lock()
	for _, act := range e.b.activity {
		if act.Kind == "key" {
			tag = act.Tag
		}
	}
	e.b.mu.Unlock()
	_, page := e.getPage("/u/" + tag)
	if !strings.Contains(page, "ssh router nvram get lan_ipaddr") || !strings.Contains(page, "Revoke + stop") {
		t.Fatalf("activity page lacks the command or the buttons")
	}
	code, body := e.post("/u/"+tag+"/stop", nil)
	if code != 200 || !strings.Contains(string(body), `"stopped":1`) {
		t.Fatalf("stop: %d %s", code, body)
	}
	if len(e.b.keys.Keys()) != 0 {
		t.Fatalf("key still loaded: %v", e.b.keys.Keys())
	}
	done := make(chan error, 1)
	go func() { done <- sleeper.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("process not stopped")
	}
}

func TestKeyUseCommand(t *testing.T) {
	for want, chain := range map[string][]string{
		"ssh router uptime":    {"/usr/bin/ssh router uptime", claudeChain[1]},
		`git commit -q -m "x"`: {"/usr/bin/ssh-keygen -Y sign -n git -f /tmp/k -U /tmp/b", "/bin/sh /Users/me/.local/bin/opgate-ssh-sign -Y sign", `git commit -q -m "x"`, claudeChain[1]},
		"git push origin main": {"/usr/bin/ssh git@github.com git-receive-pack 'someone/x.git'", "git push origin main", "-zsh"},
	} {
		if got := keyUseCommand(chain); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestHistoryPage(t *testing.T) {
	e := newEnv(t)
	e.b.cfg.AuditLog = filepath.Join(t.TempDir(), "audit.jsonl")
	e.b.audit = &Audit{path: e.b.cfg.AuditLog}
	a := newAuthenticator("approve.example")
	e.enroll(a)
	r := e.ask(cfReq)
	e.approve(a, r, "", 0x05)
	e.b.Wait(context.Background(), r)
	d := e.ask(RequestIn{Kind: KindSSH, Refs: []string{"op://Agents/opgate server key/private key"}, Reason: "check dnsmasq on the router"})
	e.post("/r/"+d.ID+"/deny", nil)
	e.b.Wait(context.Background(), d)
	open := e.ask(RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/x/y"}, Reason: "still waiting for the owner"})
	_, page := e.getPage("/history")
	for _, want := range []string{"list the zones to check DNS", "Approved · test", "check dnsmasq on the router", "Denied", "/r/" + open.ID, "Waiting for you"} {
		if !strings.Contains(page, want) {
			t.Errorf("history lacks %q", want)
		}
	}
}
