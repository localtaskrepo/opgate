package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeB64u(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The example of RFC 8291 section 5: same keys and salt give the same bytes.
func TestEncryptPushRFC8291(t *testing.T) {
	asKey, err := ecdh.P256().NewPrivateKey(mustB64(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	if got := b64u.EncodeToString(asKey.PublicKey().Bytes()); got != "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8" {
		t.Fatalf("sender public key %s", got)
	}
	ua := mustB64(t, "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
	out, err := encryptPush([]byte("When I grow up, I want to be a watermelon"), ua, mustB64(t, "BTBZMqHH6r4Tts7J_aSIgg"), asKey,
		mustB64(t, "DGv6ra1nlYgDCS1FRnbzlw"))
	if err != nil {
		t.Fatal(err)
	}
	want := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	if got := b64u.EncodeToString(out); got != want {
		t.Fatalf("ciphertext\n got %s\nwant %s", got, want)
	}
	if _, err := encryptPush(make([]byte, maxPushPayload+1), ua, make([]byte, 16), asKey, make([]byte, 16)); err == nil {
		t.Error("an oversized message was encrypted")
	}
}

// decryptPush is the browser's side (RFC 8291), to check what Send posts.
func decryptPush(t *testing.T, body []byte, ua *ecdh.PrivateKey, auth []byte) []byte {
	t.Helper()
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if rs != pushRecordSize || idlen != 65 {
		t.Fatalf("header rs=%d idlen=%d", rs, idlen)
	}
	asPub := body[21 : 21+idlen]
	as, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := ua.ECDH(as)
	info := append(append([]byte("WebPush: info\x00"), ua.PublicKey().Bytes()...), asPub...)
	ikm, _ := hkdf.Key(sha256.New, secret, auth, string(info), 32)
	cek, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, body[21+idlen:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain[len(plain)-1] != 0x02 {
		t.Fatal("no last-record delimiter")
	}
	return plain[:len(plain)-1]
}

type memBlobs struct {
	mu   sync.Mutex
	m    map[string][]byte
	fail error
}

func (b *memBlobs) Load(name string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return nil, b.fail
	}
	return b.m[name], nil
}

func (b *memBlobs) Save(name string, v []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string][]byte{}
	}
	b.m[name] = append([]byte{}, v...)
	return nil
}

// A browser subscription: its keys, and the device as opgate stores it.
type testBrowser struct {
	key  *ecdh.PrivateKey
	auth []byte
}

func newTestBrowser() testBrowser {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	a := make([]byte, 16)
	rand.Read(a)
	return testBrowser{k, a}
}

func (tb testBrowser) device(id, endpoint string, mobile bool) pushDevice {
	return pushDevice{ID: id, Name: id, Mobile: mobile, Endpoint: endpoint,
		P256dh: b64u.EncodeToString(tb.key.PublicKey().Bytes()), Auth: b64u.EncodeToString(tb.auth)}
}

func TestWebPusherSend(t *testing.T) {
	br := newTestBrowser()
	var got struct {
		hdr  http.Header
		body []byte
	}
	status := http.StatusCreated
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.hdr = r.Header.Clone()
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	blobs := &memBlobs{}
	p := &webPusher{blobs: blobs, client: srv.Client(), subject: "https://approve.example"}
	pub, err := p.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	// the key is kept: a second pusher on the same store has the same one
	if pub2, _ := (&webPusher{blobs: blobs}).PublicKey(); pub2 != pub {
		t.Fatal("VAPID key not kept")
	}
	dev := br.device("phone", srv.URL+"/fcm/send/abc", true)
	if err := p.Send(context.Background(), dev, []byte(`{"kind":"test"}`), pushOpts{TTL: 90 * time.Second, Urgency: "high", Topic: pushTopic("x")}); err != nil {
		t.Fatal(err)
	}
	if string(decryptPush(t, got.body, br.key, br.auth)) != `{"kind":"test"}` {
		t.Error("payload doesn't decrypt")
	}
	for k, v := range map[string]string{"Ttl": "90", "Content-Encoding": "aes128gcm", "Urgency": "high", "Topic": pushTopic("x")} {
		if got.hdr.Get(k) != v {
			t.Errorf("header %s = %q, want %q", k, got.hdr.Get(k), v)
		}
	}
	// VAPID: a JWT for the push service's origin, signed with the key whose public half is k=
	authz := got.hdr.Get("Authorization")
	tok, k, ok := strings.Cut(strings.TrimPrefix(authz, "vapid t="), ", k=")
	if !ok || k != pub {
		t.Fatalf("authorization %q", authz)
	}
	parts := strings.Split(tok, ".")
	var claims struct {
		Aud, Sub string
		Exp      int64
	}
	json.Unmarshal(mustB64(t, parts[1]), &claims)
	if claims.Aud != srv.URL || claims.Sub != "https://approve.example" || claims.Exp < time.Now().Unix() {
		t.Errorf("claims %+v", claims)
	}
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), mustB64(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	sig := mustB64(t, parts[2])
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pk, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("VAPID signature doesn't verify")
	}
	status = http.StatusGone
	if err := p.Send(context.Background(), dev, []byte(`{}`), pushOpts{}); !errors.Is(err, errPushGone) {
		t.Errorf("410: %v", err)
	}
	status = http.StatusTooManyRequests
	if err := p.Send(context.Background(), dev, []byte(`{}`), pushOpts{}); err == nil || errors.Is(err, errPushGone) {
		t.Errorf("429: %v", err)
	}
}

func TestPushHostAllowed(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc":            true,
		"https://updates.push.services.mozilla.com/wpush/v2": true,
		"https://web.push.apple.com/abc":                     true,
		"http://fcm.googleapis.com/fcm/send/abc":             false,
		"https://fcm.googleapis.com:8443/x":                  false,
		"https://user@fcm.googleapis.com/x":                  false,
		"https://192.0.2.8:8123/api":                         false,
		"https://fcm.googleapis.com.evil.example/x":          false,
		"https://evilpush.apple.com/x":                       false,
	} {
		if pushHostAllowed(u) != ok {
			t.Errorf("%s: want %v", u, ok)
		}
	}
}

// --- routing

type sentPush struct {
	dev string
	msg pushMsg
	o   pushOpts
}

type fakePusher struct {
	mu   sync.Mutex
	sent []sentPush
	errs map[string]error // device ID -> error
}

func (f *fakePusher) PublicKey() (string, error) { return "BKEY", nil }
func (f *fakePusher) Send(_ context.Context, d pushDevice, payload []byte, o pushOpts) error {
	var m pushMsg
	json.Unmarshal(payload, &m)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errs[d.ID]; err != nil {
		return err
	}
	f.sent = append(f.sent, sentPush{d.ID, m, o})
	return nil
}

func (f *fakePusher) take() []sentPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.sent
	f.sent = nil
	return out
}

type routerEnv struct {
	r          *notifyRouter
	push       *fakePusher
	blobs      *memBlobs
	phone, mac pushDevice
}

func newRouterEnv(t *testing.T, devs ...string) *routerEnv {
	e := &routerEnv{push: &fakePusher{errs: map[string]error{}}, blobs: &memBlobs{}}
	e.phone = newTestBrowser().device("phone", "https://fcm.googleapis.com/fcm/send/p", true)
	e.mac = newTestBrowser().device("mac", "https://fcm.googleapis.com/fcm/send/m", false)
	var s notifySettings
	for _, d := range devs {
		s.Devices = append(s.Devices, map[string]pushDevice{"phone": e.phone, "mac": e.mac}[d])
	}
	raw, _ := json.Marshal(s)
	e.blobs.Save(notifyBlob, raw)
	e.r = newNotifyRouter("https://approve.example", e.blobs, e.push)
	return e
}

func testRequest() *Request {
	return &Request{RequestIn: RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/Cloudflare/credential"}, Reason: "list zones"},
		ID: "r1", Expires: time.Now().Add(10 * time.Minute)}
}

// Without a device nobody hears of a request: the asking agent is told (and the overview says so).
func TestRouterWithoutDevices(t *testing.T) {
	e := newRouterEnv(t)
	if err := e.r.Ask(testRequest(), "u"); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Errorf("Ask without devices: %v", err)
	}
	if err := e.r.Used(Activity{Kind: "daily", Tag: "t1", Count: 1}, "u"); err != nil {
		t.Errorf("Used without devices: %v", err)
	}
	if len(e.push.take()) != 0 {
		t.Error("sent without devices")
	}
}

func TestRouterPhone(t *testing.T) {
	e := newRouterEnv(t, "phone")
	r := testRequest()
	if err := e.r.Ask(r, "https://approve.example/r/r1"); err != nil {
		t.Fatal(err)
	}
	sent := e.push.take()
	if len(sent) != 1 {
		t.Fatalf("sent %v", sent)
	}
	m := sent[0].msg
	if m.Kind != "ask" || m.Tag != "opgate-r1" || m.Silent || !m.Sticky || sent[0].o.Urgency != "high" || sent[0].o.TTL < 9*time.Minute {
		t.Errorf("ask %+v %+v", m, sent[0].o)
	}
	if len(m.Actions) != 2 || !strings.Contains(m.Actions[0].URL, "?go=approve&t="+r.goToken) || m.Actions[1].Post != "/r/r1/deny" {
		t.Errorf("actions %+v", m.Actions)
	}
	// approved: the notice is cleared; denied: a quiet outcome notice (phone default)
	e.r.Done(r, Result{Status: "approved"})
	if s := e.push.take(); len(s) != 1 || s[0].msg.Kind != "clear" || s[0].msg.Tag != "opgate-r1" {
		t.Errorf("approved: %+v", s)
	}
	r2 := testRequest()
	r2.ID = "r2"
	e.r.Ask(r2, "u")
	e.push.take()
	e.r.Done(r2, Result{Status: "denied"})
	if s := e.push.take(); len(s) != 1 || s[0].msg.Kind != "info" || !s[0].msg.Silent || !strings.HasPrefix(s[0].msg.Title, "Denied") {
		t.Errorf("denied: %+v", s)
	}
	// uses: the daily key alerts on the first use, then updates quietly
	e.r.Used(Activity{Kind: "daily", Tag: "d", Count: 1, Title: "Build key"}, "u")
	e.r.Used(Activity{Kind: "daily", Tag: "d", Count: 2, Title: "Build key"}, "u")
	s := e.push.take()
	if len(s) != 2 || s[0].msg.Silent || !s[1].msg.Silent || s[1].o.Topic != pushTopic("d") {
		t.Errorf("daily uses: %+v", s)
	}
	if s[0].msg.Actions[1].Post != "/u/d/revoke" {
		t.Errorf("revoke action %+v", s[0].msg.Actions)
	}
}

func TestRouterLevels(t *testing.T) {
	e := newRouterEnv(t, "phone", "mac")
	e.r.prefs.update(func(s *notifySettings) error {
		s.Devices[0].Levels = map[string]string{"ask": lvOff, "key": lvSilent}
		return nil
	})
	r := testRequest()
	e.r.Ask(r, "u")
	sent := e.push.take()
	if len(sent) != 1 || sent[0].dev != "mac" {
		t.Fatalf("ask: %+v", sent)
	}
	// the outcome only goes where the request went
	e.r.Done(r, Result{Status: "expired"})
	if s := e.push.take(); len(s) != 1 || s[0].dev != "mac" || s[0].msg.Kind != "clear" { // mac default: outcome off
		t.Errorf("expired: %+v", s)
	}
	e.r.Used(Activity{Kind: "key", Tag: "k", Count: 1}, "u")
	for _, s := range e.push.take() {
		if !s.msg.Silent { // phone: silent by choice; mac: silent by default
			t.Errorf("%s alerted on a key use", s.dev)
		}
	}
}

func TestRouterFailures(t *testing.T) {
	e := newRouterEnv(t, "phone")
	e.push.errs["phone"] = errors.New("push service: 500")
	if err := e.r.Ask(testRequest(), "u"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("failed push not reported: %v", err)
	}
	if st := e.r.prefs.statusOf("phone"); st.Fails != 1 || st.Err == "" {
		t.Errorf("status %+v", st)
	}
	// the browser ended the subscription: the device is marked and kept that way
	e.push.errs["phone"] = errPushGone
	e.r.Ask(testRequest(), "u")
	s, _ := e.r.prefs.get()
	if s.Devices[0].Gone.IsZero() || len(s.active()) != 0 {
		t.Fatal("gone device still active")
	}
	if s2, _ := newNotifyRouter("x", e.blobs, e.push).prefs.get(); s2.Devices[0].Gone.IsZero() {
		t.Error("gone not saved")
	}
}

// Keychain not readable: the agent is told, and defaults are never saved over the owner's settings.
func TestRouterUnreadableSettings(t *testing.T) {
	r := newNotifyRouter("x", &memBlobs{fail: errors.New("locked")}, &fakePusher{})
	if err := r.Ask(testRequest(), "u"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("Ask: %v", err)
	}
	if err := r.prefs.update(func(*notifySettings) error { return nil }); err == nil {
		t.Error("saved over unreadable settings")
	}
}

// --- the settings page

func pushEnv(t *testing.T) (*env, *routerEnv, *authenticator) {
	e := newEnv(t)
	re := newRouterEnv(t)
	e.b.push = re.r
	a := newAuthenticator("approve.example")
	e.enroll(a)
	return e, re, a
}

func (e *env) postWith(path string, body any, cookies []*http.Cookie) (int, string) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestSettingsNeedUnlock(t *testing.T) {
	e, re, a := pushEnv(t)
	br := newTestBrowser()
	sub := map[string]any{"endpoint": "https://fcm.googleapis.com/fcm/send/new", "p256dh": b64u.EncodeToString(br.key.PublicKey().Bytes()),
		"auth": b64u.EncodeToString(br.auth), "name": "Phone  ·  Chrome", "mobile": true}
	if code, _ := e.postWith("/notify/subscribe", sub, nil); code != http.StatusForbidden {
		t.Fatalf("locked subscribe: %d", code)
	}
	_, _, cookies := e.unlock(a, 0x05)
	code, body := e.postWith("/notify/subscribe", sub, cookies)
	if code != 200 {
		t.Fatalf("subscribe: %d %s", code, body)
	}
	var out struct{ ID string }
	json.Unmarshal([]byte(body), &out)
	s, _ := re.r.prefs.get()
	if len(s.Devices) != 1 || s.Devices[0].Name != "Phone · Chrome" || !s.Devices[0].Mobile || s.Devices[0].ID != out.ID {
		t.Fatalf("devices %+v", s.Devices)
	}
	// the same browser again keeps its device
	if code, _ := e.postWith("/notify/subscribe", sub, cookies); code != 200 {
		t.Fatal("resubscribe failed")
	}
	if s, _ := re.r.prefs.get(); len(s.Devices) != 1 {
		t.Error("same browser added twice")
	}
	// refused: other hosts, bad keys, unknown levels
	bad := map[string]any{"endpoint": "https://192.0.2.8:8123/api/x", "p256dh": sub["p256dh"], "auth": sub["auth"]}
	if code, _ := e.postWith("/notify/subscribe", bad, cookies); code == 200 {
		t.Error("subscription to a non-push host accepted")
	}
	bad = map[string]any{"endpoint": sub["endpoint"], "p256dh": "AAAA", "auth": sub["auth"]}
	if code, _ := e.postWith("/notify/subscribe", bad, cookies); code == 200 {
		t.Error("bad key accepted")
	}
	if code, _ := e.postWith("/notify/level", map[string]string{"id": out.ID, "cat": "ask", "level": "every"}, cookies); code == 200 {
		t.Error("level not offered for that kind accepted")
	}
	if code, b := e.postWith("/notify/level", map[string]string{"id": out.ID, "cat": "daily", "level": "off"}, cookies); code != 200 {
		t.Errorf("level: %d %s", code, b)
	}
	if code, _ := e.postWith("/notify/rename", map[string]string{"id": out.ID, "name": "Phone"}, cookies); code != 200 {
		t.Error("rename failed")
	}
	if code, _ := e.postWith("/notify/test", map[string]string{"id": out.ID}, cookies); code != 200 {
		t.Error("test failed")
	}
	s, _ = re.r.prefs.get()
	if s.Devices[0].level("daily") != lvOff || s.Devices[0].Name != "Phone" || len(re.push.take()) != 1 {
		t.Errorf("after changes: %+v", s)
	}
	// the page shows the device and its settings, never the endpoint (a capability URL)
	_, page := e.getPage("/settings", cookies...)
	if !strings.Contains(page, "Phone") || !strings.Contains(page, `id="lv-`+out.ID+`-daily-off" value="off" checked`) || strings.Contains(page, "fcm.googleapis.com") {
		t.Errorf("settings page wrong:\n%s", page)
	}
	// the overview warns that no device gets requests (the phone set to off)
	e.postWith("/notify/level", map[string]string{"id": out.ID, "cat": "ask", "level": "off"}, cookies)
	if _, ov := e.getPage("/"); !strings.Contains(ov, "No device gets approval requests") {
		t.Error("no warning on the overview")
	}
	// the browser renews its subscription without an unlock, but only for one opgate knows
	br2 := newTestBrowser()
	renew := map[string]any{"old": "https://fcm.googleapis.com/fcm/send/new", "endpoint": "https://fcm.googleapis.com/fcm/send/renewed",
		"p256dh": b64u.EncodeToString(br2.key.PublicKey().Bytes()), "auth": b64u.EncodeToString(br2.auth)}
	if code, b := e.postWith("/notify/resubscribe", renew, nil); code != 200 {
		t.Fatalf("resubscribe: %d %s", code, b)
	}
	renew["old"] = "https://fcm.googleapis.com/fcm/send/unknown"
	if code, _ := e.postWith("/notify/resubscribe", renew, nil); code == 200 {
		t.Error("unknown subscription renewed")
	}
	if code, _ := e.postWith("/notify/remove", map[string]string{"id": out.ID}, cookies); code != 200 {
		t.Error("remove failed")
	}
	if s, _ := re.r.prefs.get(); len(s.Devices) != 0 {
		t.Error("device not removed")
	}
}

// The push's Approve link starts the passkey prompt on a desktop; the bare link (an agent can open it) doesn't.
func TestApproveLinkTokenFromPush(t *testing.T) {
	e, _, _ := pushEnv(t)
	r := e.ask(cfReq)
	tok := r.goTokenFor()
	if _, page := e.getPage("/r/" + r.ID + "?go=approve&t=" + tok); !strings.Contains(page, `data-auto="1"`) {
		t.Error("push link didn't allow the prompt")
	}
	if _, page := e.getPage("/r/" + r.ID + "?go=approve&t=" + tok); strings.Contains(page, `data-auto`) {
		t.Error("the push link started the prompt a second time")
	}
	for _, q := range []string{"?go=approve", "?go=approve&t=wrong", "?go=deny&t=" + tok} {
		if _, page := e.getPage("/r/" + r.ID + q); strings.Contains(page, `data-auto`) {
			t.Errorf("%s allowed the prompt", q)
		}
	}
}

// The app's files: manifest (installable), service worker, icons.
func TestAppFiles(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.srv.URL + "/manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Display string
		Icons   []struct{ Src, Sizes, Purpose string }
	}
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/manifest+json" || m.Display != "standalone" || len(m.Icons) < 3 {
		t.Fatalf("manifest %+v %s", m, resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/sw.js", "/badge.png", "/icon-192.png", "/icon-512.png", "/icon-maskable.png"} {
		if code, _ := e.getPage(p); code != 200 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if _, page := e.getPage("/"); !strings.Contains(page, `rel="manifest"`) || !strings.Contains(page, `href="/settings"`) {
		t.Error("overview without manifest or settings link")
	}
}

// A request with a long reason and a command full of shell characters still fits in one push.
func TestPushPayloadFits(t *testing.T) {
	e := newRouterEnv(t, "phone")
	r := testRequest()
	r.Reason = strings.Repeat("why <&> ", 2000)
	r.Refs = []string{"op://Agents/a/x", "op://Agents/b/y", "op://Agents/c/z", "op://Agents/d/w", "op://Agents/e/v", "op://Agents/f/u", "op://Agents/g/t", "op://Agents/h/s"}
	if err := e.r.Ask(r, "https://approve.example/r/r1"); err != nil {
		t.Fatal(err)
	}
	m := e.push.take()[0].msg
	if raw := marshalPush(m); len(raw) > maxPushPayload || strings.Contains(string(raw), `\u003c`) {
		t.Errorf("payload %d bytes: %.120s", len(raw), raw)
	}
	if reason, who, ok := strings.Cut(m.Body, "\n"); !ok || len([]rune(reason)) > 601 || who == "" {
		t.Errorf("body: reason %d chars, who %q", len([]rune(reason)), who)
	}
}
