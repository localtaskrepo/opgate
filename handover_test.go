package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A build without its own item reads the newest older build's item once (the prompt at the Mac), keeps a copy and
// from then on reads only its own; saves go to its own item.
func TestKeychainStoreOwnItem(t *testing.T) {
	kc := &fakeKC{items: map[string][]byte{
		keychainStoreAccount: []byte(`{"service-account-token":"b2xk"}`),     // "old", the shared item before 0.23.0
		"store-aaaa":         []byte(`{"service-account-token":"bmV3ZXI="}`), // "newer", the build before this one
	}, gets: map[string]int{}, fail: map[string]error{},
		mod: map[string]time.Time{keychainStoreAccount: time.Unix(1, 0), "store-aaaa": time.Unix(2, 0)}, clock: time.Unix(10, 0)}
	s := &keychainStore{kc: kc, own: "store-bbbb"}
	for range 2 {
		if v, err := s.load("service-account-token"); err != nil || string(v) != "newer" {
			t.Fatalf("token %q %v", v, err)
		}
	}
	if kc.gets["store-aaaa"] != 1 || kc.gets[keychainStoreAccount] != 0 {
		t.Errorf("other builds' items read %v", kc.gets)
	}
	if err := s.save("notify-settings", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kc.items["store-bbbb"]), "notify-settings") || strings.Contains(string(kc.items["store-aaaa"]), "notify-settings") {
		t.Errorf("saved to %v", kc.items)
	}
}

// serve deletes older builds' items once it has its own, but not one made after it (a new build that got its item
// from this one and isn't installed yet), nor the shared item older builds read.
func TestKeychainStorePrune(t *testing.T) {
	kc := &fakeKC{items: map[string][]byte{keychainStoreAccount: []byte(`{}`), "store-aaaa": []byte(`{}`)},
		gets: map[string]int{}, fail: map[string]error{}, clock: time.Unix(10, 0)}
	s := &keychainStore{kc: kc, own: "store-bbbb"}
	s.prune() // no item of its own yet: nothing goes
	if len(kc.items) != 2 {
		t.Fatalf("pruned without an own item: %v", kc.items)
	}
	if err := s.adopt(map[string][]byte{"service-account-token": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	kc.put("store-cccc", []byte(`{}`))
	s.prune()
	if _, ok := kc.items["store-aaaa"]; ok {
		t.Errorf("older build's item kept: %v", kc.items)
	}
	for _, a := range []string{keychainStoreAccount, "store-bbbb", "store-cccc"} {
		if _, ok := kc.items[a]; !ok {
			t.Errorf("%s deleted", a)
		}
	}
	if err := s.adopt(nil); err == nil {
		t.Error("empty handover adopted")
	}
}

// The running build hands its store to a new one only after the passkey approval, and only to a process that passes
// the peer check; a refused peer reaches nobody.
func TestHandover(t *testing.T) {
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	e.b.kcSnapshot = func() (map[string][]byte, error) {
		return map[string][]byte{"service-account-token": []byte("ops_x")}, nil
	}
	peerErr := errors.New("not an opgate build")
	old := checkHandoverPeer
	t.Cleanup(func() { checkHandoverPeer = old })
	checkHandoverPeer = func([]proc, string) error { return peerErr }
	in := RequestIn{Kind: KindHandover, Name: "0123456789abcdef01234567", Reason: "install opgate 0.23.0"}
	asked := len(e.note.asked)
	if _, err := e.b.Submit(in, []string{"/tmp/evil handover"}); err == nil || !strings.Contains(err.Error(), "nobody was asked") {
		t.Fatalf("bad peer: %v", err)
	}
	if bad := (RequestIn{Kind: KindHandover, Name: "x", Reason: in.Reason}); func() error { _, err := e.b.Submit(bad, nil); return err }() == nil {
		t.Fatal("handover without a build id accepted")
	}
	if len(e.note.asked) != asked {
		t.Fatalf("phone asked for a refused handover: %v", e.note.asked)
	}
	checkHandoverPeer = func([]proc, string) error { return nil }
	r := e.ask(in, "/Users/x/.local/bin/opgate.new handover", "bash ./install.sh")
	resp, err := http.Get(e.srv.URL + "/r/" + r.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "New opgate build") || !strings.Contains(string(page), "keychain store") {
		t.Errorf("page doesn't say what it hands over: %s", page)
	}
	if d := durationOptions(r); d != nil {
		t.Errorf("handover offers %v (no same-again grant)", d)
	}
	if code, body := e.approve(a, r, "15m", 0x05); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	res := e.b.Wait(context.Background(), r)
	var m map[string][]byte
	if res.Status != "approved" || json.Unmarshal(res.Payload, &m) != nil || string(m["service-account-token"]) != "ops_x" {
		t.Fatalf("result %+v", res)
	}
	if len(e.b.grants) != 0 {
		t.Errorf("handover left a grant: %v", e.b.grants)
	}
}
