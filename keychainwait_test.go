package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keybase/go-keychain"
)

// A keychain call that waits for a prompt times out with a clear error; while it still waits, later calls for the
// item fail at once; once it is answered, calls work again.
func TestKeychainDeadline(t *testing.T) {
	k := &keychainWaits{timeout: 50 * time.Millisecond, pending: map[string]time.Time{}}
	answer := make(chan struct{})
	start := time.Now()
	err := k.call("web-push-vapid", func() error { <-answer; return nil })
	if !errors.Is(err, errKeychainWait) || !strings.Contains(err.Error(), "web-push-vapid") || time.Since(start) > time.Second {
		t.Fatalf("first call: %v after %s", err, time.Since(start))
	}
	start = time.Now()
	if err := k.call("web-push-vapid", func() error { t.Error("ran while the prompt is open"); return nil }); !errors.Is(err, errKeychainWait) || time.Since(start) > 20*time.Millisecond {
		t.Errorf("second call: %v", err)
	}
	if err := k.call("other", func() error { return nil }); err != nil {
		t.Errorf("another item: %v", err)
	}
	k.pending["web-push-vapid"] = time.Now().Add(-time.Minute) // older than the grace period
	if item, _, ok := k.waiting(); !ok || item != "web-push-vapid" {
		t.Errorf("waiting %q %v", item, ok)
	}
	close(answer)
	for i := 0; i < 100; i++ {
		if _, _, ok := k.waiting(); !ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := k.call("web-push-vapid", func() error { return nil }); err != nil {
		t.Errorf("after the answer: %v", err)
	}
}

// While opgate waits for keychain access, clients are told so (requests fail fast, status says it).
func TestClientsToldAboutKeychainWait(t *testing.T) {
	e := newEnv(t)
	sock := filepath.Join(t.TempDir(), "s.sock")
	go e.b.serveSocket(sock)
	old := kcWait
	kcWait = &keychainWaits{timeout: time.Second, pending: map[string]time.Time{"notify-settings": time.Now().Add(-time.Minute)}}
	t.Cleanup(func() { kcWait = old })
	ask := func(body string) clientMsg {
		var c net.Conn
		var err error
		for i := 0; i < 50; i++ {
			if c, err = net.Dial("unix", sock); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(body + "\n"))
		var m clientMsg
		json.NewDecoder(c).Decode(&m)
		return m
	}
	m := ask(`{"kind":"secrets","refs":["op://Agents/Cloudflare/credential"],"reason":"test"}`)
	if m.Result == nil || m.Result.Status != "error" || !strings.Contains(m.Result.Error, "waiting for keychain access on the Mac") {
		t.Errorf("request: %+v", m.Result)
	}
	if len(e.b.Pending()) != 0 {
		t.Error("request queued anyway")
	}
	m = ask(`{"kind":"status"}`)
	if st, _ := m.Status.(map[string]any); st == nil || !strings.Contains(st["keychain"].(string), "notify-settings") {
		t.Errorf("status: %+v", m.Status)
	}
}

// A keychain refused in dark wake or while locked is named as such (in errors and status) until a call works again.
func TestKeychainLockNamed(t *testing.T) {
	old := kcLocked
	kcLocked = &keychainLock{}
	t.Cleanup(func() { kcLocked = old })
	if err := kcLocked.note(errors.New("no access")); err == nil || errors.Is(err, errKeychainLocked) || kcLocked.locked() != nil {
		t.Errorf("other error: %v", err)
	}
	for _, code := range []keychain.Error{errSecInDarkWake, keychain.ErrorInteractionNotAllowed} {
		err := kcLocked.note(fmt.Errorf("keychain: %w", code))
		if !errors.Is(err, errKeychainLocked) || !strings.Contains(err.Error(), "handover") {
			t.Errorf("%d: %v", code, err)
		}
	}
	e := newEnv(t)
	sock := filepath.Join(t.TempDir(), "s.sock")
	go e.b.serveSocket(sock)
	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if c, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(`{"kind":"status"}` + "\n"))
	var m clientMsg
	json.NewDecoder(c).Decode(&m)
	if st, _ := m.Status.(map[string]any); st == nil || !strings.Contains(fmt.Sprint(st["keychain"]), "handover") {
		t.Errorf("status: %+v", m.Status)
	}
	if err := kcLocked.note(nil); err != nil || kcLocked.locked() != nil {
		t.Errorf("after a working call: %v %v", err, kcLocked.locked())
	}
}
