package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeKC struct {
	items map[string][]byte
	gets  map[string]int
	fail  map[string]error
	mod   map[string]time.Time // unset: the zero time (an item from before the test)
	clock time.Time
}

func (f *fakeKC) get(a string) ([]byte, error) {
	f.gets[a]++
	if err := f.fail[a]; err != nil {
		return nil, err
	}
	return f.items[a], nil
}

func (f *fakeKC) put(a string, b []byte) error {
	if err := f.fail[a]; err != nil {
		return err
	}
	f.items[a] = b
	if f.mod == nil {
		f.mod = map[string]time.Time{}
	}
	f.clock = f.clock.Add(time.Second)
	f.mod[a] = f.clock
	return nil
}

func (f *fakeKC) list() ([]kcItem, error) {
	var out []kcItem
	for a := range f.items {
		out = append(out, kcItem{Account: a, Mod: f.mod[a]})
	}
	return out, nil
}

func (f *fakeKC) del(a string) error {
	delete(f.items, a)
	return nil
}

// Values of older builds move into the one store item once; after that only the store is read.
func TestKeychainStoreMigrates(t *testing.T) {
	kc := &fakeKC{items: map[string][]byte{"service-account-token": []byte("ops_x"), "web-push-vapid": []byte("k")},
		gets: map[string]int{}, fail: map[string]error{}}
	s := &keychainStore{kc: kc}
	for range 2 {
		if v, err := s.load("service-account-token"); err != nil || string(v) != "ops_x" {
			t.Fatalf("token %q %v", v, err)
		}
		if v, _ := s.load("web-push-vapid"); string(v) != "k" {
			t.Fatalf("vapid %q", v)
		}
	}
	if kc.gets["service-account-token"] != 1 || kc.gets["web-push-vapid"] != 1 {
		t.Errorf("old items read %v", kc.gets)
	}
	if v, err := s.load("notify-settings"); v != nil || err != nil { // never stored: nothing, no error
		t.Errorf("missing %q %v", v, err)
	}
	if err := s.save("notify-settings", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	m, _ := s.readAll()
	if len(m) != 3 || string(m["service-account-token"]) != "ops_x" {
		t.Errorf("store %v", m)
	}
}

// A store that can't be read (prompt open, corrupt) is never saved over: that would drop the token.
func TestKeychainStoreNoOverwrite(t *testing.T) {
	kc := &fakeKC{items: map[string][]byte{keychainStoreAccount: []byte(`{"service-account-token":"b3BzX3g="}`)},
		gets: map[string]int{}, fail: map[string]error{keychainStoreAccount: errKeychainWait}}
	s := &keychainStore{kc: kc}
	if err := s.save("notify-settings", []byte("{}")); !errors.Is(err, errKeychainWait) {
		t.Errorf("save while waiting: %v", err)
	}
	kc.fail = map[string]error{}
	kc.items[keychainStoreAccount] = []byte("not json")
	if err := s.save("notify-settings", []byte("{}")); err == nil || string(kc.items[keychainStoreAccount]) != "not json" {
		t.Errorf("corrupt store overwritten: %v", err)
	}
}

// install.sh runs keychain-check with a new build before installing it: a build that can't read the store (no
// "Always Allow" yet, -25320 while the Mac sleeps) must fail it, so the running build keeps its keys.
func TestKeychainCheck(t *testing.T) {
	kc := &fakeKC{items: map[string][]byte{}, gets: map[string]int{}, fail: map[string]error{}}
	if err := keychainCheck(&keychainStore{kc: kc}, false); err != nil {
		t.Fatalf("no store yet (first install): %v", err)
	}
	kc.items[keychainStoreAccount] = []byte(`{"service-account-token":"b3BzX3g="}`)
	for _, fresh := range []bool{false, true} {
		if err := keychainCheck(&keychainStore{kc: kc}, fresh); err != nil {
			t.Fatalf("readable store (fresh %v): %v", fresh, err)
		}
	}
	kc = &fakeKC{items: map[string][]byte{keychainStoreAccount: []byte(`{}`)}, gets: map[string]int{},
		fail: map[string]error{keychainStoreAccount: lockErr(time.Now(), fmt.Errorf("keychain: %w", errSecInDarkWake))}}
	if err := keychainCheck(&keychainStore{kc: kc}, false); err == nil || !strings.Contains(err.Error(), "asleep") {
		t.Fatalf("dark wake: %v", err)
	}
}

// The first check passes after a one-time "Allow" too; the second, from a new process, then waits for another prompt
// and must fail, or install.sh would stop the running build for one that asks again.
func TestKeychainCheckFreshAfterOneTimeAllow(t *testing.T) {
	kc := &fakeKC{items: map[string][]byte{keychainStoreAccount: []byte(`{}`)}, gets: map[string]int{}, fail: map[string]error{}}
	kc.fail[keychainStoreAccount] = waitErr(keychainStoreAccount, time.Now())
	err := keychainCheck(&keychainStore{kc: kc}, true)
	if err == nil || !strings.Contains(err.Error(), "not Always Allow") {
		t.Fatalf("prompt in a fresh process: %v", err)
	}
}
