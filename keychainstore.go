package main

// All of opgate's keychain data (service account token, VAPID key, notification settings) lives in one item of
// service appID (config.go). Each build keeps its own item, account "store-<build>" (buildID): an item a build
// created itself it reads without a prompt, while an item of another build needs "Always Allow" at the Mac
// (keychainwait.go), which nobody answers while the owner is away. A new build gets its item from the running one
// (`opgate handover`, approved on the phone), or else copies the newest item of an older build once, after
// that prompt. Builds before 0.23.0 shared one item "store"; builds before 0.18.2 kept one item per value, and the
// first read of a value missing from the store copies it over from its old item.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/keybase/go-keychain"
)

const keychainStoreAccount = "store" // the shared item of builds before 0.23.0

// kcItem is one of opgate's keychain items, by its attributes (listing them needs no prompt).
type kcItem struct {
	Account string
	Mod     time.Time
}

// kcBackend reads, writes, lists and deletes opgate's keychain items by account (get: nil, nil for no such item).
type kcBackend interface {
	get(account string) ([]byte, error)
	put(account string, b []byte) error
	list() ([]kcItem, error)
	del(account string) error
}

type keychainStore struct {
	mu  sync.Mutex
	kc  kcBackend
	own string // this build's account (ownAccount)
}

var kcStore = &keychainStore{kc: realKeychain{}}

// buildID names this build by its executable's content: the same bytes after install.sh moves opgate.new into
// place, a different one for every rebuild (as the keychain sees it: macOS lists builds by code hash).
func buildID() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return "", err
	}
	return fileBuildID(exe)
}

func fileBuildID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)[:12]), nil
}

func (s *keychainStore) ownAccount() string {
	if s.own == "" {
		id, err := buildID()
		if err != nil {
			id = "unknown" // can't happen for a running binary; an item named so still works
		}
		s.own = keychainStoreAccount + "-" + id
	}
	return s.own
}

// storeAccount: an item holding a whole store (this build's, another build's or the old shared one).
func storeAccount(a string) bool {
	return a == keychainStoreAccount || strings.HasPrefix(a, keychainStoreAccount+"-")
}

// readAll is the store's values; an unreadable store is an error, never an empty store (saving that would wipe
// the token). Without an item of its own, the build reads the newest store item of another build (a prompt at the
// Mac) and keeps a copy in its own, so it asks only once.
func (s *keychainStore) readAll() (map[string][]byte, error) {
	own := s.ownAccount()
	raw, err := s.kc.get(own)
	if err != nil {
		return nil, err
	}
	from := ""
	if raw == nil {
		if from, err = s.newest(); err != nil {
			return nil, err
		}
		if from != "" {
			if raw, err = s.kc.get(from); err != nil {
				return nil, err
			}
		}
	}
	m := map[string][]byte{}
	if raw != nil {
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("keychain store unreadable: %w", err)
		}
	}
	if from != "" && raw != nil {
		if err := s.kc.put(own, raw); err != nil {
			log.Printf("keychain: copying %s into this build's item %s: %v", from, own, err) // still usable this time
		} else {
			log.Printf("keychain: copied %s into this build's item %s", from, own)
		}
	}
	return m, nil
}

// newest is the most recently changed store item of another build ("" if there is none).
func (s *keychainStore) newest() (string, error) {
	items, err := s.kc.list()
	if err != nil {
		return "", err
	}
	var best kcItem
	for _, it := range items {
		if storeAccount(it.Account) && it.Account != s.ownAccount() && (best.Account == "" || it.Mod.After(best.Mod)) {
			best = it
		}
	}
	return best.Account, nil
}

// snapshot is everything in the store, for `opgate handover` (the running build gives it to a new one).
func (s *keychainStore) snapshot() (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAll()
}

// adopt writes a store handed over by the running build into this build's own item.
func (s *keychainStore) adopt(m map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(m) == 0 {
		return errors.New("the running build handed over an empty store")
	}
	return s.writeAll(m)
}

// hasOwn: this build has its own item (it reads it without a prompt).
func (s *keychainStore) hasOwn() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.kc.list()
	if err != nil {
		return false, err
	}
	for _, it := range items {
		if it.Account == s.ownAccount() {
			return true, nil
		}
	}
	return false, nil
}

// prune deletes the items of builds older than this build's own item (serve, once this build has one). Items
// changed after it stay: a new build may have just got its item from this one and not be installed yet. The old
// shared "store" item stays too, as builds before 0.23.0 read it.
func (s *keychainStore) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.kc.list()
	if err != nil {
		log.Printf("keychain: listing opgate's items: %v", err)
		return
	}
	var mine time.Time
	for _, it := range items {
		if it.Account == s.ownAccount() {
			mine = it.Mod
		}
	}
	if mine.IsZero() {
		return
	}
	for _, it := range items {
		if strings.HasPrefix(it.Account, keychainStoreAccount+"-") && it.Account != s.ownAccount() && it.Mod.Before(mine) {
			if err := s.kc.del(it.Account); err != nil {
				log.Printf("keychain: deleting the old build's item %s: %v", it.Account, err)
			} else {
				log.Printf("keychain: deleted the old build's item %s", it.Account)
			}
		}
	}
}

func (s *keychainStore) load(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readAll()
	if err != nil {
		return nil, err
	}
	if v, ok := m[name]; ok {
		return v, nil
	}
	old, err := s.kc.get(name) // the item of a build before 0.18.2
	if err != nil || old == nil {
		return old, err
	}
	m[name] = old
	if err := s.writeAll(m); err != nil {
		log.Printf("keychain: copying %s into the store: %v", name, err) // still usable this time
	} else {
		log.Printf("keychain: moved %s into the store (its old item can be deleted in Keychain Access)", name)
	}
	return old, nil
}

func (s *keychainStore) save(name string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readAll()
	if err != nil {
		return err
	}
	m[name] = b
	return s.writeAll(m)
}

func (s *keychainStore) writeAll(m map[string][]byte) error {
	raw, _ := json.Marshal(m)
	return s.kc.put(s.ownAccount(), raw)
}

// keychainCheck is `opgate keychain-check`, which install.sh runs with a new build before installing it (when
// `opgate handover` couldn't give it its own item). A new build is a new app to the other builds' items (its code
// hash), so its first read needs a prompt at the Mac, and while the Mac sleeps or is locked that prompt can't show
// (-25320, errSecInDarkWake). Started anyway, it would drop the keys the running build holds until someone answers at
// the Mac. fresh is the second check, from a new process with a short deadline: a read that still waits
// for a prompt there means the build couldn't keep its copy, and the restarted service would ask again.
func keychainCheck(s *keychainStore, fresh bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.readAll()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errKeychainLocked):
		return fmt.Errorf("this build can't read its keychain item: the Mac is asleep or locked and can't show the keychain prompt (%w)", err)
	case fresh && errors.Is(err, errKeychainWait):
		return fmt.Errorf("this build can read its keychain item only after another prompt (answered with Allow, not Always Allow): %w", err)
	}
	return fmt.Errorf("this build can't read its keychain item: %w", err)
}

// realKeychain is the login keychain, each call with kcWait's deadline and noted by kcLocked.
type realKeychain struct{}

func (realKeychain) get(account string) ([]byte, error) {
	var out []byte
	err := kcWait.call(account, func() error {
		var err error
		out, err = keychainLoad(account)
		return err
	})
	return out, kcLocked.note(err)
}

func (realKeychain) put(account string, b []byte) error {
	return kcLocked.note(kcWait.call(account, func() error { return keychainSave(account, b) }))
}

// list reads attributes only, which needs no prompt.
func (realKeychain) list() ([]kcItem, error) {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(appID)
	q.SetMatchLimit(keychain.MatchLimitAll)
	q.SetReturnAttributes(true)
	res, err := keychain.QueryItem(q)
	if err != nil {
		return nil, kcLocked.note(fmt.Errorf("keychain: %w", err))
	}
	var out []kcItem
	for _, r := range res {
		out = append(out, kcItem{Account: r.Account, Mod: r.ModificationDate})
	}
	return out, nil
}

// del goes through Apple's security tool: the keychain API refuses even an item's creator a delete without the
// owner's approval (errSecInvalidOwnerEdit), the tool deletes without asking.
func (realKeychain) del(account string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password", "-s", appID, "-a", account).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
