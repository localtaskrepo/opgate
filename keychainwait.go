package main

// Keychain calls block for as long as a macOS access prompt is open. Each build of opgate is a new app to the
// keychain items' partition list (no Apple team ID: macOS lists builds by code hash), so the first read after an
// upgrade waits until the owner answers "Always Allow" at the Mac. That prompt is wanted: codesign uses the
// local signing key without asking (only export asks), so it is what stops a rebuilt impostor from reading
// the token. But opgate must not hang silently behind it: calls get a deadline, later calls for the same item fail
// at once while one still waits, and clients and `opgate status` are told what opgate is waiting for.

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/keybase/go-keychain"
)

var errKeychainWait = errors.New("waiting for keychain access on the Mac")

type keychainWaits struct {
	timeout time.Duration
	mu      sync.Mutex
	pending map[string]time.Time // item -> when its call started
}

var kcWait = &keychainWaits{timeout: 20 * time.Second, pending: map[string]time.Time{}}

// call runs f, a keychain call for item, with the deadline. f must only write variables the caller reads after a
// nil or non-timeout error (after a timeout the call goes on in the background).
func (k *keychainWaits) call(item string, f func() error) error {
	k.mu.Lock()
	if since, ok := k.pending[item]; ok {
		k.mu.Unlock()
		return waitErr(item, since)
	}
	start := time.Now()
	k.pending[item] = start
	k.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		err := f()
		k.mu.Lock()
		delete(k.pending, item)
		k.mu.Unlock()
		if d := time.Since(start); d >= k.timeout {
			log.Printf("keychain: %s answered after %s", item, d.Round(time.Second))
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(k.timeout):
		log.Printf("keychain: no access to %s after %s: a keychain prompt for opgate is waiting on the Mac (answer it with Always Allow)",
			item, k.timeout)
		return waitErr(item, start)
	}
}

// waiting names the item opgate has waited for longest, if any call has run for more than a few seconds.
func (k *keychainWaits) waiting() (string, time.Time, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var item string
	var since time.Time
	for it, t := range k.pending {
		if since.IsZero() || t.Before(since) {
			item, since = it, t
		}
	}
	if item == "" || time.Since(since) < 3*time.Second {
		return "", time.Time{}, false
	}
	return item, since, true
}

func waitErr(item string, since time.Time) error {
	return fmt.Errorf("%w (item %s, since %s): answer the keychain prompt for opgate there with Always Allow",
		errKeychainWait, item, since.Local().Format("15:04"))
}

// The keychain refuses reads while the Mac is in dark wake (asleep, Power Nap: errSecInDarkWake) or locked
// (errSecInteractionNotAllowed). An opgate started then (a reinstall at night) holds no keys until it can read it:
// kcLocked remembers since when, so `opgate status`, clients and the signing wrapper can say why.
const errSecInDarkWake = keychain.Error(-25320)

var errKeychainLocked = errors.New("the keychain can't be read while the Mac sleeps or is locked, where no keychain prompt can show: " +
	"a new opgate build gets its keychain item by a handover the owner approves on the phone (install.sh), else by the prompt at the Mac")

type keychainLock struct {
	mu    sync.Mutex
	since time.Time // zero: the last keychain call wasn't refused for that
}

var kcLocked = &keychainLock{}

// note records the outcome of a keychain call and names the cause when the keychain refused it.
func (l *keychainLock) note(err error) error {
	var kerr keychain.Error
	refused := errors.As(err, &kerr) && (kerr == errSecInDarkWake || kerr == keychain.ErrorInteractionNotAllowed)
	if err != nil && !refused {
		return err // e.g. a prompt still waiting: says nothing about the lock
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !refused {
		if !l.since.IsZero() {
			log.Printf("keychain: readable again (refused since %s)", l.since.Local().Format("15:04"))
			l.since = time.Time{}
		}
		return nil
	}
	if l.since.IsZero() {
		l.since = time.Now()
		log.Printf("keychain: %v (%v)", errKeychainLocked, err)
	}
	return lockErr(l.since, err)
}

// locked is the error naming the lock while the keychain refuses calls.
func (l *keychainLock) locked() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.since.IsZero() {
		return nil
	}
	return lockErr(l.since, nil)
}

func lockErr(since time.Time, err error) error {
	s := fmt.Sprintf("since %s; opgate tries again every 30 s", since.Local().Format("15:04"))
	if err != nil {
		return fmt.Errorf("%w (%s): %w", errKeychainLocked, s, err)
	}
	return fmt.Errorf("%w (%s)", errKeychainLocked, s)
}
