package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent is the ssh agent behind AgentSocket: opgate's own keys (autoloaded ones and approved ones with a
// lifetime) first, then the keys of the 1Password agent, so the owner's own sessions work as before. Clients can't
// add, remove or lock keys; only opgate loads them. Agents (Claude Code, Codex, Kilo, from the kernel's process
// chain) only get opgate's keys: 1Password sees every client as opgate, so one Touch ID for the owner's own git
// would otherwise let any agent use the owner's keys until 1Password locks.
type Agent struct {
	own      agent.Agent // keyring with lifetimes
	upstream string
	mu       sync.Mutex
	meta     map[string]*keyMeta // fingerprint -> where it came from

	// OnUse is called (in its own goroutine) each time one of opgate's keys signs: which key, the asking process
	// chain (ssh and its parents), and how often this load of the key has been used.
	OnUse func(m keyMeta, fp string, ps []proc)
	// OnUpstream is called when one of the 1Password agent's keys signed through opgate's agent (approved in
	// 1Password): the key's comment and the asking process chain.
	OnUpstream func(comment string, ps []proc)
}

type keyMeta struct {
	Ref    string
	Loaded time.Time
	Until  time.Time // zero: no lifetime (autoloaded)
	Uses   int
}

var errReadOnly = errors.New("opgate agent: keys are only loaded by opgate")

func newAgent(upstream string) *Agent {
	return &Agent{own: agent.NewKeyring(), upstream: upstream, meta: map[string]*keyMeta{}}
}

// AddKey parses a private key (OpenSSH or PKCS#8) and loads it; ttl 0 keeps it until opgate stops.
func (a *Agent) AddKey(pem, ref string, ttl time.Duration) error {
	raw, err := ssh.ParseRawPrivateKey([]byte(pem))
	if err != nil {
		return fmt.Errorf("not a private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return err
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	a.mu.Lock()
	if old := a.meta[fp]; old != nil && old.Until.IsZero() && a.ownHas(fp) {
		ttl = 0 // loaded without a lifetime already (autoloaded): an approval must not make it expire
	}
	a.mu.Unlock()
	k := agent.AddedKey{PrivateKey: raw, Comment: "opgate " + ref}
	m := &keyMeta{Ref: ref, Loaded: time.Now()}
	if ttl > 0 {
		k.LifetimeSecs = uint32(max(1, (ttl+time.Second-1)/time.Second)) // 0 would mean "forever"
		m.Until = time.Now().Add(ttl)
	}
	if err := a.own.Add(k); err != nil {
		return err
	}
	a.mu.Lock()
	a.meta[fp] = m
	for f := range a.meta { // forget keys that expired
		if !a.ownHas(f) {
			delete(a.meta, f)
		}
	}
	a.mu.Unlock()
	return nil
}

// ownHas reports whether a key with this fingerprint is in opgate's keyring (expired ones are gone).
func (a *Agent) ownHas(fp string) bool {
	keys, _ := a.own.List()
	for _, k := range keys {
		if pk, err := ssh.ParsePublicKey(k.Blob); err == nil && ssh.FingerprintSHA256(pk) == fp {
			return true
		}
	}
	return false
}

// loadedFP returns the loaded key with this fingerprint, if any.
func (a *Agent) loadedFP(fp string) (LoadedKey, bool) {
	for _, k := range a.Loaded() {
		if k.FP == fp {
			return k, true
		}
	}
	return LoadedKey{}, false
}

// LoadedRef returns the loaded key from ref, if any.
func (a *Agent) LoadedRef(ref string) (LoadedKey, bool) {
	for _, k := range a.Loaded() {
		if k.Ref == ref {
			return k, true
		}
	}
	return LoadedKey{}, false
}

// Remove unloads one of opgate's keys (revoked on the phone). An autoloaded key comes back with `opgate reload`.
func (a *Agent) Remove(fp string) {
	keys, _ := a.own.List()
	for _, k := range keys {
		if pk, err := ssh.ParsePublicKey(k.Blob); err == nil && ssh.FingerprintSHA256(pk) == fp {
			if err := a.own.Remove(pk); err != nil {
				log.Printf("agent: unload %s: %v", fp, err)
			}
		}
	}
	a.mu.Lock()
	delete(a.meta, fp)
	a.mu.Unlock()
}

// HasRef reports whether a key from ref is loaded (and not expired).
func (a *Agent) HasRef(ref string) bool {
	_, ok := a.LoadedRef(ref)
	return ok
}

// LoadedKey is one of opgate's keys that is loaded now.
type LoadedKey struct {
	FP string
	keyMeta
}

// Loaded lists opgate's own loaded keys (expired ones are gone from the keyring already).
func (a *Agent) Loaded() []LoadedKey {
	keys, _ := a.own.List()
	var out []LoadedKey
	for _, k := range keys {
		pk, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		fp := ssh.FingerprintSHA256(pk)
		a.mu.Lock()
		if m := a.meta[fp]; m != nil {
			out = append(out, LoadedKey{FP: fp, keyMeta: *m})
		}
		a.mu.Unlock()
	}
	return out
}

// Keys lists opgate's own keys with their origin (status).
func (a *Agent) Keys() []string {
	keys, _ := a.own.List()
	var out []string
	for _, k := range keys {
		pk, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		fp := ssh.FingerprintSHA256(pk)
		a.mu.Lock()
		m := keyMeta{}
		if p := a.meta[fp]; p != nil {
			m = *p
		}
		a.mu.Unlock()
		until := "no lifetime"
		if !m.Until.IsZero() {
			until = "until " + m.Until.Format(time.TimeOnly)
		}
		out = append(out, fmt.Sprintf("%s %s (%s)", fp, m.Ref, until))
	}
	return out
}

func (a *Agent) isOwn(key ssh.PublicKey) bool {
	keys, _ := a.own.List()
	for _, k := range keys {
		if bytes.Equal(k.Blob, key.Marshal()) {
			return true
		}
	}
	return false
}

// session is one client connection. The asking process chain is looked up once, when first needed. The 1Password
// agent is reached over one connection per session, so a session-bind (the host ssh connects to) reaches the
// signature that follows it.
type session struct {
	a     *Agent
	conn  *net.UnixConn
	once  *sync.Once
	procs *[]proc
	up    *upstream
}

type upstream struct {
	mu   sync.Mutex
	conn net.Conn
	ag   agent.ExtendedAgent
}

func newSession(a *Agent, c *net.UnixConn) session {
	return session{a: a, conn: c, once: &sync.Once{}, procs: new([]proc), up: &upstream{}}
}

// upstream dials the 1Password agent on first use; the caller holds s.up.mu.
func (s session) upstreamLocked() (agent.ExtendedAgent, error) {
	if s.up.ag == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", s.a.upstream)
		if err != nil {
			return nil, err
		}
		s.up.conn, s.up.ag = c, agent.NewClient(c)
	}
	return s.up.ag, nil
}

func (s session) close() {
	s.up.mu.Lock()
	if s.up.conn != nil {
		s.up.conn.Close()
	}
	s.up.mu.Unlock()
}

// fromAgent: an agent app is among the asking process's ancestors (kernel facts, identity.go), or an ancestor has no
// executable path (deleted while running): that one can't be told apart, so it counts as an agent.
func (s session) fromAgent() bool {
	for _, p := range s.callerChain()[min(1, len(s.callerChain())):] {
		if p.Exe == "" || procLabel(p) != "" {
			return true
		}
	}
	return false
}

var errOwnerKeys = errors.New("opgate agent: agents can't use the owner's 1Password keys (load the key with opgate ssh-add)")

func (s session) callerChain() []proc {
	if s.conn != nil {
		s.once.Do(func() { *s.procs = peerProcs(s.conn) })
	}
	return *s.procs
}

// used counts a signature with one of opgate's own keys and reports it.
func (s session) used(key ssh.PublicKey) {
	fp := ssh.FingerprintSHA256(key)
	s.a.mu.Lock()
	m := s.a.meta[fp]
	var snap keyMeta
	if m != nil {
		m.Uses++
		snap = *m
	}
	s.a.mu.Unlock()
	if m != nil && s.a.OnUse != nil {
		go s.a.OnUse(snap, fp, s.callerChain())
	}
}

func (s session) List() ([]*agent.Key, error) {
	keys, _ := s.a.own.List()
	if s.fromAgent() {
		return keys, nil
	}
	s.up.mu.Lock()
	defer s.up.mu.Unlock()
	if up, err := s.upstreamLocked(); err == nil {
		if more, err := up.List(); err == nil {
			keys = append(keys, more...)
		}
	}
	return keys, nil
}

func (s session) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.SignWithFlags(key, data, 0)
}

func (s session) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if s.a.isOwn(key) {
		own, ok := s.a.own.(agent.ExtendedAgent)
		if !ok {
			return nil, errors.New("opgate agent: the keyring can't sign with flags")
		}
		sig, err := own.SignWithFlags(key, data, flags)
		if err == nil {
			s.used(key)
		}
		return sig, err
	}
	if s.fromAgent() {
		log.Printf("agent: refused an agent the owner's key %s", ssh.FingerprintSHA256(key))
		return nil, errOwnerKeys
	}
	s.up.mu.Lock()
	defer s.up.mu.Unlock()
	up, err := s.upstreamLocked()
	if err != nil {
		return nil, fmt.Errorf("1Password agent: %w", err)
	}
	sig, err := up.SignWithFlags(key, data, flags)
	if err == nil && s.a.OnUpstream != nil {
		comment := ssh.FingerprintSHA256(key)
		if keys, lerr := up.List(); lerr == nil {
			for _, k := range keys {
				if bytes.Equal(k.Blob, key.Marshal()) && k.Comment != "" {
					comment = k.Comment
				}
			}
		}
		go s.a.OnUpstream(comment, s.callerChain())
	}
	return sig, err
}

func (s session) Add(agent.AddedKey) error       { return errReadOnly }
func (s session) Remove(ssh.PublicKey) error     { return errReadOnly }
func (s session) RemoveAll() error               { return errReadOnly }
func (s session) Lock([]byte) error              { return errReadOnly }
func (s session) Unlock([]byte) error            { return errReadOnly }
func (s session) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }

// Extension passes extensions (session-bind@openssh.com) on to the 1Password agent over the session's connection,
// so the binding applies to the signature that follows (1Password shows the host in its prompt).
func (s session) Extension(t string, contents []byte) ([]byte, error) {
	if s.fromAgent() {
		return nil, agent.ErrExtensionUnsupported
	}
	s.up.mu.Lock()
	defer s.up.mu.Unlock()
	up, err := s.upstreamLocked()
	if err != nil {
		return nil, agent.ErrExtensionUnsupported
	}
	return up.Extension(t, contents)
}

// Serve listens on path (0600) until the listener fails.
func (a *Agent) Serve(path string) error {
	os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			s := newSession(a, c)
			defer s.close()
			// ServeAgent returns only with an error; EOF is the client hanging up
			if err := agent.ServeAgent(s, c); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("agent: %v", err)
			}
		}()
	}
}
