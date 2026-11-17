package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func edPEM(t *testing.T, name string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, name)
	pk, _ := ssh.NewPublicKey(pub)
	return string(pem.EncodeToMemory(block)), pk
}

// sessionAs is a session whose asking process chain is ps (no real peer).
func sessionAs(a *Agent, ps []proc) session {
	s := newSession(a, nil)
	s.once.Do(func() { *s.procs = ps })
	return s
}

// The owner's 1Password keys are offered to the owner's own programs, never to agents.
func TestAgentsDontGetOwnerKeys(t *testing.T) {
	// unix socket paths must stay under 104 bytes, and t.TempDir's on macOS (/var/folders/..., named after the test) don't
	dir, err := os.MkdirTemp("/tmp", "og") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "1p.sock")
	ring := agent.NewKeyring()
	ownerPEM, ownerPub := edPEM(t, "owner")
	raw, _ := ssh.ParseRawPrivateKey([]byte(ownerPEM))
	ring.Add(agent.AddedKey{PrivateKey: raw, Comment: "owner"})
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(ring, c)
		}
	}()
	ag := newAgent(sock)
	minePEM, minePub := edPEM(t, "agent")
	if err := ag.AddKey(minePEM, "op://Agents/opgate build key/private key", 0); err != nil {
		t.Fatal(err)
	}
	human := sessionAs(ag, []proc{{Exe: "/usr/bin/ssh"}, {Exe: "/bin/zsh"}, {Exe: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}})
	bot := sessionAs(ag, []proc{{Exe: "/usr/bin/ssh"}, {Exe: "/bin/bash"}, {Exe: "/opt/homebrew/Caskroom/claude-code/2.1/claude"}})
	defer human.close()
	defer bot.close()
	if keys, _ := human.List(); len(keys) != 2 {
		t.Errorf("owner's terminal sees %d keys, want 2", len(keys))
	}
	if _, err := human.Sign(ownerPub, []byte("x")); err != nil {
		t.Errorf("owner's terminal can't sign: %v", err)
	}
	if keys, _ := bot.List(); len(keys) != 1 {
		t.Errorf("agent sees %d keys, want only opgate's", len(keys))
	}
	if _, err := bot.Sign(ownerPub, []byte("x")); !errors.Is(err, errOwnerKeys) {
		t.Errorf("agent signed with the owner's key: %v", err)
	}
	if sig, err := bot.Sign(minePub, []byte("x")); err != nil || minePub.Verify([]byte("x"), sig) != nil {
		t.Errorf("agent can't use opgate's key: %v", err)
	}
}

// Approving ssh-add for an autoloaded key must not give it a lifetime (git signing would stop when it ends).
func TestAutoloadedKeyKeepsNoLifetime(t *testing.T) {
	ag := newAgent("/nonexistent")
	p, _ := edPEM(t, "agent")
	ref := "op://Agents/opgate build key/private key"
	ag.AddKey(p, ref, 0)
	if err := ag.AddKey(p, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	if k, ok := ag.LoadedRef(ref); !ok || !k.Until.IsZero() {
		t.Errorf("autoloaded key got a lifetime: %+v", k)
	}
}

// A caller whose executable was deleted (Homebrew upgraded the agent while it ran) has no path: the kernel's
// process name still names it, and a process known by neither never gets the owner's keys.
func TestDeletedExecutableFailsClosed(t *testing.T) {
	ag := newAgent("/nonexistent")
	for _, chain := range [][]proc{
		{{Exe: "/usr/bin/ssh"}, {Exe: "/bin/zsh"}, {Exe: ""}},
		{{Exe: "/usr/bin/ssh"}, {Exe: "/bin/zsh"}, {Exe: "", Name: "claude"}, {Exe: "/Applications/T3 Code.app/Contents/MacOS/T3 Code"}},
	} {
		if !sessionAs(ag, chain).fromAgent() {
			t.Errorf("chain %+v counts as the owner's", chain)
		}
	}
}

// procInfo falls back to the kernel's process name when the executable is gone.
func TestProcInfoNamesDeletedExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "claude")
	body, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, body, 0o755); err != nil {
		t.Fatal(err)
	}
	// a copied system binary is killed at exec until it carries a signature of its own
	if out, err := exec.Command("/usr/bin/codesign", "--force", "-s", "-", exe).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v %s", err, out)
	}
	cmd := exec.Command(exe, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; i < 200; i++ { // Start returns after the fork: remove the file only once it runs
		if p, _, _ := procInfo(cmd.Process.Pid); p.Exe != "" && filepath.Base(p.Exe) == "claude" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	p, _, ok := procInfo(cmd.Process.Pid)
	if !ok || p.Exe != "" || procLabel(p) != "Claude Code" {
		t.Errorf("deleted executable not named: %+v", p)
	}
}
