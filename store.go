package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// The service account token lives in the login keychain, in the item created by opgate itself (keychainstore.go), so macOS lets only
// this binary read it without asking: anything else (an agent's `security find-generic-password`) gets a password
// dialog, which nobody answers while the owner is away. A rebuilt binary is a different app to the keychain's
// partition list: its first read asks at the Mac ("Always Allow"; keychainwait.go keeps opgate serving meanwhile).
// The keychain service is appID (config.go).
const keychainAccount = "service-account-token"

func loadToken() (string, error) {
	b, err := kcStore.load(keychainAccount)
	if err != nil {
		return "", fmt.Errorf("keychain: %w", err)
	}
	if len(b) == 0 {
		return "", errors.New("no service account token in the keychain: run `opgate bootstrap <op ref>` at the Mac")
	}
	return string(b), nil
}

func storeToken(token string) error { return kcStore.save(keychainAccount, []byte(token)) }

// bootstrap reads the service account token with the owner's own 1Password (Touch ID) and stores it.
func bootstrap(ctx context.Context, ref string) error {
	if !strings.HasPrefix(ref, "op://") {
		return errors.New("usage: opgate bootstrap op://<vault>/<item>/<field>")
	}
	// always 1Password's own CLI, checked: a wrapper there (or $OPGATE_REAL_OP) would see the token
	const op = "/opt/homebrew/bin/op"
	if err := exec.CommandContext(ctx, "codesign", "--verify", "-R=anchor apple generic and certificate leaf[subject.OU] = \"2BUA8C4S2C\"", op).Run(); err != nil {
		return fmt.Errorf("%s is not 1Password's signed op: %w", op, err)
	}
	cmd := exec.CommandContext(ctx, op, "read", "--no-newline", ref)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("op read: %w", err)
	}
	tok := strings.TrimSpace(string(out))
	if !strings.HasPrefix(tok, "ops_") {
		return errors.New("that is not a service account token (expected ops_...)")
	}
	if err := storeToken(tok); err != nil {
		return err
	}
	// check it works before saying so
	s := &opStore{}
	if _, err := s.client(context.Background()); err != nil {
		return fmt.Errorf("stored, but the token doesn't work: %w", err)
	}
	return nil
}

// opStore resolves references with the service account (1Password SDK, token never leaves this process).
type opStore struct {
	mu sync.Mutex
	c  *onepassword.Client
}

func (s *opStore) client(ctx context.Context) (*onepassword.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.c != nil {
		return s.c, nil
	}
	tok, err := loadToken()
	if err != nil {
		return nil, err
	}
	c, err := onepassword.NewClient(ctx, onepassword.WithServiceAccountToken(tok), onepassword.WithIntegrationInfo("opgate", version))
	if err != nil {
		return nil, err // not cached: the next call reads the keychain again
	}
	s.c = c
	return c, nil
}

// Resolve reads a reference; "op://<vault>/<item>?document" reads a Document item's file.
func (s *opStore) Resolve(ctx context.Context, ref string) (string, error) {
	c, err := s.client(ctx)
	if err != nil {
		return "", err
	}
	if base, ok := strings.CutSuffix(ref, "?document"); ok {
		return readDocument(ctx, c, base)
	}
	v, err := readWithFallback(ctx, sdkDirectory{c}, ref, func(r string) (string, error) { return c.Secrets().Resolve(ctx, r) })
	if err != nil && authError(err) {
		s.reset() // a rotated token (opgate bootstrap) takes effect on the next read, without a restart
	}
	return v, err
}

// Check finds the reference's vault and item (checkItem). An error, also when 1Password can't be asked, refuses the
// request before the owner is asked: reading it after approval would fail the same way.
func (s *opStore) Check(ctx context.Context, ref string) error {
	c, err := s.client(ctx)
	if err != nil {
		return err
	}
	err = checkItem(ctx, sdkDirectory{c}, ref)
	if err != nil && authError(err) {
		s.reset()
	}
	return err
}

func (s *opStore) reset() {
	s.mu.Lock()
	s.c = nil
	s.mu.Unlock()
}

// authError: the service account token was refused (rotated, revoked or expired).
func authError(err error) bool {
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "unauthori") || strings.Contains(e, "authenticat") || strings.Contains(e, "invalid token") ||
		strings.Contains(e, "token") && strings.Contains(e, "expired")
}

// readDocument finds vault and item by name (refs.go rules; the SDK reads files by ID) and returns the content.
func readDocument(ctx context.Context, c *onepassword.Client, ref string) (string, error) {
	vaultName, itemName, ok := strings.Cut(strings.TrimPrefix(ref, "op://"), "/")
	if !ok || itemName == "" || strings.Contains(itemName, "/") {
		return "", fmt.Errorf("document references look like op://<vault>/<item>?document, not %q", ref)
	}
	dir := sdkDirectory{c}
	vaults, err := dir.Vaults(ctx)
	if err != nil {
		return "", err
	}
	v, err := pick("vault", vaultName, "", vaults)
	if err != nil {
		return "", err
	}
	items, err := dir.Items(ctx, v.ID)
	if err != nil {
		return "", err
	}
	it, err := pick("item", itemName, " in "+v.Title, items)
	if err != nil {
		return "", err
	}
	vaultID, itemID := v.ID, it.ID
	item, err := c.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return "", err
	}
	if item.Document == nil {
		return "", fmt.Errorf("%q is not a Document item", itemName)
	}
	b, err := c.Items().Files().Read(ctx, vaultID, itemID, *item.Document)
	return string(b), err
}
