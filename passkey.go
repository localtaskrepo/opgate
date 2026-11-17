package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The approving passkeys live in the 1Password item <ControlItem>, field "passkeys" (JSON list of credentials).
// The service account can only read that vault, so nothing on this Mac (agents included) can add a passkey: an
// enrollment only prints the credential, and the owner pastes it into 1Password.

// owner is the single WebAuthn user.
type owner struct{ creds []webauthn.Credential }

func (o owner) WebAuthnID() []byte                         { return []byte("opgate-owner") }
func (o owner) WebAuthnName() string                       { return "owner" }
func (o owner) WebAuthnDisplayName() string                { return "opgate owner" }
func (o owner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

// StoredPasskey is one entry of the "passkeys" field.
type StoredPasskey struct {
	Name       string              `json:"name"`
	Added      string              `json:"added"`
	Credential webauthn.Credential `json:"credential"`
}

// passkeys reads the allowed credentials from 1Password, cached for passkeyCache (pages anyone can reach start
// passkey checks; each must not cost a 1Password read). A failed check drops the cache, so a passkey just added
// in 1Password works on the next try.
func (b *Broker) passkeys(ctx context.Context) ([]StoredPasskey, error) {
	b.pkMu.Lock()
	defer b.pkMu.Unlock()
	if b.pkCache != nil && b.now().Before(b.pkUntil) {
		return b.pkCache, nil
	}
	keys, err := b.readPasskeys(ctx)
	if err == nil && b.passkeyCache > 0 {
		b.pkCache, b.pkUntil = keys, b.now().Add(b.passkeyCache)
	}
	return keys, err
}

func (b *Broker) dropPasskeys() {
	b.pkMu.Lock()
	b.pkCache = nil
	b.pkMu.Unlock()
}

func (b *Broker) readPasskeys(ctx context.Context) ([]StoredPasskey, error) {
	raw, err := b.store.Resolve(ctx, b.cfg.ControlItem+"/passkeys")
	if err != nil {
		return nil, fmt.Errorf("reading passkeys: %w", err)
	}
	var keys []StoredPasskey
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &keys); err != nil {
		return nil, fmt.Errorf("passkeys field is not valid JSON: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("no passkeys enrolled")
	}
	return keys, nil
}

func credsOf(keys []StoredPasskey) []webauthn.Credential {
	var out []webauthn.Credential
	for _, k := range keys {
		out = append(out, k.Credential)
	}
	return out
}

// BeginApproval returns the WebAuthn options for approving request r; the challenge is bound to r.
func (b *Broker) BeginApproval(ctx context.Context, r *Request) (*protocol.CredentialAssertion, error) {
	keys, err := b.passkeys(ctx)
	if err != nil {
		return nil, err
	}
	opts, session, err := b.wa.BeginLogin(owner{credsOf(keys)},
		webauthn.WithChallenge(r.Challenge), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.session = session
	r.mu.Unlock()
	return opts, nil
}

// Durations the owner can pick on the page: secrets default 15 min of "same again", ssh keys
// default to what the agent asked for (15 min if it didn't).
var (
	grantChoices = []time.Duration{0, 15 * time.Minute, 30 * time.Minute, time.Hour}
	ttlChoices   = []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 4 * time.Hour}
)

const (
	defaultGrant = 15 * time.Minute
	defaultTTL   = 15 * time.Minute
)

// FinishApproval checks the assertion and approves r. dur is the owner's choice on the page: for secrets how long
// the same request is approved again (0: just this once), for ssh keys how long the key stays loaded.
func (b *Broker) FinishApproval(ctx context.Context, r *Request, req *http.Request, dur time.Duration) error {
	r.mu.Lock()
	session := r.session
	r.mu.Unlock()
	if session == nil {
		return errors.New("no approval started")
	}
	keys, err := b.passkeys(ctx)
	if err != nil {
		return err
	}
	cred, err := b.wa.FinishLogin(owner{credsOf(keys)}, *session, req)
	if err != nil {
		b.dropPasskeys()
		return fmt.Errorf("passkey check failed: %w", err)
	}
	if !cred.Flags.UserVerified {
		return errors.New("passkey did not verify the user")
	}
	by := ""
	for _, k := range keys {
		if string(k.Credential.ID) == string(cred.ID) {
			by = k.Name
		}
	}
	res := Result{Status: "approved", By: by}
	switch r.Kind {
	case KindSecrets:
		res.Grant = min(max(dur, 0), time.Hour)
	case KindSSH:
		if dur > 0 {
			res.TTL = min(max(dur, time.Minute), b.cfg.MaxSSHTTL.Duration)
		}
	}
	if !b.decide(r, res) {
		return errors.New("this request was already decided or has expired")
	}
	r.mu.Lock()
	out := r.result
	r.mu.Unlock()
	if out.Status != "approved" {
		return fmt.Errorf("approved, but it could not be delivered: %s", out.Error)
	}
	return nil
}

// BeginEnroll starts registering a passkey for enrollment request r.
func (b *Broker) BeginEnroll(r *Request) (*protocol.CredentialCreation, error) {
	opts, session, err := b.wa.BeginRegistration(owner{},
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.session = session
	r.mu.Unlock()
	return opts, nil
}

// FinishEnroll checks the registration and hands the credential back to the enrolling CLI.
func (b *Broker) FinishEnroll(r *Request, req *http.Request) error {
	r.mu.Lock()
	session := r.session
	r.mu.Unlock()
	if session == nil {
		return errors.New("no enrollment started")
	}
	cred, err := b.wa.FinishRegistration(owner{}, *session, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	payload, _ := json.Marshal(StoredPasskey{Name: r.Name, Added: b.now().Format(time.DateOnly), Credential: *cred})
	if !b.decide(r, Result{Status: "approved", Payload: payload, By: "enroll"}) {
		return errors.New("this enrollment ended meanwhile (expired or cancelled): run opgate enroll again")
	}
	return nil
}
