package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Kinds of requests.
const (
	KindSecrets = "secrets" // release 1Password values to one command
	KindSSH     = "ssh"     // load an ssh key into opgate's agent for a while
	KindEnroll  = "enroll"  // register a passkey (the owner stores the result in 1Password)
	KindRestore = "restore" // load a revoked autoloaded key again (created by the page, never by clients)
	// KindHandover (handover.go): give the keychain store to a new build of opgate
)

// RequestIn is what a client asks for (over the unix socket).
type RequestIn struct {
	Kind   string        `json:"kind"`
	Refs   []string      `json:"refs"`
	TTL    time.Duration `json:"ttl,omitempty"`
	Reason string        `json:"reason"`
	Cwd    string        `json:"cwd,omitempty"`
	Name   string        `json:"name,omitempty"`  // enroll: passkey name
	Route  string        `json:"route,omitempty"` // record: how the client got the values (record.go)
}

// Request is a pending or decided request. Caller is filled in by the server (peer process chain), not the client.
type Request struct {
	RequestIn
	ID        string   `json:"id"`
	Caller    []string `json:"caller"` // command lines of the asking process and its parents (for showing)
	Asker     Asker    `json:"-"`      // who asked, from the kernel's facts (identify)
	Warning   string   `json:"-"`      // told to the client with the pending message
	ident     string   // what a "same again" grant is tied to (identify)
	procs     []proc
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Challenge []byte    `json:"-"`

	mu        sync.Mutex
	timer     *time.Timer
	session   *webauthn.SessionData
	done      chan struct{}
	result    Result
	goToken   string // in the push's Approve link: lets that link start the passkey prompt on a desktop (pushnotify.go)
	enrollKey string // enroll: in the link given to the enrolling client (and its push) only; the page needs it
}

// Result is the outcome sent back to the client.
type Result struct {
	Status  string            `json:"status"` // approved, denied, expired, error
	Error   string            `json:"error,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
	Payload json.RawMessage   `json:"payload,omitempty"` // enroll: the credential
	By      string            `json:"-"`                 // approving passkey
	Grant   time.Duration     `json:"-"`
	TTL     time.Duration     `json:"-"` // ssh: the duration the owner picked (0: the agent's)
}

// SecretStore resolves op:// references (the 1Password service account).
type SecretStore interface {
	Resolve(ctx context.Context, ref string) (string, error)
	Check(ctx context.Context, ref string) error // the reference's vault and item are there (names only, no value)
}

// Notifier tells the owner's phone (and desktop) about a request.
type Notifier interface {
	Ask(r *Request, url string) error
	Done(r *Request, res Result) error
	Used(a Activity, url string) error // a grant or a key was used again: one updating notice per activity
	Revoked(a Activity) error
}

// grant is an "approve, and the same again for 30 min" permit.
type grant struct {
	Key   string
	Until time.Time
	Uses  int
	Title string // for the overview page
	Ref   string
}

func grantActivityKey(g grant) string { return g.Key + "|" + g.Until.Format(time.RFC3339Nano) }

// keyActivityKey: one activity per load of an approved key, per day and load of an autoloaded one.
// How an opgate key that signed was loaded: the "by" of its key-used audit lines (lines before 0.22.1 have none).
const (
	KeyAutoload = "autoload" // from the control item's autoload list, no approval
	KeyApproval = "approval" // approved on the page, for a while
)

func keyActivityKey(m keyMeta, now time.Time) (key, kind string) {
	if m.Until.IsZero() {
		return "ssh-daily|" + m.Ref + "|" + m.Loaded.Format(time.RFC3339Nano) + "|" + now.Format(time.DateOnly), "daily"
	}
	return "ssh-use|" + m.Ref + "|" + m.Loaded.Format(time.RFC3339Nano), "key"
}

// Broker holds pending requests, decides them with passkey assertions and releases secrets.
type Broker struct {
	cfg    Config
	store  SecretStore
	notify Notifier
	push   *notifyRouter // web push devices and settings (nil in tests that don't need them)
	keys   *Agent
	wa     *webauthn.WebAuthn
	audit  *Audit
	now    func() time.Time

	kcSnapshot func() (map[string][]byte, error) // the keychain store, for a handover (serve: kcStore.snapshot)

	mu      sync.Mutex
	pending map[string]*Request
	recent  []time.Time
	grants  map[string]*grant // "approve for 30 min": grant key -> grant

	activity     map[string]*Activity // uses after an approval, by internal key (activity.go)
	activityTags map[string]string    // random tag (page, notifications) -> internal key
	revokedRefs  map[string]bool      // autoloaded keys revoked on the phone: not loaded again by reload
	ended        map[string]ended     // decided requests' outcomes for pages still showing them (events.go)
	changes      changes              // wakes open pages (events.go)

	unlocks map[string]pendingUnlock // passkey checks for the overview's credential details (dashboard.go)

	passkeyCache time.Duration // how long the passkey list is kept (serve: 1 min; tests: 0, always read)
	pkMu         sync.Mutex
	pkCache      []StoredPasskey
	pkUntil      time.Time
	views        map[string]time.Time // view token (cookie) -> until

	dismissMu  sync.Mutex // dismissed.json
	cacheMu    sync.Mutex // the overview's audit facts
	factsKey   string
	factsStats statsView
	factsAttn  []attnItem
}

// maxReason keeps reasons readable on the phone and audit lines short.
const maxReason = 1000

func newBroker(cfg Config, store SecretStore, n Notifier, keys *Agent, audit *Audit) (*Broker, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: "opgate",
		RPOrigins:     []string{cfg.PublicURL},
	})
	if err != nil {
		return nil, err
	}
	return &Broker{cfg: cfg, store: store, notify: n, keys: keys, wa: wa, audit: audit, now: time.Now,
		pending: map[string]*Request{}, grants: map[string]*grant{}, revokedRefs: map[string]bool{},
		ended: map[string]ended{}}, nil
}

func randomID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// validate checks a request before anyone is bothered with it.
func (b *Broker) validate(in *RequestIn) error {
	switch in.Kind {
	case KindSecrets:
		if len(in.Refs) == 0 || len(in.Refs) > 8 {
			return errors.New("ask for 1 to 8 references")
		}
	case KindSSH:
		if len(in.Refs) != 1 {
			return errors.New("ask for exactly one ssh key")
		}
		if in.TTL <= 0 {
			in.TTL = defaultTTL
		}
		if in.TTL < time.Minute {
			return errors.New("ttl below 1 minute")
		}
		if in.TTL > b.cfg.MaxSSHTTL.Duration {
			return fmt.Errorf("ttl above %s", b.cfg.MaxSSHTTL)
		}
		if k, ok := b.keys.LoadedRef(in.Refs[0]); ok && k.Until.IsZero() {
			return errors.New("this key is already loaded for good (no approval needed): just use it")
		}
	case KindRestore:
		return errors.New("restore requests come from the page only")
	case KindEnroll:
		in.Refs = nil
		if in.Name == "" {
			in.Name = "passkey"
		}
		return nil
	case KindHandover:
		in.Refs, in.TTL = nil, 0
		if !buildIDPattern.MatchString(in.Name) {
			return errors.New("a handover names the new build (opgate handover)")
		}
		return nil
	default:
		return fmt.Errorf("unknown kind %q", in.Kind)
	}
	for _, r := range in.Refs {
		if !strings.HasPrefix(r, "op://") {
			return fmt.Errorf("not a 1Password reference: %q", r)
		}
	}
	if len(strings.TrimSpace(runsSuffix.ReplaceAllString(in.Reason, ""))) < 8 {
		return errors.New("give a reason (what for and why), at least a few words")
	}
	if utf8.RuneCountInString(in.Reason) > maxReason {
		return fmt.Errorf("reason too long (at most %d characters): say what and why in a sentence or two", maxReason)
	}
	return nil
}

// checkTimeout bounds checkRefs (all of a request's references).
var checkTimeout = 30 * time.Second

// checkRefs refuses references to items 1Password doesn't have, or that it can't check, before the owner is asked:
// approving them would deliver nothing.
func (b *Broker) checkRefs(in RequestIn) error {
	if in.Kind != KindSecrets && in.Kind != KindSSH {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	for _, ref := range in.Refs {
		err := b.store.Check(ctx, ref)
		var u unknownRef
		switch {
		case errors.As(err, &u):
			return fmt.Errorf("refused, nobody was asked: %s: %w. Don't guess item names: use one the user or the repo's "+
				"docs give (`opgate creds` lists the known credentials), or ask the user", ref, err)
		case ctx.Err() != nil:
			return fmt.Errorf("refused, nobody was asked: 1Password didn't answer in time when checking %s; tell the user", ref)
		case err != nil:
			return fmt.Errorf("refused, nobody was asked: checking %s in 1Password failed: %w; tell the user", ref, err)
		}
	}
	return nil
}

// grantKey identifies "the same thing again": same kind and refs, the same script file (path and content) or the
// same full command, in the same folder, from the same agent session (identify).
func grantKey(r *Request) string {
	refs := slices.Clone(r.Refs)
	slices.Sort(refs)
	return r.Kind + "|" + strings.Join(refs, ",") + "|" + r.ident
}

// challenge binds the passkey assertion to exactly this request.
func challengeFor(r *Request) []byte {
	h := sha256.New()
	// strings and a duration always encode, and writing to a hash never fails
	_ = json.NewEncoder(h).Encode(struct {
		ID, Kind, Reason string
		Refs, Caller     []string
		TTL              time.Duration
	}{r.ID, r.Kind, r.Reason, r.Refs, r.Caller, r.TTL})
	h.Write([]byte(randomID(16)))
	return h.Sum(nil)
}

// Submit registers a request from a chain known only by command lines (tests); the service uses SubmitProcs.
func (b *Broker) Submit(in RequestIn, caller []string) (*Request, error) {
	return b.SubmitProcs(in, procsFromArgs(caller))
}

// SubmitProcs registers a request and notifies the phone. A request covered by a live grant is approved at once.
func (b *Broker) SubmitProcs(in RequestIn, ps []proc) (*Request, error) {
	if err := b.validate(&in); err != nil {
		return nil, err
	}
	if err := b.checkRefs(in); err != nil {
		return nil, err
	}
	if in.Kind == KindHandover {
		if b.kcSnapshot == nil {
			return nil, errors.New("this opgate can't hand over its keychain store")
		}
		if err := checkHandoverPeer(ps, in.Name); err != nil {
			return nil, fmt.Errorf("refused, nobody was asked: %w", err)
		}
	}
	now := b.now()
	r := &Request{RequestIn: in, ID: randomID(12), Caller: argsOf(ps), Created: now, Expires: now.Add(b.cfg.PendingTTL.Duration),
		done: make(chan struct{}), procs: ps}
	r.Asker, r.ident = identify(ps)
	r.Challenge = challengeFor(r)
	if in.Kind == KindEnroll { // another local process that sees the ID (opgate status) must not register its own key
		r.enrollKey = randomID(16)
	}

	b.mu.Lock()
	cut := now.Add(-time.Hour)
	b.recent = slices.DeleteFunc(b.recent, func(t time.Time) bool { return t.Before(cut) })
	if len(b.recent) >= b.cfg.MaxPerHour {
		b.mu.Unlock()
		return nil, fmt.Errorf("more than %d requests in the last hour", b.cfg.MaxPerHour)
	}
	if in.Kind != KindEnroll {
		for k, g := range b.grants { // forget expired grants
			if !now.Before(g.Until) {
				delete(b.grants, k)
			}
		}
		if g, ok := b.grants[grantKey(r)]; ok && now.Before(g.Until) {
			b.mu.Unlock()
			b.finish(r, Result{Status: "approved", By: "grant"})
			r.mu.Lock()
			out := r.result
			r.mu.Unlock()
			if out.Status != "approved" { // nothing delivered: an error (overview), not a use
				b.audit.Log(r, "error", "grant", out.Error)
				return r, nil
			}
			b.mu.Lock()
			g.Uses++
			gc := *g
			b.mu.Unlock()
			b.audit.Log(r, "granted", "", fmt.Sprintf("use %d, until %s", gc.Uses, gc.Until.Format(time.TimeOnly)))
			d := askerOf(r)
			act := b.recordUse(grantActivityKey(gc), Activity{Kind: "grant", Title: pageTitle(r), Ref: strings.Join(r.Refs, ", "),
				GrantKey: gc.Key, Until: gc.Until},
				Use{Time: now, Agent: d.Agent, Command: agentCommand(r.Caller), Folder: r.Cwd, Project: d.Project, Root: d.Root, Chain: r.Caller})
			if err := b.notify.Used(act, b.activityURL(act.Tag)); err != nil {
				b.audit.Log(r, "notify-failed", "", err.Error())
			}
			return r, nil
		}
	}
	b.recent = append(b.recent, now)
	b.pending[r.ID] = r
	b.mu.Unlock()

	b.audit.Log(r, "asked", "", "")
	b.mu.Lock()
	r.timer = time.AfterFunc(time.Until(r.Expires), func() { b.decide(r, Result{Status: "expired", Error: "no decision in time"}) })
	b.mu.Unlock()
	b.changes.publish()
	if err := b.notify.Ask(r, b.URL(r)); err != nil {
		b.audit.Log(r, "notify-failed", "", err.Error())
		r.Warning = "the push may not have reached the owner (" + short(err.Error(), 120) + ")"
	}
	return r, nil
}

// URL is the approval page for a request.
func (b *Broker) URL(r *Request) string {
	if r.Kind == KindEnroll {
		return b.cfg.PublicURL + "/enroll/" + r.ID + "?k=" + r.enrollKey
	}
	return b.cfg.PublicURL + "/r/" + r.ID
}

// getEnroll is the pending enrollment id, only with its key.
func (b *Broker) getEnroll(id, key string) *Request {
	r := b.get(id)
	if r == nil || r.Kind != KindEnroll || key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(r.enrollKey)) != 1 {
		return nil
	}
	return r
}

func (b *Broker) get(id string) *Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pending[id]
}

// decide ends a pending request once; approved requests get their secrets here.
// decide ends a pending request once (false if it was already decided). The audit log gets what really happened:
// an approval whose secrets or key couldn't be delivered is logged as an error, and only then is no grant made.
func (b *Broker) decide(r *Request, res Result) bool {
	b.mu.Lock()
	if _, ok := b.pending[r.ID]; !ok {
		b.mu.Unlock()
		return false
	}
	delete(b.pending, r.ID)
	if r.timer != nil {
		r.timer.Stop()
	}
	b.mu.Unlock()
	b.finish(r, res)
	r.mu.Lock()
	out := r.result
	r.mu.Unlock()
	b.mu.Lock()
	if out.Status == "approved" && res.Grant > 0 {
		k := grantKey(r)
		b.grants[k] = &grant{Key: k, Until: b.now().Add(res.Grant), Title: pageTitle(r), Ref: strings.Join(r.Refs, ", ")}
	}
	b.rememberLocked(r, out)
	b.mu.Unlock()
	b.changes.publish()
	detail := out.Error
	if out.Status == "approved" && r.Kind == KindSSH {
		detail = "loaded for " + human(r.effectiveTTL(res))
	}
	b.audit.Log(r, out.Status, res.By, detail)
	if err := b.notify.Done(r, out); err != nil {
		b.audit.Log(r, "notify-failed", "", err.Error())
	}
	return true
}

// effectiveTTL is the owner's choice on the page, else what the agent asked for.
func (r *Request) effectiveTTL(res Result) time.Duration {
	if res.TTL > 0 {
		return res.TTL
	}
	return r.TTL
}

// finish releases what was approved and wakes the waiting client.
func (b *Broker) finish(r *Request, res Result) {
	if res.Status == "approved" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		switch r.Kind {
		case KindSecrets:
			res.Secrets = map[string]string{}
			for _, ref := range r.Refs {
				v, err := b.store.Resolve(ctx, ref)
				if err != nil {
					res = Result{Status: "error", Error: fmt.Sprintf("reading %s: %v", ref, err)}
					break
				}
				res.Secrets[ref] = v
			}
		case KindRestore:
			b.mu.Lock()
			delete(b.revokedRefs, r.Refs[0])
			b.mu.Unlock()
			key, err := b.store.Resolve(ctx, r.Refs[0])
			if err == nil {
				err = b.keys.AddKey(key, r.Refs[0], 0)
			}
			if err != nil {
				res = Result{Status: "error", Error: fmt.Sprintf("loading %s: %v", r.Refs[0], err)}
			}
		case KindSSH:
			key, err := b.store.Resolve(ctx, r.Refs[0])
			if err == nil {
				err = b.keys.AddKey(key, r.Refs[0], r.effectiveTTL(res))
			}
			if err != nil {
				res = Result{Status: "error", Error: fmt.Sprintf("loading %s: %v", r.Refs[0], err)}
			}
		case KindHandover:
			m, err := b.kcSnapshot()
			if err == nil && len(m) == 0 {
				err = errors.New("the keychain store is empty")
			}
			if err != nil {
				res = Result{Status: "error", Error: fmt.Sprintf("reading the keychain store: %v", err)}
				break
			}
			res.Payload, _ = json.Marshal(m) // byte slices always encode
		}
	}
	r.mu.Lock()
	r.result = res
	r.mu.Unlock()
	close(r.done)
}

// Wait blocks until the request is decided or the client gives up.
func (b *Broker) Wait(ctx context.Context, r *Request) Result {
	select {
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.result
	case <-ctx.Done():
		b.decide(r, Result{Status: "error", Error: "client went away"})
		return Result{Status: "error", Error: "client went away"}
	}
}

// Pending lists open requests (status).
func (b *Broker) Pending() []*Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*Request
	for _, r := range b.pending {
		out = append(out, r)
	}
	return out
}

// keyUsed records a signature with one of opgate's ssh keys: audit, the key's activity (per load for approved
// keys, per day for autoloaded ones like the agent key) and its updating notice.
func (b *Broker) keyUsed(m keyMeta, fp string, ps []proc) {
	caller := argsOf(ps)
	cmd := keyUseCommand(caller)
	asker, _ := identify(ps)
	ctx := strings.TrimSpace(cdPrefix.ReplaceAllString(asker.Command, ""))
	if ctx == cmd {
		ctx = ""
	}
	r := &Request{RequestIn: RequestIn{Kind: KindSSH, Refs: []string{m.Ref}, Reason: short(cmd, 160)}, ID: "use", Caller: caller, Asker: asker}
	key, kind := keyActivityKey(m, b.now()) // autoloaded (agent key): one activity and notice per day and load
	by := KeyApproval
	if kind == "daily" {
		by = KeyAutoload
	}
	b.audit.Log(r, "key-used", by, fmt.Sprintf("use %d of this load", m.Uses))
	seed := Activity{Kind: kind, Title: capitalize(friendlyItem(m.Ref)), Ref: m.Ref, KeyFP: fp, Until: m.Until}
	u := Use{Time: b.now(), Agent: asker.Agent, Command: cmd, Context: ctx, Project: asker.Project, Root: asker.Root, Chain: caller}
	if len(ps) > 0 {
		u.PID, u.Start = ps[0].PID, ps[0].Start
	}
	act := b.recordUse(key, seed, u)
	if err := b.notify.Used(act, b.activityURL(act.Tag)); err != nil {
		b.audit.Log(r, "notify-failed", "", err.Error())
	}
}

// upstreamUsed records a signature with a 1Password ssh key that went through opgate's agent (the owner approved
// it in 1Password; no push from opgate).
func (b *Broker) upstreamUsed(comment string, ps []proc) {
	caller := argsOf(ps)
	asker, _ := identify(ps)
	r := &Request{RequestIn: RequestIn{Kind: KindSSH, Refs: []string{"1Password: " + comment}, Reason: short(keyUseCommand(caller), 160)},
		ID: "use", Caller: caller, Asker: asker}
	b.audit.Log(r, "key-used", "1password", "approved in 1Password")
}

// requestRestore asks the owner (passkey) to load a revoked autoloaded key again; the page sends them there.
func (b *Broker) requestRestore(ref string) (*Request, error) {
	b.mu.Lock()
	revoked := b.revokedRefs[ref]
	b.mu.Unlock()
	if !revoked {
		return nil, errors.New("that key isn't revoked")
	}
	b.mu.Lock()
	for _, p := range b.pending { // already asked: the same page again
		if p.Kind == KindRestore && p.Refs[0] == ref {
			b.mu.Unlock()
			return p, nil
		}
	}
	b.mu.Unlock()
	now := b.now()
	r := &Request{RequestIn: RequestIn{Kind: KindRestore, Refs: []string{ref}, Reason: "Load " + friendlyItem(ref) + " again after revoking it"},
		ID: randomID(12), Created: now, Expires: now.Add(b.cfg.PendingTTL.Duration), done: make(chan struct{})}
	r.Challenge = challengeFor(r)
	b.mu.Lock()
	b.pending[r.ID] = r
	b.mu.Unlock()
	b.audit.Log(r, "asked", "page", "")
	t := time.AfterFunc(time.Until(r.Expires), func() { b.decide(r, Result{Status: "expired", Error: "no decision in time"}) })
	b.mu.Lock()
	r.timer = t
	b.mu.Unlock()
	return r, nil
}
