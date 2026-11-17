package main

// The overview page (/): what needs the owner's attention and what is allowed right now (grants and loaded keys, each
// linked to its page with Revoke), then tabs: History (searched and paged on the server, /history/items), the
// credential map's last run and the last 30 days in numbers.
//
// Anyone who can reach the page sees credential titles, status and dates. Where a credential is stored, who uses it,
// how to rotate it and what its check said need a passkey check first: it unlocks them for 10 minutes in that
// browser (an HttpOnly cookie) and nothing else. The details are rendered on the server only for an unlocked
// browser, so a locked page never contains them.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	viewCookie      = "opgate_view"
	viewFor         = 10 * time.Minute
	unlockWait      = 2 * time.Minute
	maxUnlocks      = 20
	credsStaleAfter = 72 * time.Hour // the daily check counts as not running after 3 days
	attentionWindow = 7 * 24 * time.Hour
	statsWindow     = 30 * 24 * time.Hour
)

type attnItem struct {
	Level   string // bad, warn
	Title   string
	Text    string // what it means and what to do
	Raw     string // the message as logged (folded on the page)
	When    string
	Link    string
	Restore string // ref of a revoked autoloaded key: the page offers to load it again
	Dismiss string // key for Dismiss (past failures only)
}

type activeItem struct {
	Kind, Title, Link, Uses, Tag, Left string
	Until                              int64 // unix ms for the countdown; 0: no end (autoloaded key)
	Stop                               bool  // offer Revoke + stop (approved keys: ends running ssh sessions)
	Daily                              bool
}

type credRow struct {
	CredView
	ExpiresDay, LastDay string
	In                  string // "in 56 days"
	Anchor              string // id of the row (problem rows, for links from Needs attention)
	Text                string // what the filter matches (details only when unlocked)
	Unlocked            bool   // show the details
}

type countItem struct {
	Key, Name, Sub string
	N              int
}

type agentRow struct {
	Name              string
	Requests, KeyUses int
}

type statsView struct {
	Requests, Approved, Denied, Expired, Failed, Cancelled, Reused, KeyUses, TouchID int
	Outcomes                                                                         string // "15 approved · 1 failed"
	MedianApprove                                                                    string
	Top                                                                              []countItem
	Agents                                                                           []agentRow
}

type dashData struct {
	Mode, ModeText, Version string
	Headline, HeadlineLevel string // ok, warn, bad
	Sig                     string // changes when anything on the page would (the page polls it)
	Attention               []attnItem
	Active                  []activeItem
	Hist                    histPage // the History tab's first page
	HasCreds                bool
	CredsChecked            string
	CredCounts              []countItem
	Creds                   []credRow // all, problems first
	Problems                []credRow // expired, invalid, expiring
	Upcoming                []credRow // other expiries within 90 days
	Unused                  []credRow
	Unlocked                bool
	UnlockedUntil           string
	Stats                   statsView
}

// ---------- the passkey unlock

type pendingUnlock struct {
	session *webauthn.SessionData
	until   time.Time
}

// BeginUnlock starts a passkey check for the credential details.
func (b *Broker) BeginUnlock(ctx context.Context) (string, *protocol.CredentialAssertion, error) {
	b.mu.Lock()
	open := 0
	for _, u := range b.unlocks {
		if b.now().Before(u.until) {
			open++
		}
	}
	b.mu.Unlock()
	if open >= maxUnlocks { // before any 1Password read
		return "", nil, errors.New("too many open unlock attempts; try again in a few minutes")
	}
	keys, err := b.passkeys(ctx)
	if err != nil {
		return "", nil, err
	}
	opts, session, err := b.wa.BeginLogin(owner{credsOf(keys)}, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unlocks == nil {
		b.unlocks = map[string]pendingUnlock{}
	}
	for id, u := range b.unlocks {
		if now.After(u.until) {
			delete(b.unlocks, id)
		}
	}
	if len(b.unlocks) >= maxUnlocks {
		return "", nil, errors.New("too many open unlock attempts; try again in a few minutes")
	}
	id := randomID(12)
	b.unlocks[id] = pendingUnlock{session: session, until: now.Add(unlockWait)}
	return id, opts, nil
}

// FinishUnlock checks the assertion (each attempt once) and returns a view token for viewFor.
func (b *Broker) FinishUnlock(ctx context.Context, id string, req *http.Request) (string, error) {
	now := b.now()
	b.mu.Lock()
	u, ok := b.unlocks[id]
	delete(b.unlocks, id)
	b.mu.Unlock()
	if !ok || now.After(u.until) {
		return "", errors.New("no unlock started, or it expired")
	}
	keys, err := b.passkeys(ctx)
	if err != nil {
		return "", err
	}
	cred, err := b.wa.FinishLogin(owner{credsOf(keys)}, *u.session, req)
	if err != nil {
		b.dropPasskeys()
		return "", fmt.Errorf("passkey check failed: %w", err)
	}
	if !cred.Flags.UserVerified {
		return "", errors.New("passkey did not verify the user")
	}
	by := ""
	for _, k := range keys {
		if string(k.Credential.ID) == string(cred.ID) {
			by = k.Name
		}
	}
	token := randomID(32)
	b.mu.Lock()
	if b.views == nil {
		b.views = map[string]time.Time{}
	}
	for t, until := range b.views {
		if now.After(until) {
			delete(b.views, t)
		}
	}
	b.views[token] = now.Add(viewFor)
	b.mu.Unlock()
	b.audit.Log(&Request{RequestIn: RequestIn{Kind: "view", Reason: "credential details and notification settings"}, ID: id},
		"unlocked", by, "for "+human(viewFor))
	return token, nil
}

// unlockedUntil is when the browser's view token runs out (zero: locked).
func (b *Broker) unlockedUntil(req *http.Request) time.Time {
	c, err := req.Cookie(viewCookie)
	if err != nil || c.Value == "" {
		return time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	until := b.views[c.Value]
	if !b.now().Before(until) {
		return time.Time{}
	}
	return until
}

func (b *Broker) lock(req *http.Request) {
	if c, err := req.Cookie(viewCookie); err == nil {
		b.mu.Lock()
		delete(b.views, c.Value)
		b.mu.Unlock()
	}
}

func setViewCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: viewCookie, Value: token, Path: "/", MaxAge: maxAge, HttpOnly: true,
		Secure: true, SameSite: http.SameSiteStrictMode})
}

// ---------- the page data

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < 2*time.Minute:
		return "just now"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d min ago", d/time.Minute)
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", d/time.Hour)
	}
	return fmt.Sprintf("%d days ago", d/(24*time.Hour))
}

func clock(now, t time.Time) string {
	t = t.Local()
	if y, m, d := now.Local().Date(); t.Year() == y && t.Month() == m && t.Day() == d {
		return t.Format("15:04")
	}
	return t.Format("Mon 2 Jan 15:04")
}

func left(now, until time.Time) string {
	d := until.Sub(now).Round(time.Minute)
	if d < time.Minute {
		return "until " + until.Local().Format("15:04")
	}
	return fmt.Sprintf("until %s · %d min left", until.Local().Format("15:04"), d/time.Minute)
}

// inDays is "today", "tomorrow", "in 12 days" (calendar days, local time).
func inDays(now, t time.Time) string {
	y1, m1, d1 := now.Local().Date()
	y2, m2, d2 := t.Local().Date()
	n := int(time.Date(y2, m2, d2, 0, 0, 0, 0, time.UTC).Sub(time.Date(y1, m1, d1, 0, 0, 0, 0, time.UTC)).Hours() / 24)
	switch {
	case n == -1:
		return "yesterday"
	case n < 0:
		return fmt.Sprintf("%d days ago", -n)
	case n == 0:
		return "today"
	case n == 1:
		return "tomorrow"
	}
	return fmt.Sprintf("in %d days", n)
}

var modeTexts = map[string]string{
	ModeAuto:    "Touch ID when you're at the Mac, your phone otherwise",
	ModePhone:   "every request goes to your phone",
	ModeTouchID: "1Password on the Mac only (Touch ID)",
}

// explainError says in plain words what an approval that delivered nothing ran into, and what helps.
func explainError(detail string) string {
	d := strings.ToLower(detail)
	switch {
	case strings.Contains(d, "invalid character in secret reference") || strings.Contains(d, "could not be parsed"):
		return "1Password couldn't read a name in the reference (characters like ( ) aren't allowed there). Since opgate 0.14 such names are looked up instead: asking again works."
	case strings.Contains(d, "several") && strings.Contains(d, "match"):
		return "The name fits more than one item or field: the agent has to use the exact name or the ID."
	case strings.Contains(d, "isn't an item") || strings.Contains(d, "no item"):
		return "There's no item with that name in the vault: check the name the agent asked for."
	case strings.Contains(d, "isn't a field") || strings.Contains(d, "no field") || strings.Contains(d, "field") && strings.Contains(d, "not found"):
		return "The item has no field with that name: check the field the agent asked for."
	case strings.Contains(d, "not a private key"):
		return "That field doesn't hold an ssh private key."
	case strings.Contains(d, "keychain") || strings.Contains(d, "service account"):
		return "opgate couldn't use its 1Password service account: run `opgate bootstrap` at the Mac."
	}
	return "You approved it, but reading the value from 1Password failed."
}

// ---------- dismissed past failures (~/.config/opgate/dismissed.json: key -> when)

func (b *Broker) dismissedPath() string {
	return filepath.Join(filepath.Dir(b.cfg.Socket), "dismissed.json")
}

func (b *Broker) loadDismissed() map[string]time.Time {
	m := map[string]time.Time{}
	if raw, err := os.ReadFile(b.dismissedPath()); err == nil && json.Unmarshal(raw, &m) != nil {
		return map[string]time.Time{} // a broken file dismisses nothing; the next Dismiss rewrites it
	}
	return m
}

// Dismiss hides a past failure (only keys the page offers right now) until the same thing fails again.
func (b *Broker) Dismiss(key string) error {
	now := b.now()
	_, attn := b.auditFacts(now, b.loadDismissed())
	if !slices.ContainsFunc(attn, func(a attnItem) bool { return a.Dismiss != "" && a.Dismiss == key }) {
		return errors.New("nothing to dismiss under that name")
	}
	b.dismissMu.Lock()
	defer b.dismissMu.Unlock()
	m := b.loadDismissed()
	for k, t := range m {
		if now.Sub(t) > statsWindow {
			delete(m, k)
		}
	}
	m[key] = now
	raw, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Dir(b.dismissedPath()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(b.dismissedPath(), raw, 0o600); err != nil {
		return err
	}
	b.audit.Log(&Request{RequestIn: RequestIn{Kind: "view", Reason: key}, ID: "dismiss"}, "dismissed", "page", "")
	return nil
}

// ---------- the page

func (b *Broker) dashboard(req *http.Request) dashData {
	now := b.now()
	d := dashData{Mode: currentMode(), Version: version}
	d.ModeText = modeTexts[d.Mode]
	if until := b.unlockedUntil(req); !until.IsZero() {
		d.Unlocked, d.UnlockedUntil = true, until.Local().Format("15:04")
	}
	b.attentionNow(&d, now)
	d.Attention = append(d.Attention, b.notifyAttention(now)...)
	d.Active = b.activeNow(now)
	b.credsSection(&d, now)
	st, attn := b.auditFacts(now, b.loadDismissed())
	d.Stats = st
	d.Attention = append(d.Attention, attn...)
	d.Hist = b.historyPage(histQuery{})
	bad, warn := 0, 0
	for _, a := range d.Attention {
		if a.Level == "bad" {
			bad++
		} else {
			warn++
		}
	}
	switch n := bad + warn; n {
	case 0:
		d.Headline, d.HeadlineLevel = "All clear: nothing waiting, nothing failing", "ok"
	case 1:
		d.Headline = "1 thing needs you"
	default:
		d.Headline = fmt.Sprintf("%d things need you", n)
	}
	if bad > 0 {
		d.HeadlineLevel = "bad"
	} else if warn > 0 {
		d.HeadlineLevel = "warn"
	}
	d.Sig = pageSig(d)
	return d
}

// pageSig changes when the page would show something else (not with the clock or the unlock).
func pageSig(d dashData) string {
	h := sha256.New()
	for _, a := range d.Attention {
		fmt.Fprintln(h, a.Level, a.Title, a.When, a.Dismiss)
	}
	for _, a := range d.Active {
		if a.Daily { // its use count changes with every git command
			fmt.Fprintln(h, a.Tag)
		} else {
			fmt.Fprintln(h, a.Tag, a.Uses, a.Until)
		}
	}
	for i, it := range d.Hist.Items { // routine uses are not on the first page, so they don't reload it
		if i == 5 {
			break
		}
		fmt.Fprintln(h, it.ID, it.Time.Unix(), it.Status)
	}
	fmt.Fprintln(h, d.CredsChecked, d.Mode)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// attentionNow: open requests (newest first) and revoked autoloaded keys.
func (b *Broker) attentionNow(d *dashData, now time.Time) {
	pending := b.Pending()
	sort.Slice(pending, func(i, j int) bool { return pending[i].Created.After(pending[j].Created) })
	for _, r := range pending {
		it := attnItem{Level: "warn", Title: "Waiting for you: " + pageTitle(r), Text: reasonOnly(r.Reason), When: clock(now, r.Created), Link: "/r/" + r.ID}
		if r.Kind == KindEnroll { // its page needs the key from the link opgate enroll printed (and pushed)
			it.Title, it.Link = "Waiting for you: register passkey “"+r.Name+"”", ""
			it.Text = "Open the link that opgate enroll printed, or its notification."
		}
		d.Attention = append(d.Attention, it)
	}
	b.mu.Lock()
	var revoked []string
	for ref, on := range b.revokedRefs {
		if on {
			revoked = append(revoked, ref)
		}
	}
	b.mu.Unlock()
	slices.Sort(revoked)
	for _, ref := range revoked {
		d.Attention = append(d.Attention, attnItem{Level: "bad", Title: capitalize(friendlyItem(ref)) + " is revoked",
			Text: "Whatever uses it (git signing, ssh) stays off until you load it again (passkey).", Restore: ref})
	}
}

// activeNow lists live grants and opgate's loaded keys, each with its activity page (uses, Revoke).
func (b *Broker) activeNow(now time.Time) []activeItem {
	var out []activeItem
	b.mu.Lock()
	var grants []grant
	for _, g := range b.grants {
		if now.Before(g.Until) {
			grants = append(grants, *g)
		}
	}
	b.mu.Unlock()
	sort.Slice(grants, func(i, j int) bool { return grants[i].Until.Before(grants[j].Until) })
	for _, g := range grants {
		a := b.ensureActivity(grantActivityKey(g), Activity{Kind: "grant", Title: g.Title, Ref: g.Ref, GrantKey: g.Key, Until: g.Until})
		if a.Revoked {
			continue
		}
		uses := "not used again yet"
		if a.Count > 0 {
			uses = fmt.Sprintf("used %d× again", a.Count)
		}
		out = append(out, activeItem{Kind: "Secrets · same again", Title: a.Title, Link: "/u/" + a.Tag, Tag: a.Tag, Uses: uses,
			Left: left(now, g.Until), Until: g.Until.UnixMilli()})
	}
	if b.keys == nil {
		return out
	}
	keys := b.keys.Loaded()
	sort.Slice(keys, func(i, j int) bool { return keys[i].Ref < keys[j].Ref })
	for _, k := range keys {
		key, kind := keyActivityKey(k.keyMeta, now)
		a := b.ensureActivity(key, Activity{Kind: kind, Title: capitalize(friendlyItem(k.Ref)), Ref: k.Ref, KeyFP: k.FP, Until: k.Until})
		it := activeItem{Kind: "SSH key", Title: a.Title, Link: "/u/" + a.Tag, Tag: a.Tag, Uses: fmt.Sprintf("used %d×", a.Count)}
		if kind == "daily" {
			it.Kind, it.Daily = "SSH key · no approval needed", true
			it.Left, it.Uses = "loaded since "+clock(now, k.Loaded), fmt.Sprintf("used %d× today", a.Count)
		} else {
			it.Left, it.Until, it.Stop = left(now, k.Until), k.Until.UnixMilli(), true
		}
		out = append(out, it)
	}
	return out
}

var statusOrder = map[string]int{"expired": 0, "invalid": 1, "expiring": 2, "ok": 3, "unknown": 4}

func (b *Broker) credsSection(d *dashData, now time.Time) {
	snap, err := readSnapshot(snapshotPath(b.cfg))
	if err != nil {
		d.Attention = append(d.Attention, attnItem{Level: "warn", Title: "No credential check yet",
			Text: "opgate creds hasn't written a result (launch agent " + appID + "-creds)."})
		return
	}
	d.HasCreds, d.CredsChecked = true, ago(now, snap.Time)
	if now.Sub(snap.Time) > credsStaleAfter {
		d.Attention = append(d.Attention, attnItem{Level: "warn", Title: "Credential check not running",
			Text: "The last check ran " + ago(now, snap.Time) + "; it should run daily at 07:05 (launch agent " + appID + "-creds)."})
	}
	counts := map[string]int{}
	for _, c := range snap.Credentials {
		row := credRow{CredView: c, ExpiresDay: day(c.Expires), LastDay: day(c.LastUsed), Unlocked: d.Unlocked}
		if !c.Expires.IsZero() {
			row.In = inDays(now, c.Expires)
		}
		text := []string{c.Title, c.ID, "tier " + strings.ToLower(c.Tier), c.Status}
		if d.Unlocked {
			text = append(text, c.Store, strings.Join(c.UsedBy, " "), c.Scope)
		}
		row.Text = strings.ToLower(strings.Join(text, " "))
		counts[c.Status]++
		d.Creds = append(d.Creds, row)
		switch c.Status {
		case "expired", "invalid":
			d.Attention = append(d.Attention, attnItem{Level: "bad", Title: c.Title + ": " + c.Status, Link: "#cred-" + c.ID,
				Text: "Found by the credential check " + ago(now, snap.Time) + ". Unlock the details for what the check said and how to rotate it."})
		case "expiring":
			d.Attention = append(d.Attention, attnItem{Level: "warn", Title: c.Title + ": expires " + row.In, Link: "#cred-" + c.ID,
				When: row.ExpiresDay, Text: "Rotate or renew it before then; the details say how."})
		}
		if strings.HasPrefix(c.Store, "op://") && (c.LastUsed.IsZero() || now.Sub(c.LastUsed) > statsWindow) {
			d.Unused = append(d.Unused, row)
		}
	}
	sort.SliceStable(d.Creds, func(i, j int) bool {
		a, b := d.Creds[i], d.Creds[j]
		if statusOrder[a.Status] != statusOrder[b.Status] {
			return statusOrder[a.Status] < statusOrder[b.Status]
		}
		return strings.ToLower(a.Title) < strings.ToLower(b.Title)
	})
	for _, c := range d.Creds {
		switch {
		case statusOrder[c.Status] <= statusOrder["expiring"]:
			c.Anchor = "cred-" + c.ID
			d.Problems = append(d.Problems, c)
		case !c.Expires.IsZero() && c.Expires.Sub(now) < 90*24*time.Hour:
			d.Upcoming = append(d.Upcoming, c)
		}
	}
	sort.SliceStable(d.Upcoming, func(i, j int) bool { return d.Upcoming[i].Expires.Before(d.Upcoming[j].Expires) })
	for _, s := range []string{"expired", "invalid", "expiring", "ok", "unknown"} {
		if counts[s] > 0 || s == "ok" {
			d.CredCounts = append(d.CredCounts, countItem{Key: s, Name: map[string]string{"expired": "expired", "invalid": "invalid",
				"expiring": "expiring", "ok": "OK", "unknown": "not checkable"}[s], N: counts[s]})
		}
	}
}

// auditFacts are the numbers of the last 30 days and the failures of the last 7 from the audit log, cached while
// the log, the dismissals and the minute stay the same (the page polls).
func (b *Broker) auditFacts(now time.Time, dismissed map[string]time.Time) (statsView, []attnItem) {
	key := now.Truncate(time.Minute).String()
	if st, err := os.Stat(b.cfg.AuditLog); err == nil {
		key += fmt.Sprint(st.Size(), st.ModTime().UnixNano())
	}
	raw, _ := json.Marshal(dismissed)
	key += string(raw)
	b.cacheMu.Lock()
	defer b.cacheMu.Unlock()
	if b.factsKey == key {
		return b.factsStats, slices.Clone(b.factsAttn)
	}
	st, attn := b.scanAudit(now, dismissed)
	b.factsKey, b.factsStats, b.factsAttn = key, st, attn
	return st, slices.Clone(attn)
}

// scanAudit reads the audit log once: the numbers of the last 30 days and the problems of the last 7.
func (b *Broker) scanAudit(now time.Time, dismissed map[string]time.Time) (statsView, []attnItem) {
	var st statsView
	var attn []attnItem
	f, err := os.Open(b.cfg.AuditLog)
	if err != nil {
		return st, nil
	}
	defer f.Close()
	type failure struct {
		n      int
		last   time.Time
		detail string
	}
	asked := map[string]time.Time{}
	var lat []time.Duration
	top := map[string]*countItem{}
	topLast := map[string]time.Time{}
	agents := map[string]*agentRow{}
	failures := map[string]*failure{}
	var failOrder []string
	notifyN, notifyLast := 0, time.Time{}
	for line := range auditLines(f) {
		var l auditLine
		if json.Unmarshal(line, &l) != nil || now.Sub(l.Time) > statsWindow || l.Kind == KindEnroll {
			continue
		}
		recent := now.Sub(l.Time) <= attentionWindow
		uses := false
		agent := func() *agentRow {
			name := describe(l.Caller).Agent
			if name == "" {
				name = "Terminal or other"
			}
			if agents[name] == nil {
				agents[name] = &agentRow{Name: name}
			}
			return agents[name]
		}
		switch l.Event {
		case "asked":
			st.Requests++
			asked[l.ID] = l.Time
			uses = true
			if l.By != "page" {
				agent().Requests++
			}
		case "approved":
			st.Approved++
			if t, ok := asked[l.ID]; ok {
				lat = append(lat, l.Time.Sub(t))
			}
		case "denied":
			st.Denied++
		case "expired":
			st.Expired++
		case "granted":
			st.Reused++
			uses = true
			agent().Requests++
		case "key-used":
			if l.By == Route1Password {
				st.TouchID++
			} else {
				st.KeyUses++
				uses = true
				agent().KeyUses++
			}
		case "routed":
			if l.By == Route1Password {
				st.TouchID++
				uses = true
			}
		case "error":
			if strings.Contains(l.Detail, "client went away") {
				st.Cancelled++
				continue
			}
			st.Failed++
			if recent {
				title := "a request"
				if len(l.Refs) > 0 && (l.Kind == KindSecrets || l.Kind == KindSSH || l.Kind == KindRestore) {
					title = pageTitle(&Request{RequestIn: RequestIn{Kind: l.Kind, Refs: l.Refs}})
				}
				fl := failures[title]
				if fl == nil {
					fl = &failure{}
					failures[title] = fl
					failOrder = append(failOrder, title)
				}
				fl.n++
				fl.last, fl.detail = l.Time, l.Detail
			}
		case "notify-failed":
			if recent {
				notifyN++
				notifyLast = l.Time
			}
		}
		if uses {
			seen := map[string]bool{}
			for _, ref := range l.Refs {
				name := capitalize(friendlyItem(normalizeRef(ref)))
				if strings.EqualFold(name, "opgate") {
					name = "opgate control item"
				}
				if strings.HasPrefix(ref, "1Password: ") || seen[name] {
					continue
				}
				seen[name] = true
				if top[name] == nil {
					top[name] = &countItem{Name: name}
				}
				top[name].N++
				topLast[name] = l.Time
			}
		}
	}
	for i := len(failOrder) - 1; i >= 0; i-- { // newest title first
		title := failOrder[i]
		fl := failures[title]
		key := "error:" + title
		if t, ok := dismissed[key]; ok && !t.Before(fl.last) {
			continue
		}
		when := clock(now, fl.last)
		if fl.n > 1 {
			when = fmt.Sprintf("%d× · last %s", fl.n, when)
		}
		attn = append(attn, attnItem{Level: "bad", Title: "Approved, but nothing was delivered: " + title,
			Text: explainError(fl.detail), Raw: short(fl.detail, 300), When: when, Dismiss: key})
	}
	if t, ok := dismissed["notify"]; notifyN > 0 && (!ok || t.Before(notifyLast)) {
		attn = append(attn, attnItem{Level: "warn", Title: fmt.Sprintf("Notifications failed %d× this week", notifyN),
			Text: "The requests still waited on this page, but no push arrived (no device set up, the push service or the Mac's network).",
			When: "last " + clock(now, notifyLast), Dismiss: "notify"})
	}
	if len(lat) > 0 {
		slices.Sort(lat)
		m := lat[len(lat)/2]
		if m < 90*time.Second {
			st.MedianApprove = fmt.Sprintf("%d s", m/time.Second)
		} else {
			st.MedianApprove = fmt.Sprintf("%d min", (m+30*time.Second)/time.Minute)
		}
	}
	var parts []string
	for _, p := range []struct {
		n    int
		what string
	}{{st.Approved, "approved"}, {st.Denied, "denied"}, {st.Expired, "expired"}, {st.Failed, "failed"}, {st.Cancelled, "cancelled"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.what))
		}
	}
	st.Outcomes = strings.Join(parts, " · ")
	for name, c := range top {
		c.Sub = "last " + ago(now, topLast[name])
		st.Top = append(st.Top, *c)
	}
	sort.Slice(st.Top, func(i, j int) bool {
		if st.Top[i].N != st.Top[j].N {
			return st.Top[i].N > st.Top[j].N
		}
		return st.Top[i].Name < st.Top[j].Name
	})
	if len(st.Top) > 6 {
		st.Top = st.Top[:6]
	}
	for _, a := range agents {
		st.Agents = append(st.Agents, *a)
	}
	sort.Slice(st.Agents, func(i, j int) bool {
		ti, tj := st.Agents[i].Requests+st.Agents[i].KeyUses, st.Agents[j].Requests+st.Agents[j].KeyUses
		if ti != tj {
			return ti > tj
		}
		return st.Agents[i].Name < st.Agents[j].Name
	})
	return st, attn
}
