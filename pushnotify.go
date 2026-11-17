package main

// Notification routing: opgate's own Web Push to the devices the owner turned on (settings per device and kind
// of notice, page /settings). The settings live in the keychain (blobStore), changed only after a passkey unlock:
// an agent must not be able to silence the notices about what it does.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"
	"time"
)

// Levels of a kind of notice on one device.
const (
	lvSound  = "sound"  // alert with sound/vibration
	lvSilent = "silent" // show it quietly (uses: update quietly)
	lvOff    = "off"    // not on this device
	lvFirst  = "first"  // uses: alert on the first use, then update quietly
	lvEvery  = "every"  // uses: alert on every use
)

var levelLabels = map[string]string{lvSound: "Sound", lvSilent: "Silent", lvOff: "Off", lvFirst: "First use", lvEvery: "Every use"}

// notifyCat is one kind of notice; Mobile and Desktop are the defaults.
type notifyCat struct {
	Key, Name, Help string
	Levels          []string
	Mobile, Desktop string
}

var notifyCats = []notifyCat{
	{"ask", "Approval requests", "An agent asks for a secret or an ssh key.", []string{lvSound, lvSilent, lvOff}, lvSound, lvSound},
	{"outcome", "Denied, expired, revoked", "A request ended without your approval, or something was revoked.", []string{lvSound, lvSilent, lvOff}, lvSilent, lvOff},
	{"grant", "Same-again reuses", "A secret you approved for a while is used again.", []string{lvEvery, lvFirst, lvSilent, lvOff}, lvEvery, lvSilent},
	{"key", "Approved ssh keys", "Each use of a key you loaded with approval.", []string{lvEvery, lvFirst, lvSilent, lvOff}, lvEvery, lvSilent},
	{"daily", "Keys without approval", "The keys loaded at start (autoload): one notice per day.", []string{lvEvery, lvFirst, lvSilent, lvOff}, lvFirst, lvSilent},
}

func catByKey(k string) (notifyCat, bool) {
	for _, c := range notifyCats {
		if c.Key == k {
			return c, true
		}
	}
	return notifyCat{}, false
}

// pushDevice is one browser subscription.
type pushDevice struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Mobile   bool              `json:"mobile"`
	Added    time.Time         `json:"added"`
	Endpoint string            `json:"endpoint"`
	P256dh   string            `json:"p256dh"`
	Auth     string            `json:"auth"`
	Levels   map[string]string `json:"levels,omitempty"`
	Gone     time.Time         `json:"gone,omitzero"` // the browser ended the subscription
}

func (d pushDevice) level(cat string) string {
	c, ok := catByKey(cat)
	if !ok {
		return lvOff
	}
	if v := d.Levels[cat]; slices.Contains(c.Levels, v) {
		return v
	}
	if d.Mobile {
		return c.Mobile
	}
	return c.Desktop
}

type notifySettings struct {
	Devices []pushDevice `json:"devices"`
}

func (s notifySettings) active() []pushDevice {
	var out []pushDevice
	for _, d := range s.Devices {
		if d.Gone.IsZero() {
			out = append(out, d)
		}
	}
	return out
}

// devStatus is how sending to a device went lately (memory only).
type devStatus struct {
	LastOK, LastFail time.Time
	Err              string
	Fails            int // in a row
}

const (
	maxDevices      = 10
	notifyBlob      = "notify-settings"
	failingAfter    = 3 // failures in a row before the overview shows it
	pushSendTimeout = 10 * time.Second
)

// notifyPrefs loads and saves the settings. If the keychain can't be read, nothing is saved (that would replace
// the owner's settings with defaults) and nothing can be sent (the overview and the asking agent say so).
type notifyPrefs struct {
	blobs blobStore

	mu     sync.Mutex
	loaded bool
	s      notifySettings
	status map[string]*devStatus
}

func (p *notifyPrefs) loadLocked() error {
	if p.loaded {
		return nil
	}
	raw, err := p.blobs.Load(notifyBlob)
	if err != nil {
		return err // not marked loaded: the next call tries again
	}
	var s notifySettings
	if raw != nil {
		if err := json.Unmarshal(raw, &s); err != nil {
			log.Printf("notification settings unreadable, starting over: %v", err)
			s = notifySettings{}
		}
	}
	p.s, p.loaded = s, true
	return nil
}

// clone is a deep copy (devices and their levels), so callers can't change the stored settings.
func (s notifySettings) clone() notifySettings {
	s.Devices = slices.Clone(s.Devices)
	for i := range s.Devices {
		s.Devices[i].Levels = maps.Clone(s.Devices[i].Levels)
	}
	return s
}

// get returns a copy of the settings (none while the keychain can't be read).
func (p *notifyPrefs) get() (notifySettings, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.loadLocked()
	return p.s.clone(), err
}

// update changes the settings and saves them; f works on a copy.
func (p *notifyPrefs) update(f func(s *notifySettings) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.loadLocked(); err != nil {
		return fmt.Errorf("notification settings can't be read: %w", err)
	}
	s := p.s.clone()
	if err := f(&s); err != nil {
		return err
	}
	raw, _ := json.Marshal(s)
	if err := p.blobs.Save(notifyBlob, raw); err != nil {
		return err
	}
	p.s = s
	return nil
}

func (p *notifyPrefs) statusOf(id string) devStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.status[id]; st != nil {
		return *st
	}
	return devStatus{}
}

// forget drops a removed device's status.
func (p *notifyPrefs) forget(id string) {
	p.mu.Lock()
	delete(p.status, id)
	p.mu.Unlock()
}

func (p *notifyPrefs) record(id string, err error, now time.Time) {
	p.mu.Lock()
	if p.status == nil {
		p.status = map[string]*devStatus{}
	}
	st := p.status[id]
	if st == nil {
		st = &devStatus{}
		p.status[id] = st
	}
	if err == nil {
		st.LastOK, st.Fails, st.Err = now, 0, ""
	} else {
		st.LastFail, st.Err = now, err.Error()
		st.Fails++
	}
	p.mu.Unlock()
	if errors.Is(err, errPushGone) {
		if uerr := p.update(func(s *notifySettings) error {
			for i := range s.Devices {
				if s.Devices[i].ID == id && s.Devices[i].Gone.IsZero() {
					s.Devices[i].Gone = now
				}
			}
			return nil
		}); uerr != nil {
			log.Printf("push: marking device %s gone: %v", id, uerr)
		}
	}
}

// pushMsg is what the service worker (web/sw.js) gets.
type pushMsg struct {
	Kind    string       `json:"kind"` // ask, info, used, clear, test
	Title   string       `json:"title,omitempty"`
	Body    string       `json:"body,omitempty"`
	Icon    string       `json:"icon,omitempty"` // the project's icon (/project-icon/…); the service worker falls back to opgate's
	Tag     string       `json:"tag,omitempty"`
	URL     string       `json:"url,omitempty"`
	Silent  bool         `json:"silent,omitempty"`
	Sticky  bool         `json:"sticky,omitempty"` // stays until acted on (requests)
	Actions []pushAction `json:"actions,omitempty"`
	TS      int64        `json:"ts,omitempty"`
}

// pushAction is a notification button: open a page, or post to opgate in the background (Deny, Revoke: both only
// take access away, like the same buttons on the pages).
type pushAction struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url,omitempty"`
	Post  string `json:"post,omitempty"`
}

// notifyRouter is the Notifier the service uses. asked remembers which devices got a request's push, so its
// outcome reaches the same ones.
type notifyRouter struct {
	prefs *notifyPrefs
	push  pushSender
	base  string // the page's public URL, for links
	now   func() time.Time

	mu    sync.Mutex
	asked map[string][]string
}

func newNotifyRouter(base string, blobs blobStore, push pushSender) *notifyRouter {
	return &notifyRouter{prefs: &notifyPrefs{blobs: blobs}, push: push, base: base, now: time.Now, asked: map[string][]string{}}
}

// Push text limits: a whole message must stay under maxPushPayload once encoded.
const (
	maxTitle = 160
	maxBody  = 900
)

// clip cuts s to n characters, keeping its line breaks (short would join the lines).
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// marshalPush encodes without HTML escaping (json.Marshal turns each <, > and & of a command into 6 bytes).
func marshalPush(m pushMsg) []byte {
	m.Title, m.Body = clip(m.Title, maxTitle), clip(m.Body, maxBody)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m) // plain strings, numbers and flags into memory: cannot fail
	return bytes.TrimSpace(buf.Bytes())
}

// fanout sends one message per device (build returns false to skip one). It returns the devices that got it and
// an error only when none of the devices it sent to did.
func (n *notifyRouter) fanout(devs []pushDevice, build func(d pushDevice) (pushMsg, pushOpts, bool)) ([]string, error) {
	type res struct {
		id  string
		err error
	}
	out := make(chan res, len(devs))
	sent := 0
	for _, d := range devs {
		m, o, ok := build(d)
		if !ok {
			continue
		}
		if m.TS == 0 {
			m.TS = n.now().UnixMilli()
		}
		payload := marshalPush(m)
		sent++
		go func(d pushDevice) {
			ctx, cancel := context.WithTimeout(context.Background(), pushSendTimeout)
			defer cancel()
			err := n.push.Send(ctx, d, payload, o)
			n.prefs.record(d.ID, err, n.now())
			if err != nil {
				err = fmt.Errorf("%s: %w", d.Name, err)
			}
			out <- res{d.ID, err}
		}(d)
	}
	var got []string
	var errs []error
	for range sent {
		r := <-out
		if r.err != nil {
			errs = append(errs, r.err)
		} else {
			got = append(got, r.id)
		}
	}
	if len(got) > 0 {
		return got, nil
	}
	return nil, errors.Join(errs...)
}

// goToken lets a notification's Approve button start the passkey prompt on a desktop too: only the push carries it,
// so a link an agent opens can't. The page takes it once (takeGoToken).
func (r *Request) goTokenFor() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.goToken == "" {
		r.goToken = randomID(16)
	}
	return r.goToken
}

// takeGoToken reports whether t is the request's push token and uses it up (a reload or a copied link from the
// browser history doesn't start the prompt again).
func (r *Request) takeGoToken(t string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t == "" || r.goToken == "" || subtle.ConstantTimeCompare([]byte(t), []byte(r.goToken)) != 1 {
		return false
	}
	r.goToken = "-" // spent: no token matches any more
	return true
}

func (n *notifyRouter) Ask(r *Request, url string) error {
	s, err := n.prefs.get()
	if err != nil {
		return fmt.Errorf("notification settings: %w", err)
	}
	a := askerOf(r)
	m := pushMsg{Kind: "ask", Title: "🔐 " + withProject(a.Project, headline(r)), Body: short(reasonOnly(r.Reason), 600) + "\n" + who(r),
		Icon: projectIcons.url(a.Root), Tag: "opgate-" + r.ID, URL: url, Sticky: true}
	if r.Kind != KindEnroll {
		m.Actions = []pushAction{{ID: "approve", Title: "Approve", URL: url + "?go=approve&t=" + r.goTokenFor()},
			{ID: "deny", Title: "Deny", Post: "/r/" + r.ID + "/deny"}}
	}
	ttl := max(time.Until(r.Expires), time.Minute)
	got, werr := n.fanout(s.active(), func(d pushDevice) (pushMsg, pushOpts, bool) {
		lv := d.level("ask")
		mm := m
		mm.Silent = lv == lvSilent
		return mm, pushOpts{TTL: ttl, Urgency: "high"}, lv != lvOff
	})
	n.mu.Lock()
	n.asked[r.ID] = got
	n.mu.Unlock()
	switch {
	case len(got) > 0:
		return nil
	case werr != nil:
		return werr
	case len(s.active()) == 0:
		return errors.New("no device is set up for notifications (opgate's Notifications page)")
	}
	return errors.New("no device gets approval requests (opgate's Notifications page)")
}

func (n *notifyRouter) Done(r *Request, res Result) error {
	n.mu.Lock()
	got, ok := n.asked[r.ID]
	delete(n.asked, r.ID)
	n.mu.Unlock()
	if !ok {
		return nil
	}
	s, _ := n.prefs.get()
	var devs []pushDevice
	for _, d := range s.active() {
		if slices.Contains(got, d.ID) {
			devs = append(devs, d)
		}
	}
	tag := "opgate-" + r.ID
	a := askerOf(r)
	title, icon := capitalize(res.Status)+" · "+withProject(a.Project, headline(r)), projectIcons.url(a.Root)
	_, werr := n.fanout(devs, func(d pushDevice) (pushMsg, pushOpts, bool) {
		lv := d.level("outcome")
		if res.Status == "approved" || res.Status == "error" || lv == lvOff {
			return pushMsg{Kind: "clear", Tag: tag}, pushOpts{TTL: time.Hour, Urgency: "normal"}, true
		}
		return pushMsg{Kind: "info", Title: title, Body: short(reasonOnly(r.Reason), 600), Icon: icon, Tag: tag,
			URL: n.base + "/#history", Silent: lv == lvSilent}, pushOpts{TTL: time.Hour, Urgency: "low"}, true
	})
	return werr
}

func (n *notifyRouter) Used(a Activity, url string) error {
	s, _ := n.prefs.get()
	cmd := ""
	if len(a.Uses) > 0 {
		cmd = a.Uses[0].Command
	}
	m := pushMsg{Kind: "used", Title: withProject(useProjects(a), useTitle(a)), Body: pushCmd(cmd, 5) + "\n" + useContext(a),
		Icon: projectIcons.url(useRoot(a)), Tag: a.Tag, URL: url,
		Actions: []pushAction{{ID: "details", Title: "Details", URL: url}, {ID: "revoke", Title: "Revoke", Post: "/u/" + a.Tag + "/revoke"}}}
	_, err := n.fanout(s.active(), func(d pushDevice) (pushMsg, pushOpts, bool) {
		lv := d.level(a.Kind)
		if lv == lvOff {
			return pushMsg{}, pushOpts{}, false
		}
		mm := m
		mm.Silent = lv == lvSilent || lv == lvFirst && a.Count > 1
		urg := "normal"
		if mm.Silent {
			urg = "low"
		}
		return mm, pushOpts{TTL: time.Hour, Urgency: urg, Topic: pushTopic(a.Tag)}, true
	})
	return err
}

func (n *notifyRouter) Revoked(a Activity) error {
	s, _ := n.prefs.get()
	title, icon := "Revoked · "+withProject(useProjects(a), a.Title), projectIcons.url(useRoot(a))
	_, err := n.fanout(s.active(), func(d pushDevice) (pushMsg, pushOpts, bool) {
		if d.level(a.Kind) == lvOff { // never showed it
			return pushMsg{}, pushOpts{}, false
		}
		lv := d.level("outcome")
		if lv == lvOff {
			return pushMsg{Kind: "clear", Tag: a.Tag}, pushOpts{TTL: time.Hour}, true
		}
		return pushMsg{Kind: "info", Title: title, Body: fmt.Sprintf("Used %d× before it was revoked.", a.Count),
			Icon: icon, Tag: a.Tag, Silent: lv == lvSilent}, pushOpts{TTL: time.Hour, Urgency: "low", Topic: pushTopic(a.Tag)}, true
	})
	return err
}

// Test sends a test notice to one device.
func (n *notifyRouter) Test(id string) error {
	s, err := n.prefs.get()
	if err != nil {
		return err
	}
	for _, d := range s.Devices {
		if d.ID == id {
			_, err := n.fanout([]pushDevice{d}, func(d pushDevice) (pushMsg, pushOpts, bool) {
				return pushMsg{Kind: "test", Title: "opgate notifications work", Body: "This is " + d.Name + ". Tap to open the settings.",
					Tag: "opgate-test", URL: n.base + "/settings"}, pushOpts{TTL: 5 * time.Minute, Urgency: "high"}, true
			})
			return err
		}
	}
	return errors.New("no such device")
}
