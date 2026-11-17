package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

//go:embed web
var web embed.FS

// clientMsg is one line from the server to a waiting client.
type clientMsg struct {
	Event   string  `json:"event"` // pending, result, status
	ID      string  `json:"id,omitempty"`
	URL     string  `json:"url,omitempty"`
	Summary string  `json:"summary,omitempty"`
	Warning string  `json:"warning,omitempty"`
	Result  *Result `json:"result,omitempty"`
	Status  any     `json:"status,omitempty"`
}

// serveSocket handles client requests on the unix socket.
func (b *Broker) serveSocket(path string) error {
	os.Remove(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
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
		go b.handleClient(c)
	}
}

func (b *Broker) handleClient(c *net.UnixConn) {
	defer c.Close()
	enc := json.NewEncoder(c)
	// a failed write means the client hung up: there is nobody left to tell, and the read below ends the wait
	send := func(m clientMsg) { _ = enc.Encode(m) }
	line, err := bufio.NewReader(io.LimitReader(c, 1<<20)).ReadBytes('\n') // a request is a few KB
	if err != nil {
		return
	}
	var in RequestIn
	if err := json.Unmarshal(line, &in); err != nil {
		send(clientMsg{Event: "result", Result: &Result{Status: "error", Error: "bad request"}})
		return
	}
	if in.Kind == "record" { // a client reports a route that bypassed the approval flow (record.go)
		switch in.Route {
		case Route1Password, Route1PasswordFailed, RouteOpPassthrough, RouteOpAway:
		default:
			return
		}
		var refs []string
		for _, ref := range in.Refs {
			if strings.HasPrefix(ref, "op://") && len(refs) < 8 {
				refs = append(refs, short(ref, 200))
			}
		}
		r := &Request{RequestIn: RequestIn{Kind: "secrets", Refs: refs, Reason: short(in.Reason, 300), Cwd: in.Cwd},
			ID: randomID(12), Caller: argsOf(peerProcs(c))}
		b.audit.Log(r, "routed", in.Route, "")
		send(clientMsg{Event: "ok"})
		return
	}
	if in.Kind == "reload" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		b.autoload(ctx)
		cancel()
		in.Kind = "status"
	}
	if in.Kind == "status" {
		var pend []string
		for _, r := range b.Pending() {
			pend = append(pend, fmt.Sprintf("%s %s (%s)", r.ID, summary(r), r.Reason))
		}
		st := map[string]any{"pending": pend, "keys": b.keys.Keys(), "version": version}
		if item, since, ok := kcWait.waiting(); ok {
			st["keychain"] = waitErr(item, since).Error()
		} else if err := kcLocked.locked(); err != nil {
			st["keychain"] = err.Error()
		}
		send(clientMsg{Event: "status", Status: st})
		return
	}
	// a request now would hang or reach nobody: say what opgate waits for
	if item, since, ok := kcWait.waiting(); ok {
		send(clientMsg{Event: "result", Result: &Result{Status: "error", Error: "opgate is " + waitErr(item, since).Error()}})
		return
	}
	r, err := b.SubmitProcs(in, peerProcs(c))
	if err != nil {
		send(clientMsg{Event: "result", Result: &Result{Status: "error", Error: err.Error()}})
		return
	}
	send(clientMsg{Event: "pending", ID: r.ID, URL: b.URL(r), Summary: summary(r), Warning: r.Warning})
	// a closed client connection ends the wait (and the request)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // returns when the client hangs up (or sends more, which no client does)
		cancel()
	}()
	res := b.Wait(ctx, r)
	send(clientMsg{Event: "result", ID: r.ID, Result: &res})
}

// --- approval page ---

func (b *Broker) allowed(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && slices.Contains(b.cfg.AllowFrom, host)
}

// pageOrigins are the origins of opgate's own pages: the public URL and localhost on the port opgate listens on.
// A POST from any other origin (another site, or another local web server) is refused.
func pageOrigins(cfg Config) []string {
	_, port, _ := net.SplitHostPort(cfg.Listen)
	return []string{strings.TrimSuffix(cfg.PublicURL, "/"), "http://localhost:" + port, "http://127.0.0.1:" + port, "http://[::1]:" + port}
}

func (b *Broker) handler() http.Handler {
	page := template.Must(template.ParseFS(web, "web/page.html"))
	actPage := template.Must(template.ParseFS(web, "web/activity.html"))
	dashPage := template.Must(template.New("dashboard.html").Funcs(template.FuncMap{"statusLabel": statusLabel, "typeLabel": typeLabel, "firstLine": firstLine}).ParseFS(web, "web/dashboard.html"))
	mux := http.NewServeMux()
	static, _ := fs.Sub(web, "web")
	mux.Handle("GET /app.js", http.FileServerFS(static))
	mux.Handle("GET /app.css", http.FileServerFS(static))
	for _, f := range []string{"/favicon.svg", "/favicon.ico", "/favicon-32.png", "/apple-touch-icon.png", "/sw.js",
		"/icon-192.png", "/icon-512.png", "/icon-maskable.png", "/badge.png"} {
		mux.Handle("GET "+f, http.FileServerFS(static))
	}
	mux.HandleFunc("GET /manifest.webmanifest", func(w http.ResponseWriter, req *http.Request) {
		data, _ := web.ReadFile("web/manifest.webmanifest")
		w.Header().Set("Content-Type", "application/manifest+json")
		_, _ = w.Write(data) // fails only when the page went away
	})
	mux.HandleFunc("GET /project-icon/{file}", projectIcons.serve)
	b.settingsRoutes(mux)
	mux.HandleFunc("GET /r/{id}", func(w http.ResponseWriter, req *http.Request) {
		go_ := req.URL.Query().Get("go")
		if go_ != "approve" && go_ != "deny" {
			go_ = ""
		}
		r := b.get(req.PathValue("id"))
		// the push's Approve button may start the passkey prompt on a desktop too (once)
		auto := r != nil && go_ == "approve" && r.takeGoToken(req.URL.Query().Get("t"))
		b.renderPage(w, page, r, KindSecrets, go_, auto, b.requestState(req.PathValue("id"))["status"])
	})
	mux.HandleFunc("GET /enroll/{id}", func(w http.ResponseWriter, req *http.Request) {
		b.renderPage(w, page, b.getEnroll(req.PathValue("id"), req.URL.Query().Get("k")), KindEnroll, "", false, "")
	})
	mux.HandleFunc("POST /r/{id}/options", func(w http.ResponseWriter, req *http.Request) {
		r := b.get(req.PathValue("id"))
		if r == nil || r.Kind == KindEnroll {
			http.Error(w, "no such request", http.StatusNotFound)
			return
		}
		opts, err := b.BeginApproval(req.Context(), r)
		writeJSON(w, opts, err)
	})
	mux.HandleFunc("POST /r/{id}/approve", func(w http.ResponseWriter, req *http.Request) {
		r := b.get(req.PathValue("id"))
		if r == nil || r.Kind == KindEnroll {
			http.Error(w, "no such request", http.StatusNotFound)
			return
		}
		q := req.URL.Query().Get("dur")
		if q == "" {
			q = req.URL.Query().Get("grant") // pages from before 0.8
		}
		dur, _ := time.ParseDuration(q)
		writeJSON(w, map[string]string{"status": "approved"}, b.FinishApproval(req.Context(), r, req, dur))
	})
	mux.HandleFunc("POST /r/{id}/deny", func(w http.ResponseWriter, req *http.Request) {
		// a page or notification for a request decided elsewhere hears so, instead of "Denied" for a click that did nothing
		r := b.get(req.PathValue("id"))
		if r == nil || r.Kind == KindEnroll || !b.decide(r, Result{Status: "denied", Error: "denied on the phone", By: "page"}) {
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "already decided"})
			return
		}
		writeJSON(w, map[string]string{"status": "denied"}, nil)
	})
	mux.HandleFunc("GET /r/{id}/state", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, b.requestState(req.PathValue("id")), nil)
	})
	mux.HandleFunc("GET /events", b.serveEvents)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dashPage.Execute(w, b.dashboard(req)); err != nil {
			log.Printf("overview page: %v", err)
		}
	})
	mux.HandleFunc("GET /overview/state", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, map[string]string{"sig": b.dashboard(req).Sig}, nil)
	})
	mux.HandleFunc("POST /dismiss", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&in); err != nil {
			writeJSON(w, nil, errors.New("bad request"))
			return
		}
		writeJSON(w, map[string]string{"status": "dismissed"}, b.Dismiss(in.Key))
	})
	mux.HandleFunc("POST /unlock/options", func(w http.ResponseWriter, req *http.Request) {
		id, opts, err := b.BeginUnlock(req.Context())
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, map[string]any{"id": id, "publicKey": opts.Response}, nil)
	})
	mux.HandleFunc("POST /unlock/finish", func(w http.ResponseWriter, req *http.Request) {
		token, err := b.FinishUnlock(req.Context(), req.URL.Query().Get("id"), req)
		if err == nil {
			setViewCookie(w, token, int(viewFor/time.Second))
		}
		writeJSON(w, map[string]string{"status": "unlocked"}, err)
	})
	mux.HandleFunc("POST /lock", func(w http.ResponseWriter, req *http.Request) {
		b.lock(req)
		setViewCookie(w, "", -1)
		writeJSON(w, map[string]string{"status": "locked"}, nil)
	})
	mux.HandleFunc("POST /restore", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Ref string `json:"ref"`
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&in); err != nil {
			writeJSON(w, nil, errors.New("bad request"))
			return
		}
		r, err := b.requestRestore(in.Ref)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, map[string]string{"url": "/r/" + r.ID}, nil)
	})
	// the history is the overview's first tab; /history stays for old links and notifications
	mux.HandleFunc("GET /history", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/#history", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /history/items", func(w http.ResponseWriter, req *http.Request) {
		p := b.historyPage(parseHistQuery(req.URL.Query()))
		var buf bytes.Buffer
		if err := dashPage.ExecuteTemplate(&buf, "events", p); err != nil {
			log.Printf("history items: %v", err)
		}
		writeJSON(w, map[string]any{"html": buf.String(), "page": p.Page, "pages": p.Pages, "total": p.Total, "label": p.Label}, nil)
	})
	mux.HandleFunc("GET /u/{tag}", func(w http.ResponseWriter, req *http.Request) {
		a, ok := b.getActivity(req.PathValue("tag"))
		d := activityData{Found: ok, A: a}
		if req.URL.Query().Get("go") == "revoke" {
			d.Go = "revoke"
		}
		d.KindLabel = map[string]string{"grant": "Secrets · same again", "key": "SSH key", "daily": "SSH key · no approval"}[a.Kind]
		if !a.Until.IsZero() {
			d.Until = a.Until.Local().Format("15:04")
		}
		for i := range d.A.Uses {
			d.A.Uses[i].Folder = shortHome(d.A.Uses[i].Folder)
			d.A.Uses[i].Icon = projectIcons.url(d.A.Uses[i].Root)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := actPage.Execute(w, d); err != nil {
			log.Printf("activity page: %v", err)
		}
	})
	mux.HandleFunc("GET /u/{tag}/state", func(w http.ResponseWriter, req *http.Request) {
		a, ok := b.getActivity(req.PathValue("tag"))
		writeJSON(w, map[string]any{"found": ok, "count": a.Count, "revoked": a.Revoked}, nil)
	})
	mux.HandleFunc("POST /u/{tag}/revoke", func(w http.ResponseWriter, req *http.Request) {
		_, n, err := b.Revoke(req.PathValue("tag"), false)
		writeJSON(w, map[string]int{"stopped": n}, err)
	})
	mux.HandleFunc("POST /u/{tag}/restore", func(w http.ResponseWriter, req *http.Request) {
		a, ok := b.getActivity(req.PathValue("tag"))
		if !ok || a.Kind != "daily" {
			writeJSON(w, nil, errors.New("nothing to restore"))
			return
		}
		r, err := b.requestRestore(a.Ref)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, map[string]string{"url": "/r/" + r.ID}, nil)
	})
	mux.HandleFunc("POST /u/{tag}/stop", func(w http.ResponseWriter, req *http.Request) {
		_, n, err := b.Revoke(req.PathValue("tag"), true)
		writeJSON(w, map[string]int{"stopped": n}, err)
	})
	mux.HandleFunc("POST /enroll/{id}/options", func(w http.ResponseWriter, req *http.Request) {
		r := b.getEnroll(req.PathValue("id"), req.URL.Query().Get("k"))
		if r == nil {
			http.Error(w, "no such enrollment", http.StatusNotFound)
			return
		}
		opts, err := b.BeginEnroll(r)
		writeJSON(w, opts, err)
	})
	mux.HandleFunc("POST /enroll/{id}/finish", func(w http.ResponseWriter, req *http.Request) {
		r := b.getEnroll(req.PathValue("id"), req.URL.Query().Get("k"))
		if r == nil {
			http.Error(w, "no such enrollment", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "registered"}, b.FinishEnroll(r, req))
	})
	public, _ := url.Parse(b.cfg.PublicURL)
	origins := pageOrigins(b.cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !b.allowed(req) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// DNS rebinding and cross-site forms: only our own host names, and POSTs only from our own pages
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != public.Hostname() && host != "localhost" && host != "127.0.0.1" && host != "::1" {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		if req.Method == http.MethodPost {
			if o := req.Header.Get("Origin"); o != "" && !slices.Contains(origins, o) {
				http.Error(w, "cross-site request", http.StatusForbidden)
				return
			}
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, req)
	})
}

type refView struct{ Item, Field string }

type activityData struct {
	Found                bool
	A                    Activity
	Go, KindLabel, Until string
}

type durOpt struct {
	Value, Label string
	Checked      bool
}

type pageData struct {
	Found, Enroll, Grantable   bool
	Ended                      string // not open any more: how it ended, when opgate still knows (approved, denied, ...)
	Auto                       bool   // Go=approve came with the push's token
	EnrollKey                  string // enroll: the key from the link (posted back with options and finish)
	R                          *Request
	Kind, KindLabel, Title, Go string
	Agent, Script, Folder      string
	Project, Icon              string
	Reason, Runs               string // the agent's words; the command `opgate run` appended to them
	Command, TTL, ExpiresClock string
	ExpiresAt                  int64 // unix ms, for the countdown
	Durations                  []durOpt
	Refs                       []refView
	Chain                      []string
}

func (b *Broker) renderPage(w http.ResponseWriter, t *template.Template, r *Request, kind, go_ string, auto bool, state string) {
	d := pageData{Enroll: kind == KindEnroll, Go: go_, Auto: auto, Kind: "secrets"}
	if state != "pending" && state != "gone" {
		d.Ended = state
	}
	if d.Enroll {
		d.Kind = KindEnroll
	}
	if r != nil && (r.Kind == KindEnroll) == d.Enroll {
		a := askerOf(r)
		d.Found, d.R, d.Kind, d.Title, d.EnrollKey = true, r, r.Kind, pageTitle(r), r.enrollKey
		d.Agent, d.Script, d.Command = a.Agent, a.Script, tidyLines(a.Command)
		d.Reason, d.Runs = splitReason(r.Reason)
		d.Project, d.Icon = a.Project, projectIcons.url(a.Root)
		d.KindLabel = map[string]string{KindSSH: "SSH key", KindSecrets: "Secrets", KindEnroll: "New passkey", KindRestore: "Load key again",
			KindHandover: "New opgate build"}[r.Kind]
		d.Grantable = r.Kind == KindSecrets
		d.Folder = shortHome(r.Cwd)
		d.Refs = groupRefs(r.Refs, true)
		if r.Kind == KindHandover {
			d.Refs = []refView{{Item: "opgate's keychain store", Field: "service account token, push key, settings"}}
		}
		d.Chain = slices.Clone(r.Caller)
		if r.Kind == KindSSH {
			d.TTL = human(r.TTL)
		}
		d.Durations = durationOptions(r)
		d.ExpiresAt = r.Expires.UnixMilli()
		d.ExpiresClock = r.Expires.Local().Format("15:04")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, d); err != nil {
		log.Printf("page: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSONStatus(w, http.StatusOK, v)
}

// writeJSONStatus answers with v. A failed write means the page went away: there is nobody left to tell.
func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// autoload loads the keys listed in the control item's "autoload" field (one op:// reference per line) without an
// approval: the owner chose these to be used freely (for example the git signing key).
func (b *Broker) autoload(ctx context.Context) {
	raw, err := b.store.Resolve(ctx, b.cfg.ControlItem+"/autoload")
	if err != nil {
		if !errors.Is(err, errKeychainLocked) { // logged once by kcLocked
			log.Printf("autoload: %v", err)
		}
		return
	}
	for _, ref := range autoloadRefs(raw) {
		b.mu.Lock()
		revoked := b.revokedRefs[ref]
		b.mu.Unlock()
		if revoked {
			log.Printf("autoload %s: revoked on the phone; load it again from its activity page", ref)
			continue
		}
		if b.keys.HasRef(ref) {
			continue
		}
		key, err := b.store.Resolve(ctx, ref)
		if err == nil {
			err = b.keys.AddKey(key, ref, 0)
		}
		if err != nil {
			log.Printf("autoload %s: %v", ref, err)
			continue
		}
		log.Printf("autoload: loaded %s", ref)
		b.changes.publish()
	}
}

// autoloadRefs splits the autoload field: one reference per line (item titles may contain spaces).
func autoloadRefs(raw string) []string {
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func serve() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	log.Printf("opgate %s starting", version)
	keys := newAgent(cfg.UpstreamAgent)
	pusher := &webPusher{blobs: keychainBlobs{}, client: &http.Client{Timeout: pushSendTimeout}, subject: cfg.PublicURL}
	notify := newNotifyRouter(cfg.PublicURL, keychainBlobs{}, pusher)
	b, err := newBroker(cfg, &opStore{}, notify, keys, &Audit{path: cfg.AuditLog})
	if err != nil {
		return err
	}
	b.push = notify
	b.kcSnapshot = kcStore.snapshot
	b.passkeyCache = time.Minute
	keys.OnUse = b.keyUsed
	keys.OnUpstream = b.upstreamUsed
	go func() {
		// the keychain or 1Password may not be reachable right after login: retry until a key is loaded
		wait := 30 * time.Second
		for len(keys.Keys()) == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			b.autoload(ctx)
			cancel()
			if len(keys.Keys()) == 0 {
				if kcLocked.locked() != nil {
					wait = 30 * time.Second // load the keys soon after the Mac is unlocked
				}
				time.Sleep(wait)
				wait = min(2*wait, 10*time.Minute)
			}
		}
	}()
	errc := make(chan error, 3)
	go func() { errc <- keys.Serve(cfg.AgentSocket) }()
	go func() { errc <- b.serveSocket(cfg.Socket) }()
	go func() {
		srv := &http.Server{Addr: cfg.Listen, Handler: b.handler(), ReadHeaderTimeout: 10 * time.Second}
		errc <- srv.ListenAndServe()
	}()
	log.Printf("opgate %s: requests %s, agent %s, page %s (%s)", version, cfg.Socket, cfg.AgentSocket, cfg.Listen, cfg.PublicURL)
	// after the sockets are up: the first keychain read of a new build waits for the owner's answer at the Mac
	go func() {
		if _, err := pusher.PublicKey(); err != nil { // creates the VAPID key on the first start
			log.Printf("web push: %v", err)
		}
		kcStore.prune() // older builds' items, once this build has its own

	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	return serveUntil(errc, sig)
}

// serveUntil returns the first server error, or nil once launchd stops the service (SIGTERM on bootout and
// kickstart -k): a stop is no failure, and launchctl list shows the last run's exit status.
func serveUntil(errc <-chan error, sig <-chan os.Signal) error {
	select {
	case err := <-errc:
		return err
	case s := <-sig:
		log.Printf("opgate %s stopping (%v)", version, s)
		return nil
	}
}

// durationOptions is the switch on the page: secrets "Once / 15 min / 30 min / 1 h" (15 min preselected), ssh keys
// "15 min / 1 h / 4 h" plus the agent's own duration if it is none of these (the agent's choice preselected).
func durationOptions(r *Request) []durOpt {
	var out []durOpt
	switch r.Kind {
	case KindSecrets:
		for _, d := range grantChoices {
			o := durOpt{Value: d.String(), Label: human(d), Checked: d == defaultGrant}
			if d == 0 {
				o.Value, o.Label = "0s", "Once"
			}
			out = append(out, o)
		}
	case KindSSH:
		choices := slices.Clone(ttlChoices)
		if !slices.Contains(choices, r.TTL) {
			choices = append(choices, r.TTL)
			slices.Sort(choices)
		}
		for _, d := range choices {
			out = append(out, durOpt{Value: d.String(), Label: human(d), Checked: d == r.TTL})
		}
	}
	return out
}
