package main

// opgate creds: the credential map. A registry (a JSON file, the build value credsReg; no secret values) lists every
// credential with where it lives, who uses it, how to rotate it and how to check it. `opgate creds` checks each one
// (read-only probes: an HTTP call, a TLS handshake, RDAP, Grafana's service account API, a VictoriaMetrics query or a
// small command that prints JSON), adds the last use from opgate's audit log, reports status and expiry, keeps a
// change log (creds.jsonl next to the audit log) and can push metrics to VictoriaMetrics for Grafana alerts.
//
// The registry is a file agents can edit, so it never influences approvals: it is a report. The service only shows
// the last run's result (creds-latest.json) on its overview page, as data. Probes run as whoever runs `opgate creds` (no privileges of the service) and read only
// tier B files (~/.config/...); tier A values (op://...) are never fetched for a check.

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

// Cred is one registry entry.
type Cred struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Tier         string   `json:"tier"`  // A or B
	Store        string   `json:"store"` // op://..., ~/.config/..., keychain:<item> or any label
	UsedBy       []string `json:"used_by"`
	Scope        string   `json:"scope,omitempty"`
	Created      string   `json:"created,omitempty"`       // YYYY-MM-DD
	Expires      string   `json:"expires,omitempty"`       // YYYY-MM-DD, declared (a probe's expiry wins)
	LifespanDays int      `json:"lifespan_days,omitempty"` // expiry = created + lifespan when nothing else says
	WarnDays     int      `json:"warn_days,omitempty"`     // "expiring" this many days ahead (default 30)
	Rotate       string   `json:"rotate,omitempty"`        // where the procedure is documented
	Revoke       string   `json:"revoke,omitempty"`
	Lifecycle    string   `json:"lifecycle,omitempty"` // row id in lifecycle.csv
	Probe        *Probe   `json:"probe,omitempty"`
}

// Probe says how to check a credential. Exactly one kind per probe.
type Probe struct {
	Type string `json:"type"` // http, tls, rdap, grafana_sa, metric, command

	// http: GET URL with the credential; valid when the status is in Expect (default 200)
	URL       string `json:"url,omitempty"`
	Auth      string `json:"auth,omitempty"`       // bearer, header:<Name>[:<template with {value}>], basic:<user>, none
	TokenFile string `json:"token_file,omitempty"` // ~/... file with the value (tier B)
	Expect    []int  `json:"expect,omitempty"`
	Insecure  bool   `json:"insecure,omitempty"` // self-signed certificate

	// tls: certificate expiry of Address (host:port), validated for ServerName
	Address    string `json:"address,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	// rdap: domain expiry
	Domain string `json:"domain,omitempty"`

	// grafana_sa: service account Account's newest token (expiry, last use) via the admin login in PasswordFile
	Account      string `json:"account,omitempty"`
	PasswordFile string `json:"password_file,omitempty"`

	// metric: Query returns a unix timestamp of the last success (e.g. a job that uses the credential); valid when it
	// is younger than MaxAge
	Query  string   `json:"query,omitempty"`
	MaxAge Duration `json:"max_age,omitempty"`

	// command: Argv prints {"valid": bool, "expires": "...", "last_used": "...", "detail": "..."} (all optional)
	Argv    []string `json:"argv,omitempty"`
	Timeout Duration `json:"timeout,omitempty"`
}

// Registry is the file.
type Registry struct {
	Credentials []Cred `json:"credentials"`
}

// Finding is what a probe found (zero values: unknown).
type Finding struct {
	Valid    *bool
	Expires  time.Time
	LastUsed time.Time
	Detail   string
}

// Report is one credential's result.
type Report struct {
	Cred       Cred      `json:"-"`
	ID         string    `json:"id"`
	Tier       string    `json:"tier"`
	Status     string    `json:"status"` // ok, expiring, expired, invalid, unknown
	Expires    time.Time `json:"expires,omitzero"`
	ExpiresSrc string    `json:"expires_source,omitempty"` // probe, declared, lifespan
	LastUsed   time.Time `json:"last_used,omitzero"`
	LastSrc    string    `json:"last_used_source,omitempty"` // probe, opgate
	Uses30d    int       `json:"opgate_uses_30d"`
	Detail     string    `json:"detail,omitempty"`
}

var statusCode = map[string]int{"ok": 0, "expiring": 1, "expired": 2, "invalid": 3, "unknown": -1}

// defaultRegistryPath is the registry this Mac's build names ("": none, opgate creds is off without --file).
func defaultRegistryPath() string { return expand(credsReg) }

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		return home(p[2:])
	}
	return p
}

func parseDay(s string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02", s, time.Local)
}

// loadRegistry reads and validates the registry.
func loadRegistry(path string) (Registry, error) {
	var r Registry
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&r); err != nil {
		return r, fmt.Errorf("%s: %w", path, err)
	}
	return r, validateRegistry(r)
}

func validateRegistry(r Registry) error {
	var errs []string
	seen := map[string]bool{}
	for i, c := range r.Credentials {
		where := fmt.Sprintf("entry %d (%s)", i+1, c.ID)
		if c.ID == "" || strings.ContainsAny(c.ID, " \"{}=,") {
			errs = append(errs, where+": id missing or not a plain word")
		}
		if seen[c.ID] {
			errs = append(errs, where+": duplicate id")
		}
		seen[c.ID] = true
		if c.Tier != "A" && c.Tier != "B" {
			errs = append(errs, where+": tier must be A or B")
		}
		if c.Title == "" || c.Store == "" || len(c.UsedBy) == 0 {
			errs = append(errs, where+": title, store and used_by are required")
		}
		for _, d := range []string{c.Created, c.Expires} {
			if d != "" {
				if _, err := parseDay(d); err != nil {
					errs = append(errs, where+": date "+d+" is not YYYY-MM-DD")
				}
			}
		}
		if c.LifespanDays > 0 && c.Created == "" {
			errs = append(errs, where+": lifespan_days needs created")
		}
		if p := c.Probe; p != nil {
			if msg := validateProbe(c, p); msg != "" {
				errs = append(errs, where+": "+msg)
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

func validateProbe(c Cred, p *Probe) string {
	switch p.Type {
	case "http":
		if p.URL == "" {
			return "http probe needs url"
		}
		a := p.Auth
		if a != "none" && a != "bearer" && !strings.HasPrefix(a, "header:") && !strings.HasPrefix(a, "basic:") {
			return "http auth must be bearer, header:<Name>, basic:<user> or none"
		}
		if a != "none" && p.TokenFile == "" {
			return "http probe with auth needs token_file"
		}
		if strings.HasPrefix(p.TokenFile, "op://") || (c.Tier == "A" && a != "none") {
			return "probes never read tier A values (op://); check tier A credentials by metadata only"
		}
	case "tls":
		if p.Address == "" {
			return "tls probe needs address"
		}
	case "rdap":
		if p.Domain == "" {
			return "rdap probe needs domain"
		}
	case "grafana_sa":
		if p.URL == "" || p.Account == "" || p.PasswordFile == "" {
			return "grafana_sa probe needs url, account and password_file"
		}
	case "metric":
		if p.URL == "" || p.Query == "" || p.MaxAge.Duration <= 0 {
			return "metric probe needs url, query and max_age"
		}
	case "command":
		if len(p.Argv) == 0 {
			return "command probe needs argv"
		}
	default:
		return "unknown probe type " + p.Type
	}
	return ""
}

// ---------- probes

type prober struct {
	client *http.Client
	now    func() time.Time
	roots  *x509.CertPool // nil: the system roots (tests set their own)
}

var credsNow = time.Now // tests

func newProber() *prober {
	return &prober{client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: noRedirect}, now: credsNow}
}

func boolp(b bool) *bool { return &b }

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(expand(path))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (pr *prober) run(ctx context.Context, c Cred) Finding {
	p := c.Probe
	switch p.Type {
	case "http":
		return pr.http(ctx, p)
	case "tls":
		return pr.tls(ctx, p)
	case "rdap":
		return pr.rdap(ctx, p)
	case "grafana_sa":
		return pr.grafana(ctx, p)
	case "metric":
		return pr.metric(ctx, p)
	case "command":
		return pr.command(ctx, p)
	}
	return Finding{Detail: "unknown probe"}
}

// noRedirect: a probe answers with the first response. Following a redirect would send custom auth headers
// (X-API-Key) to wherever it points; Go only drops Authorization across hosts.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (pr *prober) http(ctx context.Context, p *Probe) Finding {
	req, err := http.NewRequestWithContext(ctx, "GET", p.URL, nil)
	if err != nil {
		return Finding{Detail: err.Error()}
	}
	if p.Auth != "none" {
		v, err := readSecret(p.TokenFile)
		if err != nil {
			return Finding{Valid: boolp(false), Detail: "token file: " + err.Error()}
		}
		switch {
		case p.Auth == "bearer":
			req.Header.Set("Authorization", "Bearer "+v)
		case strings.HasPrefix(p.Auth, "header:"):
			name, tmpl, ok := strings.Cut(strings.TrimPrefix(p.Auth, "header:"), ":")
			if !ok {
				tmpl = "{value}"
			}
			req.Header.Set(name, strings.ReplaceAll(tmpl, "{value}", v))
		case strings.HasPrefix(p.Auth, "basic:"):
			req.SetBasicAuth(strings.TrimPrefix(p.Auth, "basic:"), v)
		}
	}
	client := pr.client
	if p.Insecure {
		client = &http.Client{Timeout: pr.client.Timeout, CheckRedirect: noRedirect,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Finding{Detail: "unreachable: " + scrub(err.Error(), p.URL)}
	}
	// drained so the connection can be reused; the status code is the finding, a broken body doesn't change it
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	expect := p.Expect
	if len(expect) == 0 {
		expect = []int{200}
	}
	for _, e := range expect {
		if resp.StatusCode == e {
			return Finding{Valid: boolp(true), Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return Finding{Valid: boolp(false), Detail: fmt.Sprintf("HTTP %d: rejected", resp.StatusCode)}
	}
	return Finding{Detail: fmt.Sprintf("HTTP %d (expected %v)", resp.StatusCode, expect)}
}

// scrub keeps URLs out of error texts (a query string could hold a value).
func scrub(msg, u string) string {
	if pu, err := url.Parse(u); err == nil && pu.RawQuery != "" {
		msg = strings.ReplaceAll(msg, pu.RawQuery, "…")
	}
	return msg
}

func (pr *prober) tls(ctx context.Context, p *Probe) Finding {
	host := p.ServerName
	if host == "" {
		host, _, _ = net.SplitHostPort(p.Address)
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{ServerName: host, RootCAs: pr.roots}}
	c, err := d.DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return Finding{Valid: boolp(false), Detail: "TLS: " + err.Error()}
	}
	defer c.Close()
	conn, ok := c.(*tls.Conn)
	if !ok {
		return Finding{Detail: "TLS: not a TLS connection"}
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Finding{Detail: "no certificate"}
	}
	return Finding{Valid: boolp(true), Expires: certs[0].NotAfter, Detail: "issuer " + certs[0].Issuer.CommonName}
}

var rdapBase = "https://rdap.org/domain/"

func (pr *prober) rdap(ctx context.Context, p *Probe) Finding {
	req, err := http.NewRequestWithContext(ctx, "GET", rdapBase+url.PathEscape(p.Domain), nil)
	if err != nil {
		return Finding{Detail: "RDAP: " + err.Error()}
	}
	resp, err := pr.client.Do(req)
	if err != nil {
		return Finding{Detail: "RDAP: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Finding{Detail: fmt.Sprintf("RDAP HTTP %d", resp.StatusCode)}
	}
	var d struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return Finding{Detail: "RDAP: " + err.Error()}
	}
	for _, e := range d.Events {
		if e.Action == "expiration" {
			if t, err := time.Parse(time.RFC3339, e.Date); err == nil {
				return Finding{Expires: t, Detail: "RDAP"}
			}
		}
	}
	return Finding{Detail: "RDAP: no expiration event"}
}

func (pr *prober) grafana(ctx context.Context, p *Probe) Finding {
	pw, err := readSecret(p.PasswordFile)
	if err != nil {
		return Finding{Detail: "password file: " + err.Error()}
	}
	get := func(path string, v any) error {
		req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(p.URL, "/")+path, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth("admin", pw)
		resp, err := pr.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
	}
	var search struct {
		ServiceAccounts []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			IsDisabled bool   `json:"isDisabled"`
		} `json:"serviceAccounts"`
	}
	if err = get("/api/serviceaccounts/search?perpage=100&query="+url.QueryEscape(p.Account), &search); err != nil {
		return Finding{Detail: "Grafana: " + err.Error()}
	}
	for _, sa := range search.ServiceAccounts {
		if sa.Name != p.Account {
			continue
		}
		if sa.IsDisabled {
			return Finding{Valid: boolp(false), Detail: "service account disabled"}
		}
		var toks []struct {
			Name       string     `json:"name"`
			Expiration *time.Time `json:"expiration"`
			LastUsedAt *time.Time `json:"lastUsedAt"`
			HasExpired bool       `json:"hasExpired"`
		}
		if err = get(fmt.Sprintf("/api/serviceaccounts/%d/tokens", sa.ID), &toks); err != nil {
			return Finding{Detail: "Grafana: " + err.Error()}
		}
		f := Finding{Valid: boolp(false), Detail: "no unexpired token"}
		for _, t := range toks {
			if t.HasExpired {
				continue
			}
			f.Valid, f.Detail = boolp(true), fmt.Sprintf("%d token(s)", len(toks))
			if t.Expiration != nil && (f.Expires.IsZero() || t.Expiration.After(f.Expires)) {
				f.Expires = *t.Expiration
			}
			if t.LastUsedAt != nil && t.LastUsedAt.After(f.LastUsed) {
				f.LastUsed = *t.LastUsedAt
			}
		}
		return f
	}
	return Finding{Valid: boolp(false), Detail: "service account " + p.Account + " not found"}
}

func (pr *prober) metric(ctx context.Context, p *Probe) Finding {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(p.URL, "/")+"/api/v1/query?query="+url.QueryEscape(p.Query), nil)
	if err != nil {
		return Finding{Detail: "metrics: " + err.Error()}
	}
	resp, err := pr.client.Do(req)
	if err != nil {
		return Finding{Detail: "metrics: " + err.Error()}
	}
	defer resp.Body.Close()
	var d struct {
		Data struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil || len(d.Data.Result) == 0 || len(d.Data.Result[0].Value) < 2 {
		return Finding{Detail: "metrics: no data for " + p.Query}
	}
	var ts float64
	if s, ok := d.Data.Result[0].Value[1].(string); ok {
		if ts, err = strconv.ParseFloat(s, 64); err != nil {
			return Finding{Detail: "metrics: not a timestamp: " + s}
		}
	}
	if ts <= 0 {
		return Finding{Valid: boolp(false), Detail: "never succeeded"}
	}
	last := time.Unix(int64(ts), 0)
	age := pr.now().Sub(last)
	return Finding{Valid: boolp(age <= p.MaxAge.Duration), LastUsed: last,
		Detail: fmt.Sprintf("last success %s ago (max %s)", age.Round(time.Minute), p.MaxAge.Duration)}
}

func (pr *prober) command(ctx context.Context, p *Probe) Finding {
	timeout := p.Timeout.Duration
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := make([]string, len(p.Argv))
	for i, a := range p.Argv {
		argv[i] = expand(a)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// own process group: on timeout the whole group is killed, so a child holding stdout can't keep us waiting
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard // stderr may echo arguments or values: never shown
	if err := cmd.Run(); err != nil {
		return Finding{Detail: "command failed: " + err.Error()}
	}
	var r struct {
		Valid    *bool  `json:"valid"`
		Expires  string `json:"expires"`
		LastUsed string `json:"last_used"`
		Detail   string `json:"detail"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &r); err != nil {
		return Finding{Detail: "command output is not JSON"}
	}
	f := Finding{Valid: r.Valid, Detail: r.Detail}
	f.Expires, _ = parseTime(r.Expires)
	f.LastUsed, _ = parseTime(r.LastUsed)
	return f
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return parseDay(s)
}

// ---------- opgate's own usage records

// auditUses returns, per op:// reference, the last use and the number of uses in the last 30 days (events that
// released a value or used a key: granted, released, key-used, routed, ...; asked/denied/expired don't count).
func auditUses(path string, now time.Time) map[string]struct {
	Last  time.Time
	Count int
} {
	out := map[string]struct {
		Last  time.Time
		Count int
	}{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	notUse := map[string]bool{"asked": true, "denied": true, "expired": true, "error": true, "cancelled": true, "revoked": true,
		"undelivered": true, "notify-failed": true}
	for line := range auditLines(f) {
		var e struct {
			Time  string   `json:"time"`
			Event string   `json:"event"`
			By    string   `json:"by"`
			Refs  []string `json:"refs"`
		}
		if json.Unmarshal(line, &e) != nil || notUse[e.Event] {
			continue
		}
		if e.Event == "routed" && (e.By == Route1PasswordFailed || e.By == RouteOpAway) { // nothing was released
			continue
		}
		t, err := time.Parse(time.RFC3339, e.Time)
		if err != nil {
			continue
		}
		for _, r := range e.Refs {
			r = refKey(r)
			u := out[r]
			if t.After(u.Last) {
				u.Last = t
			}
			if now.Sub(t) <= 30*24*time.Hour {
				u.Count++
			}
			out[r] = u
		}
	}
	return out
}

// refKey is what audit uses and registry entries are matched on: vault and item, compared like refs.go does
// (letters and digits only, any case), so "Backup bucket S3" counts for "Backup bucket (S3)".
func refKey(r string) string {
	n := normalizeRef(r)
	if body, ok := strings.CutPrefix(n, "op://"); ok {
		v, it, _ := strings.Cut(body, "/")
		return "op://" + refName(v) + "/" + refName(it)
	}
	return n
}

// normalizeRef: op://vault/item/field and op://vault/item?document both count as item-level uses.
func normalizeRef(r string) string {
	r = strings.SplitN(r, "?", 2)[0]
	if strings.HasPrefix(r, "op://") {
		parts := strings.Split(strings.TrimPrefix(r, "op://"), "/")
		if len(parts) >= 2 {
			return "op://" + parts[0] + "/" + parts[1]
		}
	}
	return r
}

// ---------- evaluation

func evaluate(c Cred, f Finding, uses map[string]struct {
	Last  time.Time
	Count int
}, now time.Time) Report {
	r := Report{Cred: c, ID: c.ID, Tier: c.Tier, Detail: f.Detail}
	switch {
	case !f.Expires.IsZero():
		r.Expires, r.ExpiresSrc = f.Expires, "probe"
	case c.Expires != "":
		r.Expires, _ = parseDay(c.Expires)
		r.ExpiresSrc = "declared"
	case c.LifespanDays > 0:
		created, _ := parseDay(c.Created)
		r.Expires, r.ExpiresSrc = created.AddDate(0, 0, c.LifespanDays), "lifespan"
	}
	if !f.LastUsed.IsZero() {
		r.LastUsed, r.LastSrc = f.LastUsed, "probe"
	}
	if strings.HasPrefix(c.Store, "op://") {
		u := uses[refKey(c.Store)]
		r.Uses30d = u.Count
		if u.Last.After(r.LastUsed) {
			r.LastUsed, r.LastSrc = u.Last, "opgate"
		}
	}
	warn := c.WarnDays
	if warn <= 0 {
		warn = 30
	}
	switch {
	case f.Valid != nil && !*f.Valid:
		r.Status = "invalid"
	case !r.Expires.IsZero() && !now.Before(r.Expires):
		r.Status = "expired"
	case !r.Expires.IsZero() && r.Expires.Sub(now) < time.Duration(warn)*24*time.Hour:
		r.Status = "expiring"
	case f.Valid != nil || !r.Expires.IsZero():
		r.Status = "ok"
	default:
		r.Status = "unknown"
	}
	return r
}

func checkAll(ctx context.Context, reg Registry, pr *prober, auditPath string) []Report {
	now := pr.now()
	uses := auditUses(auditPath, now)
	reports := make([]Report, len(reg.Credentials))
	done := make(chan struct{}, len(reg.Credentials))
	for i, c := range reg.Credentials {
		go func() {
			var f Finding
			if c.Probe != nil {
				f = pr.run(ctx, c)
			} else {
				f.Detail = "no probe (declared data only)"
			}
			reports[i] = evaluate(c, f, uses, now)
			done <- struct{}{}
		}()
	}
	for range reg.Credentials {
		<-done
	}
	return reports
}

// ---------- outputs

// CredSnapshot is the last full run, for the service's overview page (creds-latest.json next to creds-state.json).
// No values: the same facts `opgate creds show` prints.
type CredSnapshot struct {
	Time        time.Time  `json:"time"`
	Credentials []CredView `json:"credentials"`
}

// CredView is one credential on the overview page. Title, tier, status and dates are shown to anyone who can open the
// page; the rest only after a passkey check.
type CredView struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Tier       string    `json:"tier"`
	Status     string    `json:"status"`
	Expires    time.Time `json:"expires,omitzero"`
	ExpiresSrc string    `json:"expires_source,omitempty"`
	LastUsed   time.Time `json:"last_used,omitzero"`
	LastSrc    string    `json:"last_used_source,omitempty"`
	Uses30d    int       `json:"opgate_uses_30d"`
	Detail     string    `json:"detail,omitempty"`
	Store      string    `json:"store"`
	UsedBy     []string  `json:"used_by,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	Created    string    `json:"created,omitempty"`
	Rotate     string    `json:"rotate,omitempty"`
	Revoke     string    `json:"revoke,omitempty"`
	Lifecycle  string    `json:"lifecycle,omitempty"`
}

func snapshotPath(cfg Config) string {
	return filepath.Join(filepath.Dir(cfg.Socket), "creds-latest.json")
}

// writeSnapshot replaces the snapshot in one step (the page never reads half a file).
func writeSnapshot(path string, reports []Report, now time.Time) error {
	snap := CredSnapshot{Time: now}
	for _, r := range reports {
		c := r.Cred
		snap.Credentials = append(snap.Credentials, CredView{ID: r.ID, Title: c.Title, Tier: r.Tier, Status: r.Status,
			Expires: r.Expires, ExpiresSrc: r.ExpiresSrc, LastUsed: r.LastUsed, LastSrc: r.LastSrc, Uses30d: r.Uses30d,
			Detail: r.Detail, Store: c.Store, UsedBy: c.UsedBy, Scope: c.Scope, Created: c.Created, Rotate: c.Rotate,
			Revoke: c.Revoke, Lifecycle: c.Lifecycle})
	}
	b, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readSnapshot(path string) (CredSnapshot, error) {
	var s CredSnapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func day(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02")
}

func printTable(w io.Writer, reports []Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIER\tSTATUS\tEXPIRES\tLAST USED\tDETAIL")
	for _, r := range reports {
		exp := day(r.Expires)
		if r.ExpiresSrc != "" && r.ExpiresSrc != "probe" {
			exp += " (" + r.ExpiresSrc + ")"
		}
		last := day(r.LastUsed)
		if r.LastSrc != "" {
			last += " (" + r.LastSrc + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Tier, r.Status, exp, last, r.Detail)
	}
	tw.Flush()
}

func printShow(w io.Writer, r Report) {
	c := r.Cred
	fmt.Fprintf(w, "%s: %s (tier %s)\n  status   %s, expires %s %s, last used %s %s\n  detail   %s\n  stored   %s\n  used by  %s\n",
		c.ID, c.Title, c.Tier, r.Status, day(r.Expires), r.ExpiresSrc, day(r.LastUsed), r.LastSrc, r.Detail, c.Store, strings.Join(c.UsedBy, ", "))
	for _, kv := range [][2]string{{"scope", c.Scope}, {"created", c.Created}, {"rotate", c.Rotate}, {"revoke", c.Revoke}, {"calendar", c.Lifecycle}} {
		if kv[1] != "" {
			fmt.Fprintf(w, "  %-8s %s\n", kv[0], kv[1])
		}
	}
}

func metricsText(reports []Report, now time.Time) string {
	var b strings.Builder
	for _, r := range reports {
		l := fmt.Sprintf(`{id=%q,tier=%q}`, r.ID, r.Tier)
		fmt.Fprintf(&b, "opgate_credential_status%s %d\n", l, statusCode[r.Status])
		if !r.Expires.IsZero() {
			fmt.Fprintf(&b, "opgate_credential_expiry_timestamp_seconds%s %d\n", l, r.Expires.Unix())
		}
		if !r.LastUsed.IsZero() {
			fmt.Fprintf(&b, "opgate_credential_last_used_timestamp_seconds%s %d\n", l, r.LastUsed.Unix())
		}
	}
	fmt.Fprintf(&b, "opgate_creds_last_run_timestamp_seconds %d\n", now.Unix())
	return b.String()
}

func pushMetrics(ctx context.Context, client *http.Client, vm, text string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(vm, "/")+"/api/v1/import/prometheus", strings.NewReader(text))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("VictoriaMetrics import: HTTP %d", resp.StatusCode)
	}
	return nil
}

// logChanges appends one line per credential whose status or expiry changed since the last run (state file next
// to it), so creds.jsonl is the history of the credential map, not a dump of every run.
func logChanges(logPath, statePath string, reports []Report, now time.Time) (int, error) {
	prev := map[string]string{}
	if b, err := os.ReadFile(statePath); err == nil && json.Unmarshal(b, &prev) != nil {
		prev = map[string]string{} // a broken state file counts as no previous run; it is rewritten below
	}
	cur := map[string]string{}
	var lines []string
	for _, r := range reports {
		key := r.Status + " " + day(r.Expires)
		cur[r.ID] = key
		if prev[r.ID] != key {
			line, _ := json.Marshal(map[string]any{"time": now.Format(time.RFC3339), "id": r.ID, "status": r.Status,
				"expires": day(r.Expires), "previous": prev[r.ID], "detail": r.Detail})
			lines = append(lines, string(line))
		}
	}
	for id := range prev {
		if _, ok := cur[id]; !ok {
			line, _ := json.Marshal(map[string]any{"time": now.Format(time.RFC3339), "id": id, "status": "removed", "previous": prev[id]})
			lines = append(lines, string(line))
		}
	}
	sort.Strings(lines)
	if len(lines) > 0 {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
			return 0, err
		}
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil { // the state stays as it was, so the next run logs these changes again
			return 0, err
		}
	}
	b, _ := json.MarshalIndent(cur, "", " ")
	return len(lines), os.WriteFile(statePath, b, 0o600)
}

// compareLifecycle reports calendar rows whose due date differs from the credential's expiry by more than a day,
// and rows the registry names that don't exist. lifecycle.csv: id,title,last_done,interval_days,due,... A row's due
// date is its due column, else last_done + interval_days (as the maintenance calendar computes it).
func compareLifecycle(path string, reports []Report) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	due := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cols := strings.Split(sc.Text(), ",")
		if len(cols) >= 5 && cols[0] != "id" {
			d := cols[4]
			if d == "" && cols[2] != "" && cols[3] != "" {
				var n int
				if last, err := parseDay(cols[2]); err == nil {
					if _, err := fmt.Sscan(cols[3], &n); err == nil && n > 0 {
						d = last.AddDate(0, 0, n).Format("2006-01-02")
					}
				}
			}
			due[cols[0]] = d
		}
	}
	var out []string
	for _, r := range reports {
		row := r.Cred.Lifecycle
		if row == "" || r.Expires.IsZero() {
			continue
		}
		d, ok := due[row]
		if !ok {
			out = append(out, fmt.Sprintf("%s: calendar row %s does not exist", r.ID, row))
			continue
		}
		if d == "" {
			out = append(out, fmt.Sprintf("%s: calendar row %s has no due date; expiry is %s", r.ID, row, day(r.Expires)))
			continue
		}
		t, err := parseDay(d)
		if err != nil || t.Sub(r.Expires) > 24*time.Hour || r.Expires.Sub(t) > 24*time.Hour {
			out = append(out, fmt.Sprintf("%s: calendar row %s is due %s, credential expires %s (%s)", r.ID, row, d, day(r.Expires), r.ExpiresSrc))
		}
	}
	return out, nil
}

const credsUsage = `opgate creds: the credential map (registry %s)

  opgate creds                     check every credential: status, expiry, last use
  opgate creds show ID             everything about one credential (where it is, who uses it, how to rotate it)
  opgate creds unused [DAYS]       credentials with no known use for DAYS (default 90): revoke candidates
  opgate creds validate            check the registry file only (no probes)
  flags: --json  --push VM_URL (metrics to VictoriaMetrics)  --lifecycle CSV (compare due dates)  --file REGISTRY
         --quiet (no table; for the launch agent)
Status: ok, expiring (within warn_days, default 30), expired, invalid (the probe says no), unknown (nothing to check).
Values are never printed. Changes are logged to %s.
`

func credsMain(args []string) int {
	ctx := context.Background() // a command-line run: the client timeouts bound each probe
	cfg, _ := loadConfig()
	logPath := filepath.Join(filepath.Dir(cfg.AuditLog), "creds.jsonl")
	statePath := filepath.Join(filepath.Dir(cfg.Socket), "creds-state.json")
	snapPath := snapshotPath(cfg)
	if d := os.Getenv("OPGATE_CREDS_DIR"); d != "" { // tests
		logPath, statePath = filepath.Join(d, "creds.jsonl"), filepath.Join(d, "creds-state.json")
		snapPath = filepath.Join(d, "creds-latest.json")
		cfg.AuditLog = filepath.Join(d, "audit.jsonl")
	}
	fs := flag.NewFlagSet("creds", flag.ContinueOnError)
	file := fs.String("file", defaultRegistryPath(), "registry")
	asJSON := fs.Bool("json", false, "JSON output")
	push := fs.String("push", "", "VictoriaMetrics URL for the metrics")
	lifecycle := fs.String("lifecycle", "", "lifecycle.csv to compare")
	quiet := fs.Bool("quiet", false, "no table")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, credsUsage, cmp.Or(defaultRegistryPath(), "none"), logPath) }
	// flags may come after the subcommand: split them out
	var pos, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && a != "--json" && a != "-json" && a != "--quiet" && a != "-quiet" && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, a)
		}
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "opgate creds: off, this build names no registry (OPGATE_CREDS_REGISTRY in install.env, README.md \"Configure\"); --file REGISTRY checks one")
		return 1
	}
	reg, err := loadRegistry(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opgate creds:", err)
		return 1
	}
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}
	if sub == "validate" {
		fmt.Printf("%d credentials, registry ok\n", len(reg.Credentials))
		return 0
	}
	if sub != "" && sub != "show" && sub != "unused" {
		fs.Usage()
		return 2
	}
	pr := newProber()
	if *push != "" && sub == "" {
		// a newly installed binary gets "no route to host" on the LAN for a few seconds (macOS refreshes its Local
		// Network permission), and at login the network may not be up yet: wait for the push target first
		waitReachable(ctx, *push, 90*time.Second)
	}
	if sub == "show" {
		if len(pos) != 2 {
			fs.Usage()
			return 2
		}
		var one Registry
		for _, c := range reg.Credentials {
			if c.ID == pos[1] {
				one.Credentials = append(one.Credentials, c)
			}
		}
		if len(one.Credentials) == 0 {
			fmt.Fprintln(os.Stderr, "opgate creds: no credential", pos[1])
			return 1
		}
		printShow(os.Stdout, checkAll(ctx, one, pr, cfg.AuditLog)[0])
		return 0
	}
	days := 90
	if sub == "unused" && len(pos) > 1 {
		if days, err = strconv.Atoi(pos[1]); err != nil {
			fs.Usage()
			return 2
		}
	}
	reports := checkAll(ctx, reg, pr, cfg.AuditLog)
	now := pr.now()
	if sub == "unused" {
		n := 0
		for _, r := range reports {
			if r.LastUsed.IsZero() || now.Sub(r.LastUsed) > time.Duration(days)*24*time.Hour {
				fmt.Printf("%-28s last used %s %s\n", r.ID, day(r.LastUsed), r.LastSrc)
				n++
			}
		}
		fmt.Printf("(%d of %d without a known use in %d days; \"-\" = no source records use)\n", n, len(reports), days)
		return 0
	}
	if _, err := logChanges(logPath, statePath, reports, now); err != nil {
		fmt.Fprintln(os.Stderr, "opgate creds: log:", err)
	}
	if err := writeSnapshot(snapPath, reports, now); err != nil {
		fmt.Fprintln(os.Stderr, "opgate creds: snapshot:", err)
	}
	code := 0
	if *push != "" {
		if err := pushMetrics(ctx, pr.client, *push, metricsText(reports, now)); err != nil {
			fmt.Fprintln(os.Stderr, "opgate creds: push:", err)
			code = 1
		}
	}
	if *lifecycle != "" {
		diffs, err := compareLifecycle(*lifecycle, reports)
		if err != nil {
			fmt.Fprintln(os.Stderr, "opgate creds: lifecycle:", err)
			code = 1
		}
		for _, d := range diffs {
			fmt.Println("calendar:", d)
		}
	}
	switch {
	case *asJSON:
		b, _ := json.MarshalIndent(reports, "", " ")
		fmt.Println(string(b))
	case !*quiet:
		printTable(os.Stdout, reports)
	}
	return code
}

// waitReachable waits until a TCP connection to the URL's host works (at most max). It reports whether it did.
func waitReachable(ctx context.Context, rawURL string, max time.Duration) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	host := net.JoinHostPort(u.Hostname(), port)
	deadline := time.Now().Add(max)
	d := &net.Dialer{Timeout: 3 * time.Second}
	for {
		c, err := d.DialContext(ctx, "tcp", host)
		if err == nil {
			c.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}
