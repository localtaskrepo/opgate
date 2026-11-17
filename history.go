package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// HistItem is one event of the history page, built from the audit log: a request and its outcome, the reuse of a
// grant, a key use without prompt, or a use that went through 1Password itself (Touch ID, op passthrough).
type HistItem struct {
	ID      string
	Time    time.Time
	Type    string // request, reuse, key, 1password, op, view
	Title   string
	Reason  string
	Under   string // key uses and reuses: the approval that allowed them ("12:54 approval: Restart dnsmasq …")
	Runs    string // opgate run: the command that got the secrets (split off the reason)
	Routine bool   // a use of the autoloaded key or the owner's own 1Password key (hidden unless asked for)
	Agent   string
	Command string
	Folder  string
	Project string // the repository the agent worked in (lines from 0.18.2 on)
	Icon    string // its icon (/project-icon/…), "" without one
	Status  string // approved, denied, expired, cancelled, error, pending, reused, used, touchid, failed, passed
	By      string
	TTL     string
}

type auditLine struct {
	Time   time.Time `json:"time"`
	ID     string    `json:"id"`
	Event  string    `json:"event"`
	Kind   string    `json:"kind"`
	Refs   []string  `json:"refs"`
	TTL    string    `json:"ttl"`
	Reason string    `json:"reason"`
	Caller []string  `json:"caller"`
	Cwd    string    `json:"cwd"`
	Proj   string    `json:"project"`
	Root   string    `json:"root"`
	By     string    `json:"by"`
	Detail string    `json:"detail"`
}

// history reads the audit log and returns its newest limit events, newest first.
func (b *Broker) history(limit int) []HistItem {
	f, err := os.Open(b.cfg.AuditLog)
	if err != nil {
		return nil
	}
	defer f.Close()
	var items []*HistItem
	byID := map[string]*HistItem{}
	approvedBy := map[string]string{} // kind + refs -> "HH:MM approval: reason", the newest approval of that set
	icons := map[string]string{}      // one lookup per repository, not per line
	for line := range auditLines(f) {
		var l auditLine
		if json.Unmarshal(line, &l) != nil || l.ID == "" {
			continue
		}
		r := &Request{RequestIn: RequestIn{Kind: l.Kind, Refs: l.Refs, Reason: l.Reason}, Caller: l.Caller}
		if d, err := time.ParseDuration(l.TTL); err == nil {
			r.TTL = d
		}
		base := HistItem{ID: l.ID, Time: l.Time, Agent: describe(l.Caller).Agent, Folder: shortHome(l.Cwd), Project: l.Proj}
		if l.Root != "" {
			ic, ok := icons[l.Root]
			if !ok {
				ic = projectIcons.url(l.Root)
				icons[l.Root] = ic
			}
			base.Icon = ic
		}
		switch l.Event {
		case "asked", "granted":
			if l.Kind == KindEnroll {
				continue
			}
			it := base
			it.Reason, it.Runs = splitReason(l.Reason)
			it.Type, it.Status, it.Title, it.Command = "request", "pending", pageTitle(r), agentCommand(l.Caller)
			if l.Kind == KindSSH && r.TTL > 0 {
				it.TTL = human(r.TTL)
			}
			if l.Event == "granted" {
				it.Type, it.Status, it.By = "reuse", "reused", "same-again permission"
				it.Under = approvedBy[refsKey(l.Kind, l.Refs)]
			}
			items = append(items, &it)
			byID[l.ID] = &it
		case "approved", "denied", "expired", "error":
			if it := byID[l.ID]; it != nil && it.Status == "pending" {
				it.Status, it.By = l.Event, l.By
				if l.Event == "error" && strings.Contains(l.Detail, "client went away") {
					it.Status = "cancelled"
				}
				if d, ok := strings.CutPrefix(l.Detail, "loaded for "); ok && l.Kind == KindSSH {
					it.TTL = d // what the owner picked on the page
				}
				if l.Event == "approved" {
					approvedBy[refsKey(l.Kind, l.Refs)] = l.Time.Local().Format("Mon 15:04") + " approval: " + it.Reason
				}
			}
		case "key-used":
			if len(l.Refs) == 0 {
				continue
			}
			it := base
			it.Type, it.Status, it.Command = "key", "used", keyUseCommand(l.Caller)
			it.Title = capitalize(friendlyItem(l.Refs[0]))
			switch {
			case strings.HasPrefix(l.Refs[0], "1Password: "):
				it.Title, it.Status, it.Reason, it.Routine = l.Refs[0], "touchid", "approved in 1Password", true
			case l.By == KeyAutoload:
				it.Reason, it.Routine = "loaded without approval", true
			default:
				it.Under = approvedBy[refsKey(KindSSH, l.Refs)]
				switch {
				case it.Under != "":
				case l.By == KeyApproval:
					it.Reason = "approved earlier"
				default: // before 0.22.1 the line didn't say: no approval in the log means autoloaded
					it.Reason, it.Routine = "loaded without approval", true
				}
			}
			items = append(items, &it)
		case "notify-settings":
			it := base
			it.Type, it.Status, it.Title, it.Reason = "settings", "changed", "Notifications", l.Reason
			items = append(items, &it)
		case "unlocked":
			it := base
			it.Type, it.Status, it.By, it.Title = "view", "approved", l.By, "Credential details"
			it.Reason = "unlocked with the passkey " + l.Detail
			items = append(items, &it)
		case "routed":
			it := base
			it.Command = agentCommand(l.Caller)
			it.Reason, it.Runs = splitReason(l.Reason)
			switch l.By {
			case Route1Password:
				it.Type, it.Status, it.Title = "1password", "touchid", pageTitle(r)
			case Route1PasswordFailed:
				it.Type, it.Status, it.Title = "1password", "failed", pageTitle(r)
			case RouteOpAway:
				it.Type, it.Status, it.Title = "op", "failed", strings.SplitN(l.Reason, ":", 2)[0]
				it.Reason = "not run: nobody at the Mac for Touch ID (use op read, op run or op item get --fields)"
			case RouteOpPassthrough:
				it.Type, it.Status, it.Title = "op", "passed", strings.SplitN(l.Reason, ":", 2)[0]
				if len(l.Refs) > 0 {
					it.Title += " · " + pageTitle(r)
				}
			default:
				continue
			}
			if it.Title == "" {
				it.Title = "1Password"
			}
			items = append(items, &it)
		}
	}
	// limit counts what the owner looks for; routine key uses in between come along (they are hidden by default)
	var out []HistItem
	for i, n := len(items)-1, 0; i >= 0 && n < limit; i-- {
		it := *items[i]
		if !it.Routine {
			n++
		}
		if it.Status == "pending" && b.get(it.ID) == nil {
			it.Status = "expired" // pending in the log but no longer open (e.g. opgate restarted)
		}
		out = append(out, it)
	}
	return out
}

var typeLabels = map[string]string{"request": "Request", "reuse": "Reuse", "key": "Key use", "1password": "1Password", "op": "op command", "view": "Unlock", "settings": "Settings"}

// statusLabel is the pill text on the history page.
func statusLabel(it HistItem) string {
	switch it.Status {
	case "approved":
		if it.By != "" && it.By != "grant" {
			return "Approved · " + it.By
		}
		return "Approved"
	case "reused":
		return "Reused · no prompt"
	case "used":
		return "Used · no prompt"
	case "touchid":
		return "Touch ID"
	case "passed":
		return "To 1Password"
	}
	return capitalize(it.Status)
}

func typeLabel(it HistItem) string { return typeLabels[it.Type] }

// searchText is what the page's search matches against (lowercase).
func searchText(it HistItem) string {
	return strings.ToLower(strings.Join([]string{it.Title, it.Reason, it.Under, it.Runs, it.Agent, it.Command, it.Folder, it.Project, it.By,
		statusLabel(it), typeLabel(it)}, " "))
}

// refsKey names a set of references of one kind, in any order.
func refsKey(kind string, refs []string) string {
	r := slices.Clone(refs)
	slices.Sort(r)
	return kind + "|" + strings.Join(r, ",")
}

// reasonArg is an opgate --reason argument (or OPGATE_REASON=) with its value, quoted or not
var reasonArg = regexp.MustCompile(`(--reason[= ]\s*|OPGATE_REASON=)("(?:[^"\\]|\\.)*"|'[^']*'|\S+)`)

// firstLine is a command's first line for the one-line preview, with " …" when more follows. The reason is shown
// above it, so its argument becomes "…".
func firstLine(cmd string) string {
	l, rest, ok := strings.Cut(cmd, "\n")
	l = reasonArg.ReplaceAllString(l, "$1…")
	if ok && strings.TrimSpace(rest) != "" {
		return l + " …"
	}
	return l
}

// ---------- the History tab: filtered and paged on the server, so the page stays small

const histPageSize = 20

// histQuery is what the History tab asks for (the query string of /history/items).
type histQuery struct {
	Q, Type, Status string
	Asc, Routine    bool // oldest first; include routine key uses
	Page            int  // from 1
}

func parseHistQuery(v url.Values) histQuery {
	p, _ := strconv.Atoi(v.Get("page"))
	return histQuery{Q: v.Get("q"), Type: v.Get("type"), Status: v.Get("status"), Asc: v.Get("dir") == "asc",
		Routine: v.Get("routine") == "1", Page: p}
}

type histPage struct {
	Items              []HistItem
	Total, Page, Pages int
	Hidden             int    // routine key uses left out
	Label              string // "1–20 of 172 · 388 routine key uses hidden"
}

// statusGroups: outcome filters that cover several statuses
var statusGroups = map[string][]string{"noprompt": {"reused", "used"}, "failed": {"failed", "error"}}

func (q histQuery) match(it HistItem) bool {
	if q.Type != "" && it.Type != q.Type {
		return false
	}
	if q.Status != "" && it.Status != q.Status && !slices.Contains(statusGroups[q.Status], it.Status) {
		return false
	}
	text := searchText(it)
	for _, w := range strings.Fields(strings.ToLower(q.Q)) {
		if !strings.Contains(text, w) {
			return false
		}
	}
	return true
}

// historyPage searches the whole audit log. Open requests are left out (Needs attention shows them); routine key
// uses only when asked for or searched.
func (b *Broker) historyPage(q histQuery) histPage {
	var p histPage
	var all []HistItem
	for _, it := range b.history(1 << 30) {
		if it.Status == "pending" || !q.match(it) {
			continue
		}
		if it.Routine && !q.Routine && strings.TrimSpace(q.Q) == "" {
			p.Hidden++
			continue
		}
		all = append(all, it)
	}
	if q.Asc {
		slices.Reverse(all)
	}
	p.Total = len(all)
	p.Pages = max(1, (p.Total+histPageSize-1)/histPageSize)
	p.Page = min(max(q.Page, 1), p.Pages)
	from := (p.Page - 1) * histPageSize
	p.Items = all[from:min(from+histPageSize, p.Total)]
	switch {
	case p.Total == 0:
		p.Label = "No events"
	case p.Pages == 1:
		p.Label = fmt.Sprintf("%d events", p.Total)
	default:
		p.Label = fmt.Sprintf("%d–%d of %d", from+1, from+len(p.Items), p.Total)
	}
	if p.Hidden > 0 {
		p.Label += fmt.Sprintf(" · %d routine hidden", p.Hidden)
	}
	return p
}
