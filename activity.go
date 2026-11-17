package main

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Activity is what happens after an approval: the uses of a 30-min grant, of an approved ssh key (per load) or of
// an autoloaded key (per day). Each has a page (/u/<tag>) with every use and the full command, and can be revoked
// there or from its notification (the grant is cancelled, the key unloaded; "stop" also ends ssh sessions that used
// the key and still run). Revoking only takes access away, so it needs no passkey.
type Activity struct {
	Tag      string
	Kind     string // "grant", "key", "daily"
	Title    string // "Router key", "Cloudflare DNS token"
	Ref      string
	GrantKey string // kind grant
	KeyFP    string // kinds key, daily
	Until    time.Time
	Count    int
	Revoked  bool
	Created  time.Time
	Uses     []Use // newest first, at most maxUses
}

// Use is one use: when, by whom, and the command the agent ran.
type Use struct {
	Time    time.Time
	Agent   string
	Command string // what used it (key uses: the ssh or git command; grants: the agent's command)
	Context string // the agent's whole command, when it differs from Command
	Folder  string
	Project string // Asker.Project
	Root    string // Asker.Root
	Icon    string // the project's icon, set for the page
	Chain   []string
	PID     int   // the process that used the key (ssh, ssh-keygen); 0 if not known
	Start   int64 // its start time: Stop only signals the PID while it is still that process
}

const maxUses = 30

var cdPrefix = regexp.MustCompile(`^(?:cd\s+(?:"[^"]*"|'[^']*'|\S+)\s*&&\s*)+`)

// agentCommand is the command worth showing: the agent's command unwrapped from its shell wrapper, without
// leading `cd <dir> &&` steps; the asking process itself when there is no agent command.
func agentCommand(chain []string) string {
	a := describe(chain)
	cmd := strings.TrimSpace(cdPrefix.ReplaceAllString(strings.TrimSpace(a.Command), ""))
	if cmd == "" && len(chain) > 0 {
		cmd = chain[0]
	}
	return tidyLines(cmd)
}

// tidyLines keeps a command's own lines (a script sent over ssh, a multi-line commit message) but drops blank ones
// and trailing spaces; older audit lines still have ps's \012 for a newline.
func tidyLines(cmd string) string {
	var out []string
	for _, l := range strings.Split(psUnescape(cmd), "\n") {
		if l = strings.TrimRight(l, " \t\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// keyUseCommand is the process that used an ssh key, as a person would name it: `ssh router uptime`, or for git
// (signing via ssh-keygen, pushes via ssh to GitHub) the git command above it. Paths of programs are shortened.
func keyUseCommand(chain []string) string {
	helper := func(c string) bool {
		f := strings.Fields(c)
		if len(f) == 0 {
			return true
		}
		base := path.Base(f[0])
		switch {
		case base == "ssh-keygen", strings.Contains(c, "opgate-ssh-sign"):
			return true
		case base == "ssh" && (strings.Contains(c, "git-receive-pack") || strings.Contains(c, "git-upload-pack")):
			return true // the git command above says more
		case (base == "sh" || base == "bash" || base == "zsh") && (strings.Contains(c, "shell-snapshots") || len(f) == 1):
			return true
		}
		return false
	}
	for _, c := range chain {
		if !helper(c) {
			c = tidyLines(c)
			prog, rest, _ := strings.Cut(c, " ")
			if rest == "" {
				return path.Base(prog)
			}
			return path.Base(prog) + " " + strings.TrimLeft(rest, " ")
		}
	}
	return agentCommand(chain)
}

// recordUse adds a use to the activity for key (one per grant, per key load, per day of an autoloaded key; a new
// grant or load is a new activity, so a revoked one never hides the next) and returns a copy for notifying. Each
// activity gets a random tag: it names its page and notifications and can't be guessed.
func (b *Broker) recordUse(key string, seed Activity, u Use) Activity {
	defer b.changes.publish() // runs after the unlock below
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.activityLocked(key, seed)
	a.Count++
	a.Uses = append([]Use{u}, a.Uses...)
	if len(a.Uses) > maxUses {
		a.Uses = a.Uses[:maxUses]
	}
	c := *a
	c.Uses = slices.Clone(a.Uses)
	return c
}

// activityLocked returns the activity for key, creating it from seed (b.mu held). Activities nobody has used (or,
// without uses, that were created) for a day are forgotten.
func (b *Broker) activityLocked(key string, seed Activity) *Activity {
	if b.activity == nil {
		b.activity, b.activityTags = map[string]*Activity{}, map[string]string{}
	}
	for k, old := range b.activity {
		last := old.Created
		if len(old.Uses) > 0 {
			last = old.Uses[0].Time
		}
		if b.now().Sub(last) > 24*time.Hour {
			delete(b.activity, k)
			delete(b.activityTags, old.Tag)
		}
	}
	a := b.activity[key]
	if a == nil {
		a = &seed
		a.Tag, a.Created = randomID(12), b.now()
		b.activity[key] = a
		b.activityTags[a.Tag] = key
	}
	return a
}

// ensureActivity returns the activity for key (created without a use if needed), so the overview can link a grant
// or a loaded key to its page with Revoke before anything used it.
func (b *Broker) ensureActivity(key string, seed Activity) Activity {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := *b.activityLocked(key, seed)
	c.Uses = slices.Clone(c.Uses)
	return c
}

func (b *Broker) getActivity(tag string) (Activity, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.activity[b.activityTags[tag]]
	if a == nil {
		return Activity{}, false
	}
	c := *a
	c.Uses = slices.Clone(a.Uses)
	return c, true
}

func (b *Broker) activityURL(tag string) string { return b.cfg.PublicURL + "/u/" + tag }

// Revoke ends what the activity allows; stop also ends running ssh sessions that used the key.
func (b *Broker) Revoke(tag string, stop bool) (Activity, int, error) {
	b.mu.Lock()
	a := b.activity[b.activityTags[tag]]
	if a == nil {
		b.mu.Unlock()
		return Activity{}, 0, errors.New("unknown or expired activity")
	}
	a.Revoked = true
	if a.Kind == "daily" { // an autoloaded key stays unloaded until the owner restores it with a passkey
		b.revokedRefs[a.Ref] = true
	}
	if g := b.grants[a.GrantKey]; a.Kind == "grant" && g != nil && g.Until.Equal(a.Until) { // not a newer grant
		delete(b.grants, a.GrantKey)
	}
	c := *a
	c.Uses = slices.Clone(a.Uses)
	b.mu.Unlock()
	defer b.changes.publish()
	if c.Kind != "grant" && c.KeyFP != "" {
		// an approved key only if it is still this load (a newer approval has another end time)
		if k, ok := b.keys.loadedFP(c.KeyFP); ok && (c.Kind == "daily" || k.Until.Equal(c.Until)) {
			b.keys.Remove(c.KeyFP)
		}
	}
	stopped := 0
	if stop && c.Kind == "key" { // only sessions of an approved key; and only processes that are still the same
		seen := map[int]bool{}
		for _, u := range c.Uses {
			if u.PID > 1 && !seen[u.PID] && procAlive(u.PID, u.Start) {
				seen[u.PID] = true
				if syscall.Kill(u.PID, syscall.SIGTERM) == nil {
					stopped++
				}
			}
		}
	}
	r := &Request{RequestIn: RequestIn{Kind: KindSecrets, Refs: []string{c.Ref}, Reason: "revoked on the phone"}, ID: tag}
	b.audit.Log(r, "revoked", "page", fmt.Sprintf("%s, stopped %d processes", c.Kind, stopped))
	if err := b.notify.Revoked(c); err != nil {
		b.audit.Log(r, "notify-failed", "", err.Error())
	}
	return c, stopped, nil
}
