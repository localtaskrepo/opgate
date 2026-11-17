package main

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// summary is the one-line "what" of a request: "router key for 1 h", "Cloudflare DNS token (credential, account
// id) for cf-dns.sh", "register passkey phone".
func summary(r *Request) string {
	switch r.Kind {
	case KindSSH:
		return fmt.Sprintf("%s for %s", friendlyItem(firstRef(r)), human(r.TTL))
	case KindEnroll:
		return "register passkey " + r.Name
	case KindRestore:
		return "load " + friendlyItem(firstRef(r)) + " again"
	case KindHandover:
		return "hand opgate's keychain store to the new build " + r.Name[:min(8, len(r.Name))]
	}
	var parts []string
	for _, g := range groupRefs(r.Refs, false) {
		parts = append(parts, g.Item+" ("+g.Field+")")
	}
	s := strings.Join(parts, ", ")
	if sc := askerOf(r).Script; sc != "" {
		s += " for " + sc
	}
	return s
}

// groupRefs is one row per item with its fields joined ("Cloudflare DNS token" · "credential, account id");
// withVault names the vault of items outside the agents' vault.
func groupRefs(refs []string, withVault bool) []refView {
	var out []refView
	idx := map[string]int{}
	for _, ref := range refs {
		p := strings.SplitN(strings.TrimPrefix(ref, "op://"), "/", 3)
		item, field := friendlyItem(ref), ""
		if len(p) == 3 {
			field = p[2]
		}
		if strings.HasSuffix(ref, "?document") {
			item, field = strings.TrimSuffix(item, "?document"), "document"
		}
		if withVault && len(p) > 0 && p[0] != vault() {
			item = p[0] + " / " + item
		}
		if i, ok := idx[item]; ok {
			out[i].Field += ", " + field
			continue
		}
		idx[item] = len(out)
		out = append(out, refView{Item: item, Field: field})
	}
	return out
}

func human(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%d h", d/time.Hour)
	}
	return fmt.Sprintf("%d min", d/time.Minute)
}

// headline is a request's "what" in its notification: "Router key for 1 h", "Cloudflare DNS token" (agent and
// script are on the line below, the fields on the page).
func headline(r *Request) string {
	if r.Kind == KindSecrets {
		return pageTitle(r)
	}
	return capitalize(summary(r))
}

// withProject puts the project first, where a glance at the notification finds it: "webapp · Router key for 1 h".
func withProject(project, s string) string {
	if project == "" {
		return s
	}
	return project + " · " + s
}

// who is "Claude Code (VS Code)" or "Claude Code · cf-dns.sh", with the folder when no project is known.
func who(r *Request) string {
	a := askerOf(r)
	parts := []string{}
	if a.Agent != "" {
		parts = append(parts, a.Agent)
	}
	if a.Script != "" {
		parts = append(parts, a.Script)
	}
	if len(parts) == 0 {
		parts = append(parts, "unknown process")
	}
	if a.Project == "" && r.Cwd != "" {
		parts = append(parts, shortHome(r.Cwd))
	}
	return strings.Join(parts, " · ")
}

// useTitle: "Router key used (3×)", "Agent key used (14× today)", "Cloudflare DNS token used again (2×)".
func useTitle(a Activity) string {
	switch a.Kind {
	case "daily":
		return fmt.Sprintf("%s used (%d× today)", a.Title, a.Count)
	case "grant":
		return fmt.Sprintf("%s used again (%d×)", a.Title, a.Count)
	}
	return fmt.Sprintf("%s used (%d×)", a.Title, a.Count)
}

// useProjects names the projects of an activity's uses, newest first: "homelab", or "webapp +2" when the agent
// key signed in three repositories today.
func useProjects(a Activity) string {
	var seen []string
	for _, u := range a.Uses {
		if u.Project != "" && !slices.Contains(seen, u.Project) {
			seen = append(seen, u.Project)
		}
	}
	switch len(seen) {
	case 0:
		return ""
	case 1:
		return seen[0]
	}
	return fmt.Sprintf("%s +%d", seen[0], len(seen)-1)
}

// useContext is the second line: agent, the folder when no project is known, and how long the permission runs.
func useContext(a Activity) string {
	var parts []string
	if len(a.Uses) > 0 {
		u := a.Uses[0]
		if u.Agent != "" {
			parts = append(parts, u.Agent)
		}
		if u.Folder != "" && u.Project == "" {
			parts = append(parts, shortHome(u.Folder))
		}
	}
	if !a.Until.IsZero() {
		parts = append(parts, "until "+a.Until.Local().Format("15:04"))
	}
	return strings.Join(parts, " · ")
}

// useRoot is the repository of the newest use that has one (its icon goes on the notification).
func useRoot(a Activity) string {
	for _, u := range a.Uses {
		if u.Root != "" {
			return u.Root
		}
	}
	return ""
}
