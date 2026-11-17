package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Asker is the human-readable version of a request's process chain: which agent app asked, the command it ran and
// the script (if any) that called opgate.
type Asker struct {
	Agent   string // "Claude Code (VS Code)", "Codex", "Terminal", or ""
	Command string // the command the agent ran, unwrapped from the agent's shell wrapper
	Script  string // base name of the script that called opgate, e.g. "cf-dns.sh"
	Project string // the repository the agent works in, "webapp"; "homelab → webapp" when the asking process is in another
	Root    string // that repository's folder (its lotar icon)
}

// unwrapShell returns the command inside an agent's shell wrapper: Claude Code runs
// `bash -c source <snapshot> && ... && eval '<command>' < /dev/null && pwd -P >| ...`.
func unwrapShell(cmd string) string {
	i := strings.Index(cmd, "eval '")
	if i < 0 {
		return cmd
	}
	rest := cmd[i+len("eval '"):]
	var b strings.Builder
	for j := 0; j < len(rest); j++ {
		// a quote inside the command: bash writes it as '\'' , Claude Code as '"'"'
		if strings.HasPrefix(rest[j:], `'\''`) {
			b.WriteByte('\'')
			j += 3
			continue
		}
		if strings.HasPrefix(rest[j:], `'"'"'`) {
			b.WriteByte('\'')
			j += 4
			continue
		}
		if rest[j] == '\'' {
			break
		}
		b.WriteByte(rest[j])
	}
	return strings.TrimSpace(b.String())
}

// describe reads a chain known only by command lines (audit log, tests); live requests use identify() with the
// kernel's facts (Request.Asker).
func describe(chain []string) Asker {
	a, _ := identify(procsFromArgs(chain))
	return a
}

// askerOf is who asked: the kernel-checked Asker of a live request, else what the command lines say.
func askerOf(r *Request) Asker {
	if r.Asker != (Asker{}) {
		return r.Asker
	}
	return describe(r.Caller)
}

// short cuts s to n characters on a word boundary.
func short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := n
	for i := n; i > n/2; i-- {
		if r[i] == ' ' {
			cut = i
			break
		}
	}
	return string(r[:cut]) + " …"
}

// friendlyItem is the item title of a reference without the "opgate " prefix: "router key".
func friendlyItem(ref string) string {
	p := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(p) < 2 {
		return ref
	}
	return strings.TrimSuffix(strings.TrimPrefix(p[1], "opgate "), "?document")
}

func capitalize(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// firstRef is the request's first reference ("" for a malformed audit line without one).
func firstRef(r *Request) string {
	if len(r.Refs) == 0 {
		return ""
	}
	return r.Refs[0]
}

// pageTitle is the short headline of the page: "Router key for 1 h", "Cloudflare DNS token" (fields, script and
// agent are shown next to it).
func pageTitle(r *Request) string {
	if r.Kind == KindSSH {
		return capitalize(friendlyItem(firstRef(r))) // the duration is on the switch, where the owner can change it
	}
	if r.Kind == KindRestore {
		return "Load " + friendlyItem(firstRef(r)) + " again"
	}
	if r.Kind != KindSecrets {
		return capitalize(summary(r))
	}
	var items []string
	for _, ref := range r.Refs {
		if it := friendlyItem(ref); !slices.Contains(items, it) {
			items = append(items, it)
		}
	}
	return capitalize(strings.Join(items, " + "))
}

// shortHome writes the home folder as ~.
func shortHome(p string) string {
	if h, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, h) {
		return "~" + p[len(h):]
	}
	return p
}

// runsSuffix is what `opgate run` adds to the agent's reason: " (runs: <command>)".
var runsSuffix = regexp.MustCompile(`\s*\(runs: (.*)\)\s*$`)

// splitReason separates the agent's own words from the command `opgate run` appended to them, so the pages show the
// reason once and the command where commands go. Paths in the reason are shortened like in commands.
func splitReason(reason string) (why, runs string) {
	m := runsSuffix.FindStringSubmatchIndex(reason)
	if m == nil {
		return shortPaths(reason), ""
	}
	return shortPaths(strings.TrimSpace(reason[:m[0]])), reason[m[2]:m[3]]
}

// reasonOnly is the agent's reason without the appended command.
func reasonOnly(reason string) string {
	why, _ := splitReason(reason)
	return why
}
