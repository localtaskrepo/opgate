package main

// Notifications are plain text (no colours, no monospace), so they get what the pages' fmtCmd (app.js) gives
// commands as far as text can: one step per line, short paths, the reason (already in the notification) elided and
// ssh's connection options left out. Display only: the pages and the audit log keep the whole command.

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	// Claude Code's per-session scratch folders: /private/tmp/claude-501/-Users-…-webapp/<uuid>/
	claudeTmp = regexp.MustCompile(`/(?:private/)?tmp/claude-\d+/[^/\s'"]+/[0-9a-f-]{36}/`)
	usersDir  = regexp.MustCompile(`/Users/[^/\s'"]+(/|$|["'\s])`)
	// ssh options that only say how to connect
	sshNoise = regexp.MustCompile(`\s+-o\s*(?:BatchMode|ConnectTimeout|ConnectionAttempts|ControlMaster|ControlPath|ControlPersist|ServerAlive\w*|LogLevel)=\S+`)
)

// shortPaths writes Claude Code's scratch folders as "…/" and home folders as "~", like the pages.
func shortPaths(s string) string {
	return usersDir.ReplaceAllString(claudeTmp.ReplaceAllString(s, "…/"), "~$1")
}

type cmdStep struct{ op, text string } // op: "", "&&", "||" or "|" (";" and newlines just start a step)

// cmdSteps splits a shell command at &&, ||, ;, | and newlines outside quotes and $( … ).
func cmdSteps(cmd string) []cmdStep {
	var out []cmdStep
	var b strings.Builder
	op := ""
	next := func(nop string) {
		if s := strings.TrimSpace(b.String()); s != "" {
			out = append(out, cmdStep{op, s})
		}
		b.Reset()
		op = nop
	}
	rs := []rune(cmd)
	q, depth := rune(0), 0
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		peek := rune(0)
		if i+1 < len(rs) {
			peek = rs[i+1]
		}
		switch {
		case q != 0:
			if c == '\\' && q == '"' && peek != 0 {
				b.WriteRune(c)
				i++
				c = rs[i]
			} else if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == '\\' && peek != 0:
			b.WriteRune(c)
			i++
			c = rs[i]
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case depth > 0:
		case c == '\n' || c == ';':
			next("")
			continue
		case c == '&' && peek == '&', c == '|' && peek == '|':
			next(string([]rune{c, c}))
			i++
			continue
		case c == '|':
			next("|")
			continue
		}
		b.WriteRune(c)
	}
	next("")
	return out
}

// pushCmd is a command for a notification: at most maxLines lines, each a step.
func pushCmd(cmd string, maxLines int) string {
	cmd = reasonArg.ReplaceAllString(shortPaths(cmd), "$1…")
	var lines []string
	for _, s := range cmdSteps(cmd) {
		t := s.text
		if l, _, ok := strings.Cut(t, "\n"); ok { // a quoted text over several lines (a commit message)
			t = l + " …"
		}
		if prog, rest, _ := strings.Cut(t, " "); strings.HasPrefix(prog, "/") {
			t = strings.TrimSpace(path.Base(prog) + " " + rest)
		}
		if p, _, _ := strings.Cut(t, " "); p == "ssh" || p == "scp" {
			t = sshNoise.ReplaceAllString(t, "")
		}
		if s.op != "" {
			t = s.op + " " + t
		}
		lines = append(lines, short(t, 110))
	}
	if len(lines) > maxLines {
		lines = append(lines[:maxLines-1], fmt.Sprintf("… %d more steps", len(lines)-maxLines+1))
	}
	return strings.Join(lines, "\n")
}
