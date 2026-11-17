package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// agentLabel names the agent app an executable belongs to, or "".
func agentLabel(exe string) string {
	low := strings.ToLower(exe)
	base := path.Base(low)
	switch {
	case strings.Contains(low, "/native-binary/claude") || base == "claude":
		return "Claude Code"
	case base == "codex" || strings.Contains(low, "/codex/") && !strings.Contains(low, "cryptexd"):
		return "Codex"
	case base == "kilo" || base == "kilocode":
		return "Kilo"
	}
	return ""
}

// procLabel is agentLabel of a process: its executable, or the kernel's process name once that was deleted.
func procLabel(p proc) string {
	if p.Exe == "" {
		return agentLabel(p.Name)
	}
	return agentLabel(p.Exe)
}

func inVSCode(exe string) bool {
	return strings.Contains(exe, "Visual Studio Code.app") || strings.Contains(exe, "/.vscode/")
}

var interpreters = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"python": true, "python3": true, "node": true, "perl": true, "ruby": true, "osascript": true}

func isInterpreter(exe string) bool {
	b := path.Base(exe)
	return interpreters[b] || strings.HasPrefix(b, "python3.")
}

// scriptArg is the script an interpreter runs ("" for `-c '...'`, `-lc '...'` and interactive shells) and its
// subcommand: the script's first argument when it isn't a flag ("up" in `node pulumi.ts up --yes`); after a leading
// flag that word could be the flag's value (`--stack prod up`), so then all the arguments.
func scriptArg(args string) (script, sub string) {
	f := strings.Fields(args)
	for i, w := range f[min(1, len(f)):] {
		if w == "-c" || w == "-e" || w == "-m" {
			return "", ""
		}
		if len(w) > 2 && w[0] == '-' && w[1] != '-' && strings.ContainsRune(w[1:], 'c') { // -lc, -xc: inline code
			return "", ""
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		rest := f[i+2:]
		if len(rest) == 0 || !strings.HasPrefix(rest[0], "-") {
			return w, strings.Join(rest[:min(1, len(rest))], "")
		}
		return w, "\x00" + strings.Join(rest, " ")
	}
	return "", ""
}

// identify turns a kernel-checked process chain (procs[0] is the asking process itself) into what the owner is
// shown and into the identity a "same again" grant is tied to. Only the executable paths, working directories and
// start times come from the kernel; command lines are what the processes say about themselves, so they are shown,
// hashed in full, but never trusted to name the agent or the script.
func identify(ps []proc) (Asker, string) {
	var a Asker
	agentIdx := -1
	for i := 1; i < len(ps); i++ {
		if l := procLabel(ps[i]); l != "" {
			a.Agent, agentIdx = l, i
			break
		}
	}
	if agentIdx > 0 {
		for _, p := range ps[agentIdx:] {
			if inVSCode(p.Exe) {
				a.Agent += " (VS Code)"
				break
			}
		}
	} else {
		for _, p := range ps {
			if strings.Contains(p.Exe, "Warp.app") || strings.Contains(p.Exe, "Terminal.app") || strings.Contains(p.Exe, "iTerm.app") {
				a.Agent = "Terminal"
				break
			}
		}
	}
	a.Project, a.Root = projectLabel(ps, agentIdx)
	// the command: what the agent ran (the process right below the agent), unwrapped from its shell wrapper
	switch {
	case agentIdx >= 2:
		p := ps[agentIdx-1]
		a.Command = p.Args
		if isInterpreter(p.Exe) && strings.Contains(p.Args, "shell-snapshots") {
			a.Command = unwrapShell(p.Args)
		}
	case len(ps) > 1 && interactiveShell(ps[1]):
		a.Command = ps[0].Args // typed in a terminal: what ran is the asking process itself
	case len(ps) > 1:
		a.Command = ps[1].Args
	case len(ps) == 1:
		a.Command = ps[0].Args
	}
	// the script that called opgate: the nearest interpreter between opgate and the agent running a real file
	end := len(ps)
	if agentIdx > 0 {
		end = agentIdx
	}
	scriptID := ""
	for i := 1; i < end && scriptID == ""; i++ {
		p := ps[i]
		if !isInterpreter(p.Exe) {
			continue
		}
		s, sub := scriptArg(p.Args)
		if s == "" {
			continue
		}
		if !filepath.IsAbs(s) {
			s = filepath.Join(p.Cwd, s)
		}
		body, err := os.ReadFile(s)
		if err != nil {
			if a.Script == "" {
				a.Script = path.Base(s) // shown, but not trusted: the grant falls back to the full command
			}
			continue
		}
		h := sha256.Sum256(body)
		a.Script = path.Base(s)
		scriptID = "script:" + s + "#" + hex.EncodeToString(h[:8]) + "|sub:" + sub
	}
	// identity of a grant: the script file (path and content) and its subcommand or the full command, the folder,
	// and the agent session
	id := scriptID
	if id == "" && len(ps) > 1 {
		h := sha256.Sum256([]byte(ps[1].Args))
		id = "cmd:" + hex.EncodeToString(h[:12])
	}
	if len(ps) > 1 {
		id += "|cwd:" + ps[1].Cwd
	}
	if agentIdx > 0 {
		id += "|agent:" + strconv.Itoa(ps[agentIdx].PID) + "@" + strconv.FormatInt(ps[agentIdx].Start, 10)
	} else if len(ps) > 0 {
		top := ps[len(ps)-1]
		id += "|session:" + strconv.Itoa(top.PID) + "@" + strconv.FormatInt(top.Start, 10)
	}
	return a, id
}

// interactiveShell: a login or interactive shell (`-zsh`, `/bin/zsh` without a script).
func interactiveShell(p proc) bool {
	f := strings.Fields(p.Args)
	if len(f) == 0 {
		return false
	}
	script, _ := scriptArg(p.Args)
	return strings.HasPrefix(f[0], "-") || isInterpreter(p.Exe) && script == "" && !strings.Contains(p.Args, " -c ")
}

// procsFromArgs is a chain known only by its command lines (the audit log, tests): the first word stands in for the
// executable. Good enough for showing history, never used for grants.
func procsFromArgs(chain []string) []proc {
	ps := make([]proc, len(chain))
	for i, c := range chain {
		exe := ""
		if f := strings.Fields(c); len(f) > 0 {
			exe = f[0]
		}
		ps[i] = proc{Exe: exe, Args: c}
	}
	return ps
}

// projectLabel names the repository the agent works in (its own folder; without an agent the shell's), with the
// repository of the asking process when that is another one: "homelab → acme-shop".
func projectLabel(ps []proc, agentIdx int) (string, string) {
	var session project
	switch {
	case agentIdx > 0:
		session = projectOf(ps[agentIdx].Cwd)
	case len(ps) > 1:
		session = projectOf(ps[1].Cwd)
	}
	var here project
	if len(ps) > 0 {
		here = projectOf(ps[0].Cwd)
	}
	switch {
	case session.Name == "":
		return here.Name, here.Root
	case here.Name != "" && here.Root != session.Root:
		return session.Name + " → " + here.Name, session.Root
	}
	return session.Name, session.Root
}
