package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// Routes recorded by clients (opgate read/run, the op wrapper) for what doesn't go through an opgate approval, so
// the history shows every use: 1Password's own Touch ID route and op commands passed through to 1Password's op.
const (
	Route1Password       = "1password"        // values came from 1Password (the owner approved with Touch ID)
	Route1PasswordFailed = "1password-failed" // 1Password refused or didn't answer (mode touchid)
	RouteOpPassthrough   = "op"               // any other op command, handed to 1Password's op unchanged
	RouteOpAway          = "op-away"          // an op command not run: it needs Touch ID and nobody is at the Mac
)

var (
	refPattern = regexp.MustCompile(`op://[^\s"'` + "`" + `]+`)
	opWord     = regexp.MustCompile(`^[a-z][a-z-]*$`)
)

// recordRoute tells the service (best effort, never blocks for long) so it lands in the audit log with the asking
// process chain from the kernel. Without a running service nothing is recorded.
func recordRoute(cfg Config, route string, refs []string, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", cfg.Socket)
	if err != nil {
		return
	}
	defer c.Close()
	if c.SetDeadline(time.Now().Add(time.Second)) != nil {
		return
	}
	cwd, _ := os.Getwd()
	b, _ := json.Marshal(RequestIn{Kind: "record", Route: route, Refs: refs, Reason: reason, Cwd: cwd})
	if _, err := c.Write(append(b, '\n')); err != nil {
		return
	}
	buf := make([]byte, 64)
	_, _ = c.Read(buf) // wait for the service to have written it; its answer, a hang-up or the deadline ends the wait
}

// opSummary names a passed-through op command without its arguments (they can hold secrets, e.g. field=value in
// `op item create`): the leading subcommand words, plus any op:// references.
func opSummary(args []string) (string, []string) {
	words := []string{"op"}
	for _, a := range args {
		if len(words) == 3 || !opWord.MatchString(a) {
			break
		}
		words = append(words, a)
	}
	if len(words) == 1 && len(args) > 0 && (args[0] == "--version" || args[0] == "--help" || args[0] == "-h") {
		words = append(words, args[0])
	}
	var refs []string
	for _, a := range args {
		refs = append(refs, refPattern.FindAllString(a, -1)...)
	}
	if len(refs) > 8 {
		refs = refs[:8]
	}
	return strings.Join(words, " "), refs
}
