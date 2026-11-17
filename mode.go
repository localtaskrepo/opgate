package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// How secrets are fetched, one switch for `opgate read/run` and the `op` wrapper (~/.local/opgate/bin/op -> opgate):
//
//	auto     someone at the Mac (unlocked, input within AwayIdle): 1Password first (Touch ID), the phone if it
//	         hasn't answered after OpTimeout; nobody at the Mac: the phone straight away (no 1Password window)
//	phone    always the phone (opgate)
//	touchid  always 1Password, as before opgate
//
// Set with `opgate mode <mode>` (file ~/.config/opgate/mode); $OPGATE_MODE overrides it for one command.
const (
	ModeAuto    = "auto"
	ModePhone   = "phone"
	ModeTouchID = "touchid"
)

func modeFile() string { return home(".config/opgate/mode") }

func currentMode() string {
	if m := os.Getenv("OPGATE_MODE"); validMode(m) {
		return m
	}
	b, _ := os.ReadFile(modeFile())
	if m := strings.TrimSpace(string(b)); validMode(m) {
		return m
	}
	return ModeAuto
}

func validMode(m string) bool { return m == ModeAuto || m == ModePhone || m == ModeTouchID }

func setMode(m string) error {
	if !validMode(m) {
		return fmt.Errorf("mode is auto, phone or touchid, not %q", m)
	}
	if err := os.MkdirAll(home(".config/opgate"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(modeFile(), []byte(m+"\n"), 0o600)
}

// realOp is the 1Password CLI itself (never the wrapper).
func realOp(cfg Config) string {
	if p := os.Getenv("OPGATE_REAL_OP"); p != "" {
		return p
	}
	return cfg.RealOp
}

// opRead reads refs with the real op CLI (1Password app integration, Touch ID). Document refs
// (op://vault/item?document) use `op document get`.
func opRead(ctx context.Context, cfg Config, refs []string) (map[string]string, error) {
	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, realOp(cfg), args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		// on timeout kill op and anything it started, and don't wait for pipes they still hold
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return "", errors.New("1Password didn't answer in time")
			}
			return "", fmt.Errorf("op: %s", strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	}
	dir := cliDirectory{run: run}
	out := map[string]string{}
	for _, ref := range refs {
		var v string
		var err error
		if base, ok := strings.CutSuffix(ref, "?document"); ok {
			v, err = opDocument(ctx, dir, base, run)
		} else {
			v, err = readWithFallback(ctx, dir, ref, func(r string) (string, error) { return run("read", "--no-newline", r) })
		}
		if err != nil {
			return nil, err
		}
		out[ref] = v
	}
	return out, nil
}

// opDocument reads a Document item with op; a name op doesn't find is looked up (refs.go) and read by ID.
func opDocument(ctx context.Context, dir cliDirectory, base string, run func(...string) (string, error)) (string, error) {
	vault, item, _ := strings.Cut(strings.TrimPrefix(base, "op://"), "/")
	v, err := run("document", "get", item, "--vault", vault)
	if err == nil || ctx.Err() != nil {
		return v, err
	}
	vaults, lerr := dir.Vaults(ctx)
	if lerr != nil {
		return "", err
	}
	vt, lerr := pick("vault", vault, "", vaults)
	if lerr != nil {
		return "", fmt.Errorf("%w (%w)", err, lerr)
	}
	items, lerr := dir.Items(ctx, vt.ID)
	if lerr != nil {
		return "", err
	}
	it, lerr := pick("item", item, " in "+vt.Title, items)
	if lerr != nil {
		return "", fmt.Errorf("%w (%w)", err, lerr)
	}
	return run("document", "get", it.ID, "--vault", vt.ID)
}

// present wraps ownerAtMac; OPGATE_PRESENCE=present|away overrides it (tests).
func present(cfg Config) (bool, string) {
	switch os.Getenv("OPGATE_PRESENCE") {
	case "present":
		return true, ""
	case "away":
		return false, "away (OPGATE_PRESENCE)"
	}
	return ownerAtMac(cfg.AwayIdle.Duration)
}

func serviceUp(cfg Config) bool {
	st, err := os.Stat(cfg.Socket)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// resolve fetches refs the way the mode says. Every route change is told on stderr, so the agent (and the log of
// its session) can see where the secret came from.
func resolve(cfg Config, refs []string, reason, cwd string) (map[string]string, error) {
	mode, up := currentMode(), serviceUp(cfg)
	// why the phone is asked: told once the broker has taken the request, not before it refuses it
	note := ""
	if mode != ModeTouchID && !up { // nobody to ask on the phone: 1Password is the only route
		fmt.Fprintln(os.Stderr, "opgate: service not running, using 1Password instead")
		mode = ModeTouchID
	}
	if mode == ModeAuto {
		if here, why := present(cfg); !here {
			note = why + "; asking the owner on the phone"
			mode = ModePhone
		}
	}
	if mode == ModeTouchID || mode == ModeAuto {
		timeout := 10 * time.Minute
		if mode == ModeAuto {
			timeout = cfg.OpTimeout.Duration
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		vals, err := opRead(ctx, cfg, refs)
		cancel()
		if err == nil {
			recordRoute(cfg, Route1Password, refs, reason)
			return vals, nil
		}
		if mode == ModeTouchID {
			recordRoute(cfg, Route1PasswordFailed, refs, reason)
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "opgate: 1Password: %v\n", err)
		note = "asking the owner on the phone instead"
	}
	res, err := request(RequestIn{Kind: KindSecrets, Refs: refs, Reason: reason, Cwd: cwd}, note)
	if err != nil {
		return nil, err
	}
	return res.Secrets, nil
}
