package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// opShim runs when this binary is called as "op" (~/.local/opgate/bin/op, ahead of Homebrew's op on PATH). `op read`,
// `op run`, `op document get` and `op item get <item> --vault <v> --fields <labels> --reveal` go through resolve()
// (mode auto/phone/touchid); everything else, and any flag it doesn't know, goes to the real op unchanged. In modes
// auto and phone, a command handed to op while nobody is at the Mac fails at once with a hint: op would wait for a
// Touch ID nobody gives (OPGATE_WAIT_FOR_TOUCHID=1 waits anyway).
func opShim(cfg Config, args []string) int {
	real := realOp(cfg)
	if self, err := os.Executable(); err == nil {
		if a, b := evalPath(self), evalPath(real); a == b {
			fmt.Fprintln(os.Stderr, "op (opgate): real_op points at the wrapper itself")
			return 1
		}
	}
	passthrough := func() int {
		what, refs := opSummary(args)
		reason := strings.TrimSpace(os.Getenv("OPGATE_REASON"))
		if reason == "" {
			reason = what
		} else {
			reason = what + ": " + reason
		}
		if why, away := awayForTouchID(cfg, args); away {
			recordRoute(cfg, RouteOpAway, refs, reason)
			fmt.Fprintf(os.Stderr, awayHint, why, what)
			return 1
		}
		recordRoute(cfg, RouteOpPassthrough, refs, reason)
		err := syscall.Exec(real, append([]string{"op"}, args...), os.Environ())
		fmt.Fprintln(os.Stderr, "op (opgate):", err)
		return 1
	}
	if currentMode() == ModeTouchID || len(args) == 0 {
		return passthrough()
	}
	var err error
	switch {
	case args[0] == "read":
		var p *readArgs
		if p, err = parseRead(args[1:]); errors.Is(err, errUnsupported) {
			return passthrough()
		} else if err == nil {
			err = shimRead(cfg, p)
		}
	case args[0] == "document" && len(args) > 1 && args[1] == "get":
		var p *readArgs
		if p, err = parseDocument(args[2:]); errors.Is(err, errUnsupported) {
			return passthrough()
		} else if err == nil {
			err = shimRead(cfg, p)
		}
	case args[0] == "item" && len(args) > 1 && args[1] == "get":
		var p *itemGetArgs
		if p, err = parseItemGet(args[2:]); errors.Is(err, errUnsupported) {
			return passthrough()
		} else if err == nil {
			err = shimItemGet(cfg, p)
		}
	case args[0] == "run":
		var p *runArgs
		if p, err = parseRun(args[1:]); errors.Is(err, errUnsupported) {
			return passthrough()
		} else if err == nil {
			err = shimRun(cfg, p)
		}
	default:
		return passthrough()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "op (opgate):", err)
		return 1
	}
	return 0
}

func evalPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

var errUnsupported = errors.New("unsupported flag")

const awayHint = `op (opgate): nobody is at the Mac (%s), so 1Password can't ask for Touch ID, and %q isn't routed
through opgate. For secrets use one of these (they go to the owner's phone):
  op read "op://<vault>/<item>/<field>"
  op run --env-file=<file with VAR=op://...> -- <command>      (several secrets, one approval)
  op item get "<item>" --vault <vault> --fields label=<a>,label=<b> --reveal
To wait for Touch ID anyway: OPGATE_WAIT_FOR_TOUCHID=1
`

// awayForTouchID: in modes auto and phone, an op command that needs the account (anything but version, help and
// completion) would wait for Touch ID while nobody is at the Mac.
func awayForTouchID(cfg Config, args []string) (string, bool) {
	if currentMode() == ModeTouchID || os.Getenv("OPGATE_WAIT_FOR_TOUCHID") == "1" || len(args) == 0 {
		return "", false
	}
	switch args[0] {
	case "--version", "-v", "--help", "-h", "help", "completion":
		return "", false
	}
	here, why := present(cfg)
	return why, !here
}

// itemGetArgs: `op item get <item> --vault <vault> --fields label=a,label=b --reveal` (the same as reading those
// fields; printed comma-separated on one line like op does).
type itemGetArgs struct {
	Item, Vault string
	Fields      []string
}

func parseItemGet(args []string) (*itemGetArgs, error) {
	p := &itemGetArgs{}
	reveal := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(args, &i, "--vault"); ok {
			p.Vault = v
			continue
		}
		if v, ok := flagValue(args, &i, "--fields"); ok {
			for _, f := range strings.Split(v, ",") {
				f = strings.TrimSpace(f)
				if l, ok := strings.CutPrefix(f, "label="); ok {
					f = l
				} else if strings.Contains(f, "=") { // type=, id= ...: op's own selectors
					return nil, errUnsupported
				}
				if f == "" {
					return nil, errUnsupported
				}
				p.Fields = append(p.Fields, f)
			}
			continue
		}
		if a == "--reveal" {
			reveal = true
			continue
		}
		if _, ok := flagValue(args, &i, "--account"); ok {
			continue
		}
		if strings.HasPrefix(a, "-") || p.Item != "" {
			return nil, errUnsupported // --format, --otp, --include-archive ...: op's
		}
		p.Item = a
	}
	// without --vault op searches every vault, without --reveal it hides concealed values: leave those to op
	if p.Item == "" || p.Vault == "" || !reveal || len(p.Fields) == 0 || len(p.Fields) > 8 {
		return nil, errUnsupported
	}
	for _, s := range append([]string{p.Item, p.Vault}, p.Fields...) {
		if strings.ContainsAny(s, "/?") { // not expressible as a reference
			return nil, errUnsupported
		}
	}
	return p, nil
}

func shimItemGet(cfg Config, p *itemGetArgs) error {
	var refs []string
	for _, f := range p.Fields {
		if r := "op://" + p.Vault + "/" + p.Item + "/" + f; !slices.Contains(refs, r) {
			refs = append(refs, r)
		}
	}
	reason, err := shimReason()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	vals, err := resolve(cfg, refs, reason, cwd)
	if err != nil {
		return err
	}
	out := make([]string, len(p.Fields))
	for i, f := range p.Fields {
		out[i] = vals["op://"+p.Vault+"/"+p.Item+"/"+f]
	}
	_, err = os.Stdout.WriteString(strings.Join(out, ",") + "\n")
	return err
}

// readArgs covers `op read` and `op document get`.
type readArgs struct {
	Ref       string
	NoNewline bool
	OutFile   string
	Force     bool
	FileMode  os.FileMode
}

// flagValue handles "--flag value" and "--flag=value".
func flagValue(args []string, i *int, name string) (string, bool) {
	a := args[*i]
	if v, ok := strings.CutPrefix(a, name+"="); ok {
		return v, true
	}
	if a == name && *i+1 < len(args) {
		*i++
		return args[*i], true
	}
	return "", false
}

func parseFileOpts(args []string, i *int, p *readArgs) (bool, error) {
	a := args[*i]
	if v, ok := flagValue(args, i, "--out-file"); ok {
		p.OutFile = v
	} else if v, ok := flagValue(args, i, "-o"); ok {
		p.OutFile = v
	} else if v, ok := flagValue(args, i, "--file-mode"); ok {
		m, err := strconv.ParseUint(v, 8, 32)
		if err != nil {
			return true, fmt.Errorf("bad --file-mode %q", v)
		}
		p.FileMode = os.FileMode(m)
	} else if a == "--force" || a == "-f" {
		p.Force = true
	} else if _, ok := flagValue(args, i, "--account"); ok {
		// one account on this Mac
	} else {
		return false, nil
	}
	return true, nil
}

func parseRead(args []string) (*readArgs, error) {
	p := &readArgs{FileMode: 0o600}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--no-newline" || a == "-n" {
			p.NoNewline = true
			continue
		}
		if ok, err := parseFileOpts(args, &i, p); err != nil {
			return nil, err
		} else if ok {
			continue
		}
		if strings.HasPrefix(a, "-") || p.Ref != "" {
			return nil, errUnsupported
		}
		p.Ref = a
	}
	if !strings.HasPrefix(p.Ref, "op://") {
		return nil, errUnsupported
	}
	return p, nil
}

func parseDocument(args []string) (*readArgs, error) {
	p := &readArgs{FileMode: 0o600, NoNewline: true}
	item, vault := "", ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(args, &i, "--vault"); ok {
			vault = v
			continue
		}
		if ok, err := parseFileOpts(args, &i, p); err != nil {
			return nil, err
		} else if ok {
			continue
		}
		if strings.HasPrefix(a, "-") || item != "" {
			return nil, errUnsupported
		}
		item = a
	}
	if item == "" || vault == "" {
		return nil, errUnsupported // without --vault op searches every vault: leave that to op
	}
	p.Ref = "op://" + vault + "/" + item + "?document"
	return p, nil
}

// shimReason is the reason for a routed call: OPGATE_REASON, or a refusal with the request rules.
func shimReason() (string, error) {
	r := strings.TrimSpace(os.Getenv("OPGATE_REASON"))
	return r, needReason(r, `set OPGATE_REASON="<action and target>" for this op command`)
}

func shimRead(cfg Config, p *readArgs) error {
	reason, err := shimReason()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	vals, err := resolve(cfg, []string{p.Ref}, reason, cwd)
	if err != nil {
		return err
	}
	v := vals[p.Ref]
	if !p.NoNewline {
		v += "\n"
	}
	if p.OutFile == "" {
		_, err = os.Stdout.WriteString(v)
		return err
	}
	if st, err := os.Lstat(p.OutFile); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink: not writing a secret through it", p.OutFile)
		}
		if !p.Force {
			return fmt.Errorf("%s exists (use --force)", p.OutFile)
		}
		if err := os.Remove(p.OutFile); err != nil { // recreate, so the requested mode applies
			return err
		}
	}
	f, err := os.OpenFile(p.OutFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, p.FileMode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(v)
	return err
}

type runArgs struct {
	EnvFiles []string
	Argv     []string
}

func parseRun(args []string) (*runArgs, error) {
	p := &runArgs{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			p.Argv = args[i+1:]
			break
		}
		if v, ok := flagValue(args, &i, "--env-file"); ok {
			p.EnvFiles = append(p.EnvFiles, v)
			continue
		}
		if a == "--no-masking" {
			continue
		}
		if _, ok := flagValue(args, &i, "--account"); ok {
			continue
		}
		if strings.HasPrefix(a, "-") {
			return nil, errUnsupported
		}
		p.Argv = args[i:]
		break
	}
	if len(p.Argv) == 0 {
		return nil, errUnsupported
	}
	return p, nil
}

// runEnv builds the child environment: the current one plus env files, with every op:// value replaced by its
// secret (each name once, so the child can't see the reference instead of the value).
func runEnv(environ []string, envFiles []string, resolveFn func(refs []string) (map[string]string, error)) ([]string, error) {
	vars := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := vars[k]; !ok {
			order = append(order, k)
		}
		vars[k] = v
	}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			set(k, v)
		}
	}
	for _, f := range envFiles {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
			if !ok {
				continue
			}
			set(strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`))
		}
		fh.Close()
	}
	var refs []string // each reference once: two variables may name the same one
	for _, k := range order {
		if v := vars[k]; strings.HasPrefix(v, "op://") && !slices.Contains(refs, v) {
			refs = append(refs, v)
		}
	}
	if len(refs) > 0 {
		vals, err := resolveFn(refs)
		if err != nil {
			return nil, err
		}
		for _, k := range order {
			if strings.HasPrefix(vars[k], "op://") {
				vars[k] = vals[vars[k]]
			}
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+vars[k])
	}
	return out, nil
}

func shimRun(cfg Config, p *runArgs) error {
	cwd, _ := os.Getwd()
	env, err := runEnv(os.Environ(), p.EnvFiles, func(refs []string) (map[string]string, error) {
		reason, err := shimReason() // only when there is something to ask for
		if err != nil {
			return nil, err
		}
		return resolve(cfg, refs, reason, cwd)
	})
	if err != nil {
		return err
	}
	path, err := exec.LookPath(p.Argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, p.Argv, env)
}
