// opgate: phone-approved access to a 1Password vault for agents on this Mac.
//
// Agents ask for secrets (or an ssh key for a while) with a reason; the owner gets a push, reviews the request on
// the approval page (publicURL) and approves with a passkey. Secrets come from a read-only 1Password service account
// whose token only this binary can read from the keychain. See README.md and SECURITY.md.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "0.24.1"

const usage = `opgate: phone-approved 1Password access for agents

  opgate read  --reason TEXT REF...             print the values (one per line) after approval
  opgate run   --reason TEXT --env VAR=REF... -- CMD [ARGS]   run CMD with the values in its environment
  opgate ssh-add --reason TEXT [--ttl 15m] REF  load an ssh key into opgate's agent for a while
  opgate mode [auto|phone|touchid]              show or set how secrets are fetched (also for "op read/run")
  opgate guide                                  how agents should use opgate (print this into your context)
  opgate status                                 pending requests and loaded keys
  opgate creds [show ID|unused|validate]        the credential map: status, expiry, last use (no values)
  opgate reload                                 load the autoload keys again (after editing the control item)
  opgate enroll [--name NAME]                   register a passkey (prints the entry for 1Password)
  opgate bootstrap REF                          store the service account token (owner, at the Mac)
  opgate handover                               get the keychain store from the running opgate after the owner's
                                                approval on the phone (install.sh, before installing a new build)
  opgate keychain-check [--fresh]               can this build read its keychain item (install.sh, before installing;
                                                --fresh: again from a new process, without waiting for a prompt)
  opgate serve                                  run the service (the launch agent)

The reason defaults to $OPGATE_REASON; without one, read, run and ssh-add are refused. Say what you are about to do
and why; it is what the owner sees.
`

type envFlags []string

func (e *envFlags) String() string     { return strings.Join(*e, ",") }
func (e *envFlags) Set(v string) error { *e = append(*e, v); return nil }

func main() {
	if filepath.Base(os.Args[0]) == "op" { // ~/.local/opgate/bin/op -> opgate: the transparent op wrapper
		cfg, _ := loadConfig()
		os.Exit(opShim(cfg, os.Args[1:]))
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "creds" { // own flags and subcommands (creds.go)
		os.Exit(credsMain(args))
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	reason := fs.String("reason", os.Getenv("OPGATE_REASON"), "what for and why")
	ttl := fs.Duration("ttl", 0, "ssh-add: how long the key should stay loaded (default 15m; the owner can change it)")
	name := fs.String("name", "phone", "enroll: passkey name")
	fresh := fs.Bool("fresh", false, "keychain-check: from a new process, without waiting for a prompt")
	var envs envFlags
	fs.Var(&envs, "env", "run: VAR=op://... (repeatable)")
	_ = fs.Parse(args) // ExitOnError: a bad flag exits inside Parse
	cwd, _ := os.Getwd()

	var err error
	if cmd == "read" || cmd == "run" || cmd == "ssh-add" {
		if err = needReason(*reason, `--reason "<action and target>" or OPGATE_REASON`); err != nil {
			fmt.Fprintln(os.Stderr, "opgate:", err)
			os.Exit(1)
		}
	}
	switch cmd {
	case "serve":
		err = serve()
	case "bootstrap":
		if fs.NArg() != 1 {
			err = errors.New("usage: opgate bootstrap op://<vault>/<item>/<field>")
			break
		}
		if err = bootstrap(context.Background(), fs.Arg(0)); err == nil {
			fmt.Println("opgate: service account token stored in the keychain and working")
		}
	case "read":
		var vals map[string]string
		cfg, _ := loadConfig()
		if fs.NArg() == 0 {
			err = errors.New("usage: opgate read --reason TEXT op://<vault>/<item>/<field> [more references]")
			break
		}
		vals, err = resolve(cfg, fs.Args(), *reason, cwd)
		for _, ref := range fs.Args() { // check all first: print nothing rather than half
			if err == nil && fs.NArg() > 1 && strings.Contains(vals[ref], "\n") {
				err = fmt.Errorf("%s has several lines: read it on its own", ref)
			}
		}
		if err == nil {
			for _, ref := range fs.Args() {
				fmt.Println(vals[ref])
			}
		}
	case "run":
		err = run(envs, fs.Args(), *reason, cwd)
	case "ssh-add":
		if fs.NArg() != 1 {
			err = errors.New("usage: opgate ssh-add [--ttl 1h] --reason TEXT op://<vault>/<item>/<field>")
			break
		}
		if _, err = request(RequestIn{Kind: KindSSH, Refs: fs.Args(), TTL: *ttl, Reason: *reason, Cwd: cwd}, ""); err == nil {
			fmt.Fprintf(os.Stderr, "opgate: %s loaded (opgate status shows until when)\n", friendlyItem(fs.Arg(0)))
		}
	case "enroll":
		var res *Result
		if res, err = request(RequestIn{Kind: KindEnroll, Name: *name, Reason: "register passkey " + *name, Cwd: cwd}, ""); err == nil {
			fmt.Println(string(res.Payload))
			fmt.Fprintln(os.Stderr, "opgate: add this object to the JSON list in the \"passkeys\" field of 1Password item "+controlItem)
		}
	case "handover":
		if err = handover(cwd); errors.Is(err, errNoHandover) {
			fmt.Fprintln(os.Stderr, "opgate:", err)
			os.Exit(3) // install.sh asks at the Mac instead
		}
		if err == nil {
			fmt.Println("opgate: this build has its own keychain item")
		}
	case "keychain-check":
		kcWait.timeout = 2 * time.Minute // at the Mac: time to answer the prompt
		if *fresh {
			kcWait.timeout = 5 * time.Second // allowed for good: no prompt, the read takes milliseconds
		}
		if err = keychainCheck(kcStore, *fresh); err == nil {
			fmt.Println("opgate: this build reads its keychain item")
		}
	case "guide":
		fmt.Print(guideText())
	case "mode":
		if fs.NArg() == 1 {
			err = setMode(fs.Arg(0))
		}
		if err == nil {
			fmt.Println(currentMode())
		}
	case "status":
		err = status("status")
	case "reload":
		err = status("reload")
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "opgate:", err)
		os.Exit(1)
	}
}

func dial() (net.Conn, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("opgate service not reachable (%v): if `launchctl print gui/$(id -u)/%s` says running, "+
			"see ~/Library/Logs/opgate/opgate.log; otherwise launchctl kickstart gui/$(id -u)/%s", err, appID, appID)
	}
	return c, nil
}

// request sends one request and waits for the decision, telling the caller (the agent) what is going on. note, if
// any, is printed once the broker has taken the request.
func request(in RequestIn, note string) (*Result, error) {
	c, err := dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	b, _ := json.Marshal(in)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var m clientMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return nil, err
		}
		switch m.Event {
		case "pending":
			if note != "" {
				fmt.Fprintf(os.Stderr, "opgate: %s\n", note)
			}
			fmt.Fprintf(os.Stderr, "opgate: waiting for the owner's approval on the phone: %s (%s)\n", m.Summary, m.URL)
			if m.Warning != "" {
				fmt.Fprintf(os.Stderr, "opgate: warning: %s; still waiting (the owner can open it from the history page)\n", m.Warning)
			}
		case "result":
			if m.Result.Status != "approved" {
				return nil, fmt.Errorf("%s: %s", m.Result.Status, m.Result.Error)
			}
			return m.Result, nil
		}
	}
	return nil, errors.New("opgate service closed the connection")
}

func run(envs []string, argv []string, reason, cwd string) error {
	if len(argv) == 0 || len(envs) == 0 {
		return errors.New("usage: opgate run --reason TEXT --env VAR=op://... -- CMD [ARGS]")
	}
	environ := os.Environ()
	for _, e := range envs {
		if k, v, ok := strings.Cut(e, "="); !ok || k == "" || !strings.HasPrefix(v, "op://") {
			return fmt.Errorf("bad --env %q (want NAME=op://...)", e)
		}
		environ = append(environ, e)
	}
	cfg, _ := loadConfig()
	env, err := runEnv(environ, nil, func(refs []string) (map[string]string, error) {
		return resolve(cfg, refs, reason+" (runs: "+short(strings.Join(argv, " "), 200)+")", cwd)
	})
	if err != nil {
		return err
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, env)
}

func status(kind string) error {
	c, err := dial()
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write([]byte(`{"kind":"` + kind + `"}` + "\n")); err != nil {
		return err
	}
	var m clientMsg
	if err := json.NewDecoder(c).Decode(&m); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(m.Status, "", "  ")
	fmt.Println(string(out))
	return nil
}
