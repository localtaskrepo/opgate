package main

// `opgate handover` (install.sh): a new build asks the running service for opgate's keychain store, the
// owner approves it with the passkey on the phone, and the new build writes it into an item of its own, which it
// reads without a prompt. That replaces "Always Allow" at the Mac, which nobody answers while the owner is away.
// The passkey is the gate, as the prompt was: anything on this Mac can sign a build with the local signing identity
// without asking, so the signature check below only makes sure the asker is an opgate build at all.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KindHandover gives the keychain store to a new build of opgate.
const KindHandover = "handover"

// errNoHandover: no handover was asked for (opgate not running or before 0.23.0, a build that isn't signed with the
// local signing identity); install.sh then asks at the Mac instead (keychain-check).
var errNoHandover = errors.New("no running opgate can hand over its keychain store")

var buildIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

// handover is the new build's side: nothing to do when it has its own item already.
func handover(cwd string) error {
	if ok, err := kcStore.hasOwn(); err != nil {
		return err
	} else if ok {
		return nil
	}
	id, err := buildID()
	if err != nil {
		return err
	}
	exe, _ := os.Executable()
	in := RequestIn{Kind: KindHandover, Name: id, Cwd: cwd,
		Reason: fmt.Sprintf("install opgate %s: the new build (%s, build %s) takes over the running opgate's keychain store "+
			"(service account token, push key, settings), so it starts without a prompt at the Mac", version, shortHome(exe), id)}
	c, err := dial()
	if err != nil {
		return fmt.Errorf("%w: %w", errNoHandover, err)
	}
	c.Close()
	res, err := request(in, "")
	if err != nil {
		// a build before 0.23.0, or a refused peer (ad-hoc signed, other build): nobody was asked
		if strings.Contains(err.Error(), `unknown kind "handover"`) || strings.Contains(err.Error(), "nobody was asked") {
			return fmt.Errorf("%w: %w", errNoHandover, err)
		}
		return err
	}
	var m map[string][]byte
	if err := json.Unmarshal(res.Payload, &m); err != nil {
		return fmt.Errorf("the running build's answer: %w", err)
	}
	return kcStore.adopt(m)
}

// checkHandoverPeer refuses a handover to anything but a running opgate build signed like this one, whose
// executable is the build named in the request. A variable for the tests.
var checkHandoverPeer = func(ps []proc, id string) error {
	if len(ps) == 0 || ps[0].Exe == "" {
		return errors.New("can't tell which process asks")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "codesign", "-d", "-r-", self).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reading this build's signature: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_, req, ok := strings.Cut(string(out), "designated => ")
	req = strings.TrimSpace(req)
	if !ok || strings.Contains(req, "cdhash") {
		return errors.New("this build is ad-hoc signed: a handover needs the local signing identity (make-signing-cert.sh)")
	}
	// the running process (by pid, not its file, which could be swapped after it started)
	if out, err := exec.CommandContext(ctx, "codesign", "--verify", "-R="+req, strconv.Itoa(ps[0].PID)).CombinedOutput(); err != nil {
		return fmt.Errorf("%s isn't an opgate build signed like this one: %s", ps[0].Exe, strings.TrimSpace(string(out)))
	}
	got, err := fileBuildID(ps[0].Exe)
	if err != nil {
		return err
	}
	if got != id {
		return fmt.Errorf("%s is build %s, not %s", ps[0].Exe, got, id)
	}
	return nil
}
