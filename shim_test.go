package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseRead(t *testing.T) {
	p, err := parseRead([]string{"-n", "--out-file=/tmp/x", "--force", "op://Agents/a/b"})
	if err != nil || !p.NoNewline || p.OutFile != "/tmp/x" || !p.Force || p.Ref != "op://Agents/a/b" {
		t.Fatalf("%+v %v", p, err)
	}
	for _, args := range [][]string{
		{"op://a/b/c", "op://a/b/d"}, // two refs: not op's syntax
		{"--weird", "op://a/b/c"},    // unknown flag: leave it to op
		{"notaref"},                  // not a reference
	} {
		if _, err := parseRead(args); !errors.Is(err, errUnsupported) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestParseDocumentNeedsVault(t *testing.T) {
	p, err := parseDocument([]string{"App oauth2.txt", "--vault", "Agents", "-o", "/tmp/o"})
	if err != nil || p.Ref != "op://Agents/App oauth2.txt?document" || p.OutFile != "/tmp/o" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parseDocument([]string{"App oauth2.txt"}); !errors.Is(err, errUnsupported) {
		t.Fatal("document without --vault must go to op")
	}
}

func TestParseRun(t *testing.T) {
	p, err := parseRun([]string{"--env-file", ".env", "--no-masking", "--", "curl", "-s"})
	if err != nil || !slices.Equal(p.EnvFiles, []string{".env"}) || !slices.Equal(p.Argv, []string{"curl", "-s"}) {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parseRun([]string{"--"}); !errors.Is(err, errUnsupported) {
		t.Fatal("empty command accepted")
	}
}

func TestRunEnvReplacesRefsOnce(t *testing.T) {
	dir := t.TempDir()
	envf := filepath.Join(dir, ".env")
	os.WriteFile(envf, []byte("# c\nexport B=\"op://Agents/b/c\"\nPLAIN=1\n"), 0o600)
	var asked []string
	env, err := runEnv([]string{"A=op://Agents/a/c", "HOME=/h", "A=op://Agents/a/c"}, []string{envf},
		func(refs []string) (map[string]string, error) {
			asked = refs
			return map[string]string{"op://Agents/a/c": "va", "op://Agents/b/c": "vb"}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v", asked)
	}
	want := []string{"A=va", "HOME=/h", "B=vb", "PLAIN=1"}
	if !slices.Equal(env, want) {
		t.Fatalf("env %v, want %v", env, want)
	}
}

// fakeOp writes a stand-in for 1Password's op that prints "from-op" or hangs.
func fakeOp(t *testing.T, hang bool) string {
	p := filepath.Join(t.TempDir(), "op")
	body := "#!/bin/sh\nprintf from-op\n"
	if hang {
		body = "#!/bin/sh\nsleep 5\n"
	}
	os.WriteFile(p, []byte(body), 0o755)
	return p
}

func TestModes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	sock := filepath.Join(t.TempDir(), "s.sock")
	go e.b.serveSocket(sock)
	t.Setenv("OPGATE_SOCKET", sock)
	for i := 0; i < 50 && !serviceUp(Config{Socket: sock}); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cfg := defaultConfig()
	cfg.Socket, cfg.OpTimeout = sock, Duration{300 * time.Millisecond}
	ref := "op://Agents/Cloudflare/credential"

	// touchid: 1Password only
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, false))
	t.Setenv("OPGATE_MODE", ModeTouchID)
	if v, err := resolve(cfg, []string{ref}, "a long enough reason", ""); err != nil || v[ref] != "from-op" {
		t.Fatalf("touchid: %v %v", v, err)
	}
	// auto, owner at the Mac, 1Password answers: no phone
	t.Setenv("OPGATE_MODE", ModeAuto)
	t.Setenv("OPGATE_PRESENCE", "present")
	if v, err := resolve(cfg, []string{ref}, "a long enough reason", ""); err != nil || v[ref] != "from-op" {
		t.Fatalf("auto/op: %v %v", v, err)
	}
	// auto, 1Password silent: the phone is asked after the timeout
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, true))
	go func() {
		for i := 0; i < 200; i++ {
			if p := e.b.Pending(); len(p) == 1 {
				e.approve(a, p[0], "", 0x05)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	start := time.Now()
	v, err := resolve(cfg, []string{ref}, "a long enough reason", "")
	if err != nil || v[ref] != "cf-secret" || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("auto/fallback: %v %v after %s", v, err, time.Since(start))
	}
	// auto, owner away: the phone at once, 1Password (which would answer) isn't even asked
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, false))
	t.Setenv("OPGATE_PRESENCE", "away")
	go func() {
		for i := 0; i < 200; i++ {
			if p := e.b.Pending(); len(p) == 1 {
				e.approve(a, p[0], "", 0x05)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if v, err := resolve(cfg, []string{ref}, "a long enough reason", ""); err != nil || v[ref] != "cf-secret" {
		t.Fatalf("auto/away: %v %v", v, err)
	}
	// mode file
	if err := setMode("phone"); err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("OPGATE_MODE")
	if currentMode() != ModePhone || setMode("sometimes") == nil {
		t.Fatal("mode file")
	}
}

func TestRequestWithoutReasonIsRefusedWithTheRules(t *testing.T) {
	if needReason("  Create the DNS record x -> y ", "") != nil {
		t.Fatal("a reason passes")
	}
	err := needReason(" ", `--reason "<action and target>" or OPGATE_REASON`)
	if err == nil {
		t.Fatal("blank reason passes")
	}
	for _, want := range []string{"nobody was asked", "--reason", "one concrete sentence", "the action and the target",
		"no\n  secret", "exactly the fields", "one call", "right before", `"denied", "expired" or "error"`, "tell the user", "don't guess item names", "$(...)", "opgate guide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q:\n%s", want, err)
		}
	}
	if n := strings.Count(err.Error(), "\n"); n > 8 {
		t.Errorf("refusal has %d lines, want a few", n+1)
	}

	// the op wrapper's routed calls: refused before 1Password or the phone (the fake op would hang), exit 1
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, true))
	t.Setenv("OPGATE_MODE", ModeAuto)
	t.Setenv("OPGATE_PRESENCE", "present")
	t.Setenv("OPGATE_REASON", "")
	cfg := defaultConfig()
	cfg.Socket = filepath.Join(t.TempDir(), "none.sock")
	env := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(env, []byte("TOKEN=op://Agents/x/y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"read", "op://Agents/x/y"},
		{"document", "get", "x", "--vault", "Agents"},
		{"item", "get", "x", "--vault", "Agents", "--fields", "label=y", "--reveal"},
		{"run", "--env-file", env, "--", "true"},
	} {
		start := time.Now()
		errOut, code := captureStderr(t, func() int { return opShim(cfg, args) })
		if code != 1 || time.Since(start) > 2*time.Second || !strings.Contains(errOut, "OPGATE_REASON") ||
			!strings.Contains(errOut, "one concrete sentence") {
			t.Errorf("%v: %d %v\n%s", args, code, time.Since(start), errOut)
		}
	}
}

func TestParseItemGet(t *testing.T) {
	ok := map[string][]string{
		`"Backup bucket (S3)" --vault Agents --fields "label=access key id,label=secret" --reveal`: {"access key id", "secret"},
		`Cloudflare --vault=Agents --fields credential --reveal --account my`:                      {"credential"},
		`x --reveal --vault Agents --fields label=a --fields b`:                                    {"a", "b"},
	}
	for line, want := range ok {
		p, err := parseItemGet(splitArgs(line))
		if err != nil || !slices.Equal(p.Fields, want) || p.Vault != "Agents" {
			t.Errorf("%s: %+v %v", line, p, err)
		}
	}
	for _, line := range []string{
		`x --vault Agents --format json --reveal`,              // whole item as JSON: op's
		`x --vault Agents --fields a`,                          // no --reveal
		`x --fields a --reveal`,                                // no vault
		`x --vault Agents --fields type=concealed --reveal`,    // op's selector
		`x --vault Agents --fields a/b --reveal`,               // not a reference
		`x --vault Agents --fields a --reveal --otp`,           // unknown flag
		`x y --vault Agents --fields a --reveal`,               // two items
		`--vault Agents --fields a --reveal`,                   // no item
		`x --vault Agents --fields a,b,c,d,e,f,g,h,i --reveal`, // more than one request takes
	} {
		if _, err := parseItemGet(splitArgs(line)); !errors.Is(err, errUnsupported) {
			t.Errorf("%s: want unsupported, got %v", line, err)
		}
	}
}

// splitArgs splits like a shell for the simple quoting in these tests.
func splitArgs(s string) []string {
	var out []string
	cur, q, has := "", false, false
	for _, r := range s {
		switch {
		case r == '"':
			q, has = !q, true
		case r == ' ' && !q:
			if has || cur != "" {
				out = append(out, cur)
			}
			cur, has = "", false
		default:
			cur += string(r)
		}
	}
	if has || cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestShimItemGetReadsTheFields(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OPGATE_REASON", "Preview the Pulumi stack")
	t.Setenv("OPGATE_REAL_OP", fakeOpCLI(t))
	t.Setenv("OPGATE_MODE", ModeAuto)
	t.Setenv("OPGATE_PRESENCE", "present")
	cfg := defaultConfig()
	cfg.Socket = filepath.Join(t.TempDir(), "none.sock")
	out, code := capture(t, func() int {
		return opShim(cfg, []string{"item", "get", "Backup bucket (S3)", "--vault", "Agents", "--fields", "label=access key id,label=secret (prod)", "--reveal"})
	})
	if code != 0 || out != "AKIA,prod\n" {
		t.Errorf("item get: %d %q", code, out)
	}
}

func TestAwayFailsFastInsteadOfWaitingForTouchID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, true)) // would hang: must never run
	cfg := defaultConfig()
	cfg.Socket = filepath.Join(t.TempDir(), "none.sock")
	for _, c := range []struct {
		mode, presence, wait string
		args                 []string
		away                 bool
	}{
		{ModeAuto, "away", "", []string{"item", "get", "x", "--vault", "Agents", "--format", "json", "--reveal"}, true},
		{ModePhone, "away", "", []string{"item", "list"}, true},
		{ModeAuto, "present", "", []string{"item", "get", "x"}, false},
		{ModeTouchID, "away", "", []string{"item", "get", "x"}, false}, // the owner chose Touch ID
		{ModeAuto, "away", "1", []string{"item", "get", "x"}, false},   // OPGATE_WAIT_FOR_TOUCHID
		{ModeAuto, "away", "", []string{"--version"}, false},
		{ModeAuto, "away", "", []string{"completion", "zsh"}, false},
	} {
		t.Setenv("OPGATE_MODE", c.mode)
		t.Setenv("OPGATE_PRESENCE", c.presence)
		t.Setenv("OPGATE_WAIT_FOR_TOUCHID", c.wait)
		if _, away := awayForTouchID(cfg, c.args); away != c.away {
			t.Errorf("%+v: away %v", c, away)
		}
	}
	// end to end: returns at once with the hint (a passthrough would replace the test process)
	t.Setenv("OPGATE_MODE", ModeAuto)
	t.Setenv("OPGATE_PRESENCE", "away")
	t.Setenv("OPGATE_WAIT_FOR_TOUCHID", "")
	start := time.Now()
	errOut, code := captureStderr(t, func() int {
		return opShim(cfg, []string{"item", "get", "Deploy token", "--vault", "Agents", "--format", "json", "--reveal"})
	})
	if code != 1 || time.Since(start) > 2*time.Second || !strings.Contains(errOut, "nobody is at the Mac") ||
		!strings.Contains(errOut, `"op item get"`) || !strings.Contains(errOut, "op run --env-file") || strings.Contains(errOut, "Deploy token") {
		t.Errorf("away: %d %v\n%s", code, time.Since(start), errOut)
	}
}

// captureStderr runs fn with stderr redirected and returns what it printed.
func captureStderr(t *testing.T, fn func() int) (string, int) {
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	code := fn()
	w.Close()
	os.Stderr = old
	b, _ := io.ReadAll(r)
	return string(b), code
}

// The "asking the owner" note comes only once the broker has taken the request.
func TestAwayNote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	e := newEnv(t)
	a := newAuthenticator("approve.example")
	e.enroll(a)
	sock := filepath.Join(t.TempDir(), "s.sock")
	go e.b.serveSocket(sock)
	t.Setenv("OPGATE_SOCKET", sock)
	for i := 0; i < 50 && !serviceUp(Config{Socket: sock}); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cfg := defaultConfig()
	cfg.Socket = sock
	t.Setenv("OPGATE_REAL_OP", fakeOp(t, true)) // would hang: must never run
	t.Setenv("OPGATE_MODE", ModeAuto)
	t.Setenv("OPGATE_PRESENCE", "away")
	ref := "op://Agents/Cloudflare/credential"

	errOut, _ := captureStderr(t, func() int {
		if _, err := resolve(cfg, []string{ref}, "test (runs: true)", ""); err == nil {
			t.Error("a too-short reason passes")
		}
		return 0
	})
	if strings.Contains(errOut, "asking the owner") {
		t.Errorf("refused, but told the owner is asked:\n%s", errOut)
	}

	go func() {
		for i := 0; i < 200; i++ {
			if p := e.b.Pending(); len(p) == 1 {
				e.approve(a, p[0], "", 0x05)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	errOut, _ = captureStderr(t, func() int {
		if v, err := resolve(cfg, []string{ref}, "a long enough reason", ""); err != nil || v[ref] != "cf-secret" {
			t.Errorf("away: %v %v", v, err)
		}
		return 0
	})
	if !strings.Contains(errOut, "away (OPGATE_PRESENCE); asking the owner on the phone") {
		t.Errorf("accepted, but no note:\n%s", errOut)
	}
}
