package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// make-signing-cert.sh's import trusts only codesign with the private key, so nothing exports it
// silently. Runs the script's own `security import` line against a throwaway keychain.
func TestSigningKeyImportTrustsOnlyCodesign(t *testing.T) {
	script, err := os.ReadFile("make-signing-cert.sh")
	if err != nil {
		t.Fatal(err)
	}
	var importLine string
	for l := range strings.Lines(string(script)) {
		if strings.HasPrefix(l, "security import ") {
			importLine = l
		}
	}
	if importLine == "" {
		t.Fatal("no `security import` line in make-signing-cert.sh")
	}

	dir := t.TempDir()
	kc := filepath.Join(dir, "test.keychain-db")
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	run("security", "create-keychain", "-p", "test", kc)
	t.Cleanup(func() { _ = exec.Command("security", "delete-keychain", kc).Run() })
	run("security", "unlock-keychain", "-p", "test", kc)
	cfg := filepath.Join(dir, "cfg")
	if err := os.WriteFile(cfg, []byte("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = opgate test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", cfg,
		"-keyout", filepath.Join(dir, "key.pem"), "-out", filepath.Join(dir, "cert.pem"))
	run("/usr/bin/openssl", "pkcs12", "-export", "-inkey", filepath.Join(dir, "key.pem"), "-in", filepath.Join(dir, "cert.pem"),
		"-out", filepath.Join(dir, "id.p12"), "-passout", "pass:test")

	imp := exec.Command("/bin/bash", "-c", importLine)
	imp.Env = append(os.Environ(), "tmp="+dir, "KC="+kc, "pass=test")
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", importLine, err, out)
	}

	if apps := exportApps(run("security", "dump-keychain", "-a", kc)); !slices.Equal(apps, []string{"/usr/bin/codesign"}) {
		t.Errorf("apps trusted with sign/export of the private key: %q, want only /usr/bin/codesign", apps)
	}
}

// exportApps lists the apps of the private key's (class 0x00000010) ACL entry that allows export_clear.
func exportApps(dump string) []string {
	var apps []string
	inKey, inExport := false, false
	for l := range strings.Lines(dump) {
		f := strings.Fields(l)
		switch {
		case strings.HasPrefix(l, "class: "):
			inKey, inExport = strings.TrimSpace(l) == "class: 0x00000010", false
		case !inKey || len(f) == 0:
		case f[0] == "authorizations":
			inExport = slices.Contains(f, "export_clear")
		case inExport && len(f) >= 2 && strings.HasSuffix(f[0], ":") && strings.HasPrefix(f[1], "/"):
			apps = append(apps, f[1])
		}
	}
	return apps
}

// make-signing-cert.sh takes the identity name from install.env, and the default without one (a fresh install has
// none). Runs the script's lines up to the name under an empty HOME, then with an install.env.
func TestSigningCertName(t *testing.T) {
	script, err := os.ReadFile("make-signing-cert.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	start, end := strings.Index(s, "set -euo pipefail\n"), strings.Index(s, "\nKC=")
	if start < 0 || end < start {
		t.Fatal("make-signing-cert.sh: no `set -euo pipefail` ... `KC=` block")
	}
	name := func(env string) string {
		t.Helper()
		h := t.TempDir()
		if env != "" {
			if err := os.MkdirAll(filepath.Join(h, ".config/opgate"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h, ".config/opgate/install.env"), []byte(env), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c := exec.Command("/bin/bash", "-c", s[start:end]+"\nprintf %s \"$NAME\"")
		c.Env = append(os.Environ(), "HOME="+h)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("install.env %q: %v\n%s", env, err, out)
		}
		return string(out)
	}
	if n := name(""); n != "opgate local signing" {
		t.Errorf("without install.env: %q", n)
	}
	if n := name("OPGATE_ID=x\nOPGATE_SIGNING_IDENTITY=my signing\n"); n != "my signing" {
		t.Errorf("from install.env: %q", n)
	}
}
