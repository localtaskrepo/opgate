package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeDir struct {
	vaults   []named
	items    map[string][]named
	fields   map[string][]namedField
	sections map[string][]named
	calls    []string
}

func (d *fakeDir) Vaults(context.Context) ([]named, error) {
	d.calls = append(d.calls, "vaults")
	return d.vaults, nil
}
func (d *fakeDir) Items(_ context.Context, v string) ([]named, error) {
	d.calls = append(d.calls, "items "+v)
	return d.items[v], nil
}
func (d *fakeDir) Fields(_ context.Context, v, it string) ([]namedField, []named, error) {
	d.calls = append(d.calls, "fields "+it)
	return d.fields[it], d.sections[it], nil
}

func testDir() *fakeDir {
	return &fakeDir{
		vaults: []named{{"v1", "Agents"}, {"v2", "Private"}},
		items: map[string][]named{"v1": {
			{"i1", "Backup bucket (S3)"}, {"i2", "Cloudflare DNS token"}, {"i3", "Twin (A)"}, {"i4", "Twin A"},
			{"i5", "Dup (x)"}, {"i6", "Dup [x]"},
		}},
		fields: map[string][]namedField{"i1": {
			{"f1", "access key id", ""}, {"f2", "secret (prod)", ""}, {"f3", "token", "s1"}, {"f4", "token", "s2"},
		}},
		sections: map[string][]named{"i1": {{"s1", "Staging (old)"}, {"s2", "Prod"}}},
	}
}

// reader accepts only references 1Password could parse; records what it was asked.
func reader(asked *[]string, ok map[string]string) func(string) (string, error) {
	return func(r string) (string, error) {
		*asked = append(*asked, r)
		if refUnsupported(r) {
			return "", errors.New("invalid character in secret reference")
		}
		if v, found := ok[r]; found {
			return v, nil
		}
		return "", errors.New(`"` + r + `" isn't an item`)
	}
}

func TestRefUnsupported(t *testing.T) {
	for ref, want := range map[string]bool{
		"op://Agents/Cloudflare DNS token/credential": false,
		"op://Agents/a-b_c.d/field?attribute=otp":     false,
		"op://Agents/Backup bucket (S3)/key":          true,
		"op://Agents/Grüße/key":                       true,
		"op://Agents/x/api key [prod]":                true,
	} {
		if got := refUnsupported(ref); got != want {
			t.Errorf("%s: %v", ref, got)
		}
	}
}

func TestPickRules(t *testing.T) {
	items := testDir().items["v1"]
	for name, want := range map[string]string{
		"i2":                 "i2", // ID
		"Backup bucket (S3)": "i1", // exact
		"backup bucket (s3)": "i1", // case
		"Backup bucket S3":   "i1", // letters and digits only
		"backup-bucket-s3":   "i1",
		"Twin A":             "i4", // the exact title wins over "Twin (A)"
		"Twin (A)":           "i3",
	} {
		got, err := pick("item", name, "", items)
		if err != nil || got.ID != want {
			t.Errorf("%q: %v %v", name, got, err)
		}
	}
	if got, _ := pick("item", "twin a", "", items); got.ID != "i4" { // ignoring case finds one before punctuation finds two
		t.Errorf("twin a: %v", got)
	}
	if _, err := pick("item", "Dup x", "", items); err == nil || !strings.Contains(err.Error(), "Dup (x)") || !strings.Contains(err.Error(), "i6") {
		t.Errorf("ambiguous match should name both: %v", err)
	}
	if _, err := pick("item", "()", "", items); err == nil {
		t.Error("a name of punctuation only matched something")
	}
	if _, err := pick("item", "Nope", " in Agents", items); err == nil || err.Error() != `no item "Nope" in Agents` {
		t.Errorf("missing: %v", err)
	}
}

func TestResolveFuzzy(t *testing.T) {
	ok := map[string]string{
		"op://v1/i1/access key id":                    "AKIA",
		"op://v1/i1/f2":                               "prod-secret",
		"op://v1/i1/s1/f3":                            "staging-token",
		"op://v1/i1/access key id?ssh-format=openssh": "q",
		"op://Agents/Cloudflare DNS token/credential": "cf",
	}
	cases := map[string]string{
		"op://Agents/Backup bucket (S3)/access key id":                    "AKIA",
		"op://agents/Backup bucket S3/access key id":                      "AKIA",
		"op://Agents/Backup bucket (S3)/secret (prod)":                    "prod-secret",
		"op://Agents/Backup bucket (S3)/Staging (old)/token":              "staging-token",
		"op://Agents/Backup bucket (S3)/access key id?ssh-format=openssh": "q",
	}
	for ref, want := range cases {
		var asked []string
		got, err := readWithFallback(context.Background(), testDir(), ref, reader(&asked, ok))
		if err != nil || got != want {
			t.Errorf("%s: %q %v (asked %v)", ref, got, err, asked)
		}
	}
	// a reference 1Password can read is read directly, without listing anything
	d := testDir()
	var asked []string
	if v, err := readWithFallback(context.Background(), d, "op://Agents/Cloudflare DNS token/credential", reader(&asked, ok)); v != "cf" || err != nil || len(d.calls) != 0 {
		t.Errorf("direct read: %q %v calls %v", v, err, d.calls)
	}
	// a simple field name is read by its label on the item's ID: the item's other fields are never listed
	d = testDir()
	asked = nil
	readWithFallback(context.Background(), d, "op://Agents/Backup bucket (S3)/access key id", reader(&asked, ok))
	for _, c := range d.calls {
		if strings.HasPrefix(c, "fields") {
			t.Errorf("listed the item's fields although the label worked: %v", d.calls)
		}
	}
	// errors: two sections hold "token", unknown field, unknown item, both errors when a plain ref fails
	for ref, want := range map[string]string{
		"op://Agents/Backup bucket (S3)/token":     "several fields match",
		"op://Agents/Backup bucket (S3)/nope (x)":  `no field "nope (x)" in Backup bucket (S3)`,
		"op://Agents/Missing (item)/x":             `no item "Missing (item)" in Agents`,
		"op://Agents/Missing item/x":               `isn't an item (lookup ignoring case and punctuation: no item "Missing item" in Agents)`,
		"op://Agents/Backup bucket (S3)/Prod/nope": "no field",
		"op://Agents/Backup bucket (S3)":           "references look like",
	} {
		var asked []string
		_, err := readWithFallback(context.Background(), testDir(), ref, reader(&asked, ok))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want %q)", ref, err, want)
		}
	}
	// a timed-out read isn't retried by lookup
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d = testDir()
	readWithFallback(ctx, d, "op://Agents/x/y", func(string) (string, error) { return "", errors.New("timeout") })
	if len(d.calls) != 0 {
		t.Errorf("looked up after a timeout: %v", d.calls)
	}
}

// fakeOpCLI is an op that refuses references with parentheses (like 1Password) and knows one vault and item.
func fakeOpCLI(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "op")
	script := `#!/bin/sh
case "$1 $2" in
"vault list") echo '[{"id":"v1","name":"Agents"}]' ;;
"item list") echo '[{"id":"i1","title":"Backup bucket (S3)"},{"id":"i2","title":"Notes"}]' ;;
"item get") echo '{"id":"i1","fields":[{"id":"f9","label":"secret (prod)","value":"never-used"}]}' ;;
"document get")
  if [ "$3" = "i2" ]; then printf doc-by-id; else echo "[ERROR] \"$3\" isn't a document" >&2; exit 1; fi ;;
"read --no-newline")
  case "$3" in
  *"("*) echo "[ERROR] invalid character in secret reference" >&2; exit 1 ;;
  "op://v1/i1/access key id") printf AKIA ;;
  "op://v1/i1/f9") printf prod ;;
  *) echo "[ERROR] \"$3\" isn't an item" >&2; exit 1 ;;
  esac ;;
*) echo "unexpected $*" >&2; exit 1 ;;
esac
`
	os.WriteFile(p, []byte(script), 0o755)
	return p
}

func TestTouchIDRouteReadsOddNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OPGATE_REAL_OP", fakeOpCLI(t))
	cfg := defaultConfig()
	refs := []string{"op://Agents/Backup bucket (S3)/access key id", "op://Agents/Backup bucket S3/secret (prod)", "op://Agents/notes?document"}
	vals, err := opRead(context.Background(), cfg, refs)
	if err != nil {
		t.Fatal(err)
	}
	if vals[refs[0]] != "AKIA" || vals[refs[1]] != "prod" || vals[refs[2]] != "doc-by-id" {
		t.Errorf("values %v", vals)
	}
	if _, err := opRead(context.Background(), cfg, []string{"op://Agents/Other (x)/k"}); err == nil || !strings.Contains(err.Error(), `no item "Other (x)" in Agents`) {
		t.Errorf("unknown item: %v", err)
	}
}

func TestCheckItem(t *testing.T) {
	d := testDir()
	for ref, want := range map[string]string{
		"op://Agents/Backup bucket (S3)/access key id": "",
		"op://agents/backup bucket s3/whatever":        "", // fields aren't checked: reading one needs its value
		"op://Agents/i2/credential":                    "",
		"op://Agents/Cloudflare DNS token?document":    "",
		"op://Agents/cloudflare/credential":            `no item "cloudflare" in Agents; items with similar names: "Cloudflare DNS token"`,
		"op://Agents/crates.io/credential":             `no item "crates.io" in Agents, nor one with a similar name`,
		"op://Agents/Twin A/x":                         "", // exact title before the punctuation rule
		"op://Agents/dup x/x":                          `several items match "dup x"`,
		"op://Nope/x/y":                                `no vault "Nope"`,
		"op://Agents":                                  "references look like",
	} {
		err := checkItem(context.Background(), d, ref)
		var u unknownRef
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", ref, err)
		case want != "" && (!errors.As(err, &u) || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v, want %q", ref, err, want)
		}
	}
	for _, c := range d.calls {
		if strings.HasPrefix(c, "fields") {
			t.Errorf("read an item's fields: %v", d.calls)
		}
	}
}
