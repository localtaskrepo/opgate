package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mkfile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeHome makes a home folder with ~/Development/<repos>; macOS's /var → /private/var is resolved first.
func fakeHome(t *testing.T) string {
	home, _ := filepath.EvalSymlinks(t.TempDir())
	t.Setenv("HOME", home)
	return home
}

func TestProjectOf(t *testing.T) {
	home := fakeHome(t)
	dev := filepath.Join(home, "Development")
	os.MkdirAll(filepath.Join(dev, "local", ".git"), 0o755)
	os.MkdirAll(filepath.Join(dev, "local", "mac", "opgate"), 0o755)
	os.MkdirAll(filepath.Join(dev, "@localtaskrepo", "lotar", ".git"), 0o755)
	mkfile(t, filepath.Join(dev, "acme-shop", ".tasks", "config.yml"),
		"ui:\n  theme: synthwave:outrun\n  name: \"Acme Shop\"\n  logo: logo.svg\ndefault:\n  project: ACME\n  name: not this\n")
	os.MkdirAll(filepath.Join(dev, "acme-shop", ".git"), 0o755)
	// a worktree elsewhere belongs to its main checkout
	wt := filepath.Join(home, ".t3", "worktrees", "local", "feature")
	mkfile(t, filepath.Join(wt, ".git"), "gitdir: "+filepath.Join(dev, "local", ".git", "worktrees", "feature")+"\n")
	for dir, want := range map[string]string{
		filepath.Join(dev, "local", "mac", "opgate"):  "local",
		filepath.Join(dev, "@localtaskrepo", "lotar"): "localtaskrepo/lotar",
		filepath.Join(dev, "acme-shop"):               "Acme Shop",
		filepath.Join(wt, "src"):                      "local",
		filepath.Join(home, "Downloads"):              "",
		home:                                          "",
		"/tmp":                                        "",
		"":                                            "",
	} {
		if got := projectOf(dir).Name; got != want {
			t.Errorf("projectOf(%s) = %q, want %q", dir, got, want)
		}
	}
	if r := projectOf(filepath.Join(wt, "src")).Root; r != filepath.Join(dev, "local") {
		t.Errorf("worktree root %s", r)
	}
}

func TestLotarUI(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, ".tasks", "config.yml"), "# c\nui.icon: 'a.png'\nui:\n  logo: b.svg # comment\n  nested:\n    name: deeper\nissue:\n  name: other\n")
	ui := lotarUI(dir)
	if ui["icon"] != "a.png" || ui["logo"] != "b.svg" || ui["name"] != "" {
		t.Errorf("ui %v", ui)
	}
}

// Only images inside the repository count, ui.icon before ui.logo.
func TestIconSource(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside := filepath.Join(t.TempDir(), "x.png")
	mkfile(t, outside, "png")
	mkfile(t, filepath.Join(root, "assets", "logo.png"), "png")
	mkfile(t, filepath.Join(root, "assets", "notes.txt"), "txt")
	os.Symlink(outside, filepath.Join(root, "assets", "link.png"))
	for cfg, want := range map[string]string{
		"ui:\n  logo: assets/logo.png\n":                             "assets/logo.png",
		"ui:\n  icon: assets/missing.png\n  logo: assets/logo.png\n": "assets/logo.png",
		"ui:\n  icon: assets/link.png\n":                             "",
		"ui:\n  icon: ../x.png\n":                                    "",
		"ui:\n  icon: " + outside + "\n":                             "",
		"ui:\n  icon: assets/notes.txt\n":                            "",
	} {
		mkfile(t, filepath.Join(root, ".tasks", "config.yml"), cfg)
		got := iconSource(root)
		if want != "" {
			want = filepath.Join(root, want)
		}
		if got != want {
			t.Errorf("%q: %q, want %q", cfg, got, want)
		}
	}
}

// A white logo gets a dark tile, a dark one a light tile; the result is a square PNG.
func TestTile(t *testing.T) {
	for _, c := range []struct {
		logo color.Color
		dark bool
	}{{color.White, true}, {color.RGBA{0x80, 0, 0, 0xff}, false}} {
		logo := image.NewRGBA(image.Rect(0, 0, 100, 40))
		for y := range 40 {
			for x := range 100 {
				logo.Set(x, y, c.logo)
			}
		}
		b, err := tile(logo)
		if err != nil {
			t.Fatal(err)
		}
		img, _ := png.Decode(bytes.NewReader(b))
		if img.Bounds().Dx() != iconSize || img.Bounds().Dy() != iconSize {
			t.Fatalf("size %v", img.Bounds())
		}
		r, _, _, _ := img.At(iconSize/2, 10).RGBA() // the background above the logo
		if dark := r < 0x8000; dark != c.dark {
			t.Errorf("logo %v: background red %x", c.logo, r)
		}
		if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
			t.Error("corner not rounded")
		}
	}
}

// The real path: sips renders an SVG logo, the page serves it by hash, and only that.
func TestProjectIconServed(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sips"); err != nil {
		t.Skip("no sips")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	mkfile(t, filepath.Join(root, "logo.svg"), `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100"><rect width="200" height="100" fill="#fff"/></svg>`)
	mkfile(t, filepath.Join(root, ".tasks", "config.yml"), "ui:\n  logo: logo.svg\n")
	c := &iconCache{byFile: map[string]string{}, images: map[string][]byte{}}
	u := c.url(root)
	if !strings.HasPrefix(u, "/project-icon/") || c.url(root) != u {
		t.Fatalf("url %q", u)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /project-icon/{file}", c.serve)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	img, err := png.Decode(rec.Body)
	if rec.Code != 200 || err != nil || img.Bounds().Dx() != iconSize {
		t.Fatalf("served %d %v", rec.Code, err)
	}
	if r, _, _, _ := img.At(iconSize/2, 5).RGBA(); r > 0x8000 {
		t.Error("white logo without a dark tile")
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/project-icon/0000.png", nil))
	if rec.Code != 404 {
		t.Errorf("unknown icon: %d", rec.Code)
	}
}

// The project leads the title; the script isn't repeated; the folder only shows when no project is known.
func TestNotificationText(t *testing.T) {
	e := newRouterEnv(t, "phone")
	r := testRequest()
	r.Cwd = "/somewhere"
	r.Asker = Asker{Agent: "Claude Code", Script: "cf-dns.sh", Project: "acme-shop"}
	e.r.Ask(r, "u")
	m := e.push.take()[0].msg
	if m.Title != "🔐 acme-shop · Cloudflare" || !strings.HasSuffix(m.Body, "\nClaude Code · cf-dns.sh") {
		t.Errorf("ask %q / %q", m.Title, m.Body)
	}
	e.r.Done(r, Result{Status: "denied"})
	if m := e.push.take()[0].msg; m.Title != "Denied · acme-shop · Cloudflare" {
		t.Errorf("denied %q", m.Title)
	}
	r = testRequest()
	r.Cwd = "/somewhere"
	r.Asker = Asker{Agent: "Codex"}
	e.r.Ask(r, "u")
	if m := e.push.take()[0].msg; m.Title != "🔐 Cloudflare" || !strings.HasSuffix(m.Body, "\nCodex · /somewhere") {
		t.Errorf("ask without project %q / %q", m.Title, m.Body)
	}
	now := time.Now()
	a := Activity{Kind: "daily", Tag: "d", Count: 5, Title: "Build key", Uses: []Use{
		{Time: now, Agent: "Claude Code", Command: "git commit -q -F -", Project: "webapp", Folder: "/x"},
		{Time: now, Project: "local"}, {Time: now, Project: "webapp"}, {Time: now}}}
	e.r.Used(a, "u")
	if m := e.push.take()[0].msg; m.Title != "webapp +1 · Build key used (5× today)" || m.Body != "git commit -q -F -\nClaude Code" {
		t.Errorf("used %q / %q", m.Title, m.Body)
	}
}

// The project recorded in the audit log reaches the history (with its icon), and a live request's page shows it.
func TestProjectOnPages(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	mkfile(t, filepath.Join(root, "logo.svg"), `<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#000"/></svg>`)
	mkfile(t, filepath.Join(root, ".tasks", "config.yml"), "ui:\n  icon: logo.svg\n")
	e := newEnv(t)
	e.b.cfg.AuditLog = filepath.Join(t.TempDir(), "audit.jsonl")
	e.b.audit = &Audit{path: e.b.cfg.AuditLog}
	r := &Request{RequestIn: RequestIn{Kind: KindSecrets, Refs: []string{"op://Agents/Cloudflare/credential"}, Reason: "x"}, ID: "h1",
		Asker: Asker{Agent: "Claude Code", Project: "demo", Root: root}}
	e.b.audit.Log(r, "asked", "", "")
	h := e.b.history(10)
	if len(h) != 1 || h[0].Project != "demo" || !strings.HasPrefix(h[0].Icon, "/project-icon/") {
		t.Fatalf("history %+v", h)
	}
	live := e.ask(cfReq)
	live.Asker = Asker{Agent: "Claude Code", Project: "demo", Root: root}
	resp, err := http.Get(e.srv.URL + "/r/" + live.ID)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if !strings.Contains(buf.String(), "<b>demo</b>") || !strings.Contains(buf.String(), `class="picon" src="/project-icon/`) {
		t.Error("request page without the project chip")
	}
}
