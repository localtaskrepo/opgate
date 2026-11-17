package main

// Project: the repository an agent works in, so notifications say "homelab" or "Acme Shop" instead of
// only "Claude Code", and show the project's lotar icon (ui.icon, else ui.logo in .tasks/config.yml).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// project is a repository: Name is what the owner reads, Root its folder (the main checkout for a worktree).
type project struct {
	Name, Root string
}

// projectOf finds the repository holding dir: the nearest folder with .git or .tasks below the home folder.
func projectOf(dir string) project {
	if dir == "" {
		return project{}
	}
	home, _ := os.UserHomeDir()
	for d := filepath.Clean(dir); d != home && d != "/" && d != "." && strings.HasPrefix(d, home+"/"); d = filepath.Dir(d) {
		git, gerr := os.Lstat(filepath.Join(d, ".git"))
		_, terr := os.Stat(filepath.Join(d, ".tasks"))
		if gerr != nil && terr != nil {
			continue
		}
		root := d
		if gerr == nil && git.Mode().IsRegular() { // a worktree: "gitdir: <main>/.git/worktrees/<name>"
			if main := worktreeMain(filepath.Join(d, ".git")); main != "" {
				root = main
			}
		}
		return project{Name: projectName(root, home), Root: root}
	}
	return project{}
}

func worktreeMain(gitFile string) string {
	b, err := os.ReadFile(gitFile)
	if err != nil || len(b) > 4096 {
		return ""
	}
	gd, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return ""
	}
	gd = strings.TrimSpace(gd)
	if !filepath.IsAbs(gd) {
		gd = filepath.Join(filepath.Dir(gitFile), gd)
	}
	if i := strings.Index(gd, "/.git/worktrees/"); i > 0 {
		return gd[:i]
	}
	return ""
}

// projectName: lotar's ui.name, else the folder below ~/Development ("localtaskrepo/lotar"), else its own name.
func projectName(root, home string) string {
	if n := lotarUI(root)["name"]; n != "" {
		return short(n, 40)
	}
	if rel, err := filepath.Rel(filepath.Join(home, "Development"), root); err == nil && !strings.HasPrefix(rel, "..") && rel != "." {
		parts := strings.Split(rel, "/")
		for i := range parts {
			parts[i] = strings.TrimPrefix(parts[i], "@")
		}
		return strings.Join(parts, "/")
	}
	return filepath.Base(root)
}

// lotarUI reads the ui block of a repository's lotar config (.tasks/config.yml): name, icon, logo, ...
// Only plain `key: value` lines directly under `ui:` (or `ui.key: value`) count; that is all lotar writes there.
func lotarUI(root string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(filepath.Join(root, ".tasks", "config.yml"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	in, indent := false, -1
	for n := 0; sc.Scan() && n < 2000; n++ {
		line := strings.TrimRight(sc.Text(), " \r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lead := len(line) - len(strings.TrimLeft(line, " "))
		if lead == 0 {
			in, indent = t == "ui:", -1
			if k, v, ok := strings.Cut(t, ":"); ok && strings.HasPrefix(k, "ui.") {
				out[strings.TrimPrefix(k, "ui.")] = yamlScalar(v)
			}
			continue
		}
		if !in {
			continue
		}
		if indent < 0 {
			indent = lead
		}
		if lead != indent {
			continue
		}
		if k, v, ok := strings.Cut(t, ":"); ok {
			out[strings.TrimSpace(k)] = yamlScalar(v)
		}
	}
	return out
}

func yamlScalar(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

// iconSource is the image lotar shows for the repository: ui.icon (the browser tab icon, usually square), else
// ui.logo. Like lotar, only image files inside the repository count (no paths or symlinks out of it).
func iconSource(root string) string {
	ui := lotarUI(root)
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ""
	}
	for _, k := range []string{"icon", "logo"} {
		v := ui[k]
		if v == "" || filepath.IsAbs(v) {
			continue
		}
		p, err := filepath.EvalSymlinks(filepath.Join(root, v))
		if err != nil || !strings.HasPrefix(p, realRoot+"/") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(p))
		if !slices.Contains([]string{".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".avif"}, ext) {
			continue
		}
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 {
			continue
		}
		return p
	}
	return ""
}

// Notification icons: a project's image as a 192 px square tile, served by content hash (/project-icon/<hash>.png),
// so the page only hands out images opgate rendered itself.
const iconSize = 192

type iconCache struct {
	mu     sync.Mutex
	byFile map[string]string // source path + mtime + size -> hash ("" if it couldn't be rendered)
	images map[string][]byte // hash -> PNG
}

var projectIcons = &iconCache{byFile: map[string]string{}, images: map[string][]byte{}}

// url returns the icon's path for a repository ("" without one, or when it can't be rendered).
func (c *iconCache) url(root string) string {
	if root == "" {
		return ""
	}
	src := iconSource(root)
	if src == "" {
		return ""
	}
	st, err := os.Stat(src)
	if err != nil {
		return ""
	}
	key := src + "|" + st.ModTime().String() + "|" + strconv.FormatInt(st.Size(), 10)
	c.mu.Lock()
	h, ok := c.byFile[key]
	c.mu.Unlock()
	if !ok {
		png, err := renderIcon(src)
		if err == nil {
			sum := sha256.Sum256(png)
			h = hex.EncodeToString(sum[:12])
		}
		c.mu.Lock()
		c.byFile[key] = h
		if h != "" {
			c.images[h] = png
		}
		c.mu.Unlock()
	}
	if h == "" {
		return ""
	}
	return "/project-icon/" + h + ".png"
}

func (c *iconCache) serve(w http.ResponseWriter, req *http.Request) {
	h := strings.TrimSuffix(req.PathValue("file"), ".png")
	c.mu.Lock()
	b, ok := c.images[h]
	c.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(b) // fails only when the page went away
}

// renderIcon converts the image with macOS's sips (it reads SVG, PNG, JPEG, WebP, ...) and centers it on a rounded
// square: dark behind light logos (a white logo would vanish on a light notification), light behind dark ones.
func renderIcon(src string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "opgate-icon")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "icon.png")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inner := iconSize * 3 / 4
	if err := exec.CommandContext(ctx, "/usr/bin/sips", "-s", "format", "png", "-Z", strconv.Itoa(inner), src, "--out", out).Run(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	logo, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return tile(logo)
}

// tile draws logo centered on a rounded square in a background that contrasts with it.
func tile(logo image.Image) ([]byte, error) {
	bg := color.RGBA{0xf4, 0xf4, 0xf5, 0xff}
	if brightness(logo) > 0.6 {
		bg = color.RGBA{0x1f, 0x23, 0x30, 0xff}
	}
	img := image.NewRGBA(image.Rect(0, 0, iconSize, iconSize))
	r := float64(iconSize) / 5
	for y := range iconSize {
		for x := range iconSize {
			if insideRounded(float64(x)+0.5, float64(y)+0.5, float64(iconSize), r) {
				img.SetRGBA(x, y, bg)
			}
		}
	}
	b := logo.Bounds()
	at := image.Pt((iconSize-b.Dx())/2, (iconSize-b.Dy())/2)
	draw.Draw(img, image.Rectangle{at, at.Add(b.Size())}, logo, b.Min, draw.Over)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func insideRounded(x, y, size, r float64) bool {
	cx := min(max(x, r), size-r)
	cy := min(max(y, r), size-r)
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r
}

// brightness is the average luminance (0..1) of the logo's visible pixels, weighted by their opacity.
func brightness(img image.Image) float64 {
	var sum, weight float64
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			if a == 0 {
				continue
			}
			w := float64(a) / 0xffff
			// colors are premultiplied: divide by alpha for the color itself
			l := (0.2126*float64(r) + 0.7152*float64(g) + 0.0722*float64(bl)) / float64(a)
			sum += l * w
			weight += w
		}
	}
	if weight == 0 {
		return 0
	}
	return sum / weight
}
