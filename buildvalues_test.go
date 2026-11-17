package main

import (
	"slices"
	"strings"
	"testing"
)

// The build values (install.sh -ldflags -X from install.env) reach the config, the guide and the vault check.
func TestBuildValues(t *testing.T) {
	saved := []string{ownerName, allowFrom, controlItem}
	t.Cleanup(func() { ownerName, allowFrom, controlItem = saved[0], saved[1], saved[2] })

	if g := guideText(); strings.Contains(g, "(owner:") || !strings.Contains(g, `vault "Agents"`) || strings.Contains(g, "{") {
		t.Fatalf("default guide: %q", g[:200])
	}
	ownerName, allowFrom, controlItem = "Sam", "192.0.2.7, 192.0.2.8", "op://Ops/gate"
	if c := defaultConfig(); !slices.Equal(c.AllowFrom, []string{"192.0.2.7", "192.0.2.8", "127.0.0.1", "::1"}) || c.ControlItem != "op://Ops/gate" {
		t.Fatalf("config: %v %q", c.AllowFrom, c.ControlItem)
	}
	g := guideText()
	if !strings.Contains(g, "on this Mac (owner: Sam)") || !strings.Contains(g, `op://Ops/<item>/<field>`) || strings.Contains(g, "Agents") {
		t.Fatalf("guide: %q", g)
	}
	if v := groupRefs([]string{"op://Ops/a/b", "op://Other/c/d"}, true); v[0].Item != "a" || v[1].Item != "Other / c" {
		t.Fatalf("groupRefs: %+v", v)
	}
}
