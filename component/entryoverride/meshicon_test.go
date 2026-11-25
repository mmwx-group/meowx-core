package entryoverride

import (
	"strings"
	"testing"
)

func TestMeshIcon(t *testing.T) {
	t.Cleanup(func() { SetProxyIcon(false) })
	SetProxyIcon(false)
	if MeshIcon("tailscale0") != "" {
		t.Fatal("icon must be off by default")
	}
	SetProxyIcon(true)
	got := MeshIcon("tailscale0")
	if !strings.HasPrefix(got, "data:image/svg+xml,<svg ") || strings.ContainsAny(got, "#%") {
		t.Fatalf("icon = %s", got)
	}
	if !strings.Contains(got, "<title>喵窝：") {
		t.Fatalf("icon = %s", got)
	}
	for _, iface := range []string{"", "eth0", "tailscale1"} {
		if MeshIcon(iface) != "" {
			t.Fatalf("iface %q must not get the icon", iface)
		}
	}
}
