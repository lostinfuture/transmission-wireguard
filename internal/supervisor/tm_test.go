package supervisor

import "testing"

func TestRPCAuthUsable(t *testing.T) {
	if !rpcAuthUsable(false, "", "") {
		t.Fatal("auth off")
	}
	if !rpcAuthUsable(true, "{hash}", "secret") {
		t.Fatal("env password")
	}
	if rpcAuthUsable(true, "{hash}", "") {
		t.Fatal("hashed file password")
	}
	if rpcAuthUsable(true, "plain", "") {
		t.Fatal("empty env password")
	}
}

func TestReassertTargets(t *testing.T) {
	on := map[string]any{
		"port_forwarding_enabled":             true,
		"script_torrent_done_enabled":         true,
		"script_torrent_done_seeding_enabled": false,
		"script_torrent_added_enabled":        false,
	}
	pf, scripts := reassertTargets(false, false, on)
	if !pf || !scripts {
		t.Fatalf("both off: pf=%v scripts=%v", pf, scripts)
	}
	pf, scripts = reassertTargets(true, false, on)
	if pf || !scripts {
		t.Fatalf("upnp allowed: pf=%v scripts=%v", pf, scripts)
	}
	pf, scripts = reassertTargets(false, true, on)
	if !pf || scripts {
		t.Fatalf("scripts allowed: pf=%v scripts=%v", pf, scripts)
	}
	pf, scripts = reassertTargets(true, true, on)
	if pf || scripts {
		t.Fatalf("both allowed: pf=%v scripts=%v", pf, scripts)
	}
	off := map[string]any{"port_forwarding_enabled": false}
	pf, scripts = reassertTargets(false, false, off)
	if pf || scripts {
		t.Fatalf("already off: pf=%v scripts=%v", pf, scripts)
	}
}

func TestChildEnvStripsKeys(t *testing.T) {
	in := []string{
		"LOCAL_NETWORK=192.168.1.0/24",
		"TRANSMISSION_RPC_PASSWORD=secret",
		"WIREGUARD_PRIVATE_KEY=abc",
		"WG_PRESHARED=abc",
		"PSK=abc",
		"PATH=/usr/bin",
	}
	got := childEnv(in)
	joined := ""
	for _, e := range got {
		joined += e + "\n"
	}
	if !containsAll(joined, "LOCAL_NETWORK=192.168.1.0/24", "PATH=/usr/bin") {
		t.Fatal(joined)
	}
	if containsAny(joined, "PASSWORD", "PRIVATE", "PRESHARED", "PSK=") {
		t.Fatal(joined)
	}
}

func TestHandshakeNeedsRefresh(t *testing.T) {
	if !handshakeNeedsRefresh(0, 1_000) {
		t.Fatal("zero")
	}
	if handshakeNeedsRefresh(1_000, 1_100) {
		t.Fatal("fresh")
	}
	if !handshakeNeedsRefresh(1_000, 1_181) {
		t.Fatal("stale")
	}
	if handshakeNeedsRefresh(1_000, 1_180) {
		t.Fatal("age 180 is still fresh")
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !contains(s, p) {
			return false
		}
	}
	return true
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if contains(s, p) {
			return true
		}
	}
	return false
}

func contains(s, part string) bool {
	return len(part) == 0 || (len(s) >= len(part) && (s == part || len(find(s, part)) > 0))
}

func find(s, part string) string {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return s[i:]
		}
	}
	return ""
}
