package transmission

import "testing"

func TestMerge(t *testing.T) {
	dump := map[string]any{
		"download_dir":                "/root/Downloads",
		"incomplete_dir":              "/root/Downloads",
		"incomplete_dir_enabled":      false,
		"watch_dir":                   "",
		"watch_dir_enabled":           false,
		"message_level":               float64(4),
		"rpc_whitelist":               []any{"127.0.0.1", "::1"},
		"rpc_whitelist_enabled":       true,
		"port_forwarding_enabled":     true,
		"lpd_enabled":                 true,
		"rpc_port":                    float64(9091),
		"peer_port":                   float64(51413),
		"rpc_authentication_required": false,
		"script_torrent_done_enabled": false,
		"rpc-whitelist-enabled":       true,
	}
	user := map[string]any{
		"download_dir": "/data/media",
	}
	env := []string{
		"TRANSMISSION_RPC_WHITELIST=127.0.0.1,192.168.1.*",
		"TRANSMISSION_MESSAGE_LEVEL=2",
		"TRANSMISSION_RPC_PASSWORD=secret-value",
	}
	got, err := Merge(dump, user, env, Options{TunIPv4: "10.8.0.2", RPCPassword: "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if got["download_dir"] != "/data/media" {
		t.Fatalf("download_dir = %#v", got["download_dir"])
	}
	if got["incomplete_dir"] != "/data/incomplete" || got["watch_dir"] != "/data/watch" || got["watch_dir_enabled"] != true {
		t.Fatalf("dirs = %#v %#v %#v", got["incomplete_dir"], got["watch_dir"], got["watch_dir_enabled"])
	}
	if got["message_level"] != float64(2) {
		t.Fatalf("explicit env should still apply, message_level=%#v", got["message_level"])
	}
	wl := got["rpc_whitelist"].([]any)
	if len(wl) != 2 || wl[0] != "127.0.0.1" || wl[1] != "192.168.1.*" {
		t.Fatalf("whitelist = %#v", wl)
	}
	if got["rpc_whitelist_enabled"] != false {
		t.Fatalf("whitelist enabled = %#v", got["rpc_whitelist_enabled"])
	}
	if _, ok := got["rpc-whitelist-enabled"]; ok {
		t.Fatal("kebab key survived the merge")
	}
	if got["port_forwarding_enabled"] != false || got["lpd_enabled"] != false {
		t.Fatal("upnp or lpd left on")
	}
	if got["bind_address_ipv4"] != "10.8.0.2" || got["rpc_bind_address"] != "0.0.0.0" {
		t.Fatalf("bind = %#v %#v", got["bind_address_ipv4"], got["rpc_bind_address"])
	}
	if got["rpc_authentication_required"] != true || got["rpc_password"] != "secret-value" {
		t.Fatal("auth was not forced")
	}
	if got["script_torrent_done_enabled"] != false {
		t.Fatal("script hook left on")
	}
	if Int(got, "peer_port", 0) != 51413 || Int(got, "rpc_port", 0) != 9091 {
		t.Fatalf("ports rpc=%d peer=%d", Int(got, "rpc_port", 0), Int(got, "peer_port", 0))
	}
}

func TestMergeKebabUser(t *testing.T) {
	dump := map[string]any{
		"download_dir":           "/root/Downloads",
		"incomplete_dir":         "/root/Downloads",
		"incomplete_dir_enabled": false,
		"watch_dir":              "",
		"watch_dir_enabled":      false,
		"rpc_whitelist_enabled":  true,
		"rpc_port":               float64(9091),
	}
	user := map[string]any{
		"download-dir": "/media/torrents",
		"rpc-port":     float64(8080),
	}
	got, err := Merge(dump, user, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["download_dir"] != "/media/torrents" {
		t.Fatalf("download_dir = %#v", got["download_dir"])
	}
	if _, ok := got["download-dir"]; ok {
		t.Fatal("kebab download-dir was kept")
	}
	if Int(got, "rpc_port", 0) != 8080 {
		t.Fatalf("rpc_port = %d", Int(got, "rpc_port", 0))
	}
}

func TestMergeRejectsNonFinite(t *testing.T) {
	dump := map[string]any{"message_level": float64(4)}
	if _, err := Merge(dump, nil, []string{"TRANSMISSION_MESSAGE_LEVEL=NaN"}, Options{}); err == nil {
		t.Fatal("expected NaN rejection")
	}
	if _, err := Merge(dump, nil, []string{"TRANSMISSION_MESSAGE_LEVEL=+Inf"}, Options{}); err == nil {
		t.Fatal("expected Inf rejection")
	}
}

func TestMergeCacheFromLegacyName(t *testing.T) {
	dump := cacheDump()
	user := map[string]any{"cache-size-mb": float64(64), "cache_size_mb": float64(4)}
	got, err := Merge(dump, user, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["cache_size_mib"] != float64(64) {
		t.Fatalf("cache_size_mib = %#v", got["cache_size_mib"])
	}
	if _, ok := got["cache_size_mb"]; ok {
		t.Fatal("obsolete cache_size_mb was kept")
	}
	if _, ok := got["cache-size-mb"]; ok {
		t.Fatal("kebab cache-size-mb was kept")
	}
}

func TestMergeCacheCanonicalWins(t *testing.T) {
	dump := cacheDump()
	user := map[string]any{"cache-size-mb": float64(4), "cache_size_mib": float64(512)}
	got, err := Merge(dump, user, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["cache_size_mib"] != float64(512) {
		t.Fatalf("cache_size_mib = %#v", got["cache_size_mib"])
	}
}

func TestMergeCacheEnv(t *testing.T) {
	dump := cacheDump()
	user := map[string]any{"cache-size-mb": float64(4)}
	got, err := Merge(dump, user, []string{"TRANSMISSION_CACHE_SIZE_MIB=512"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["cache_size_mib"] != float64(512) {
		t.Fatalf("cache_size_mib = %#v", got["cache_size_mib"])
	}
	got, err = Merge(dump, user, []string{"TRANSMISSION_CACHE_SIZE_MB=256"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["cache_size_mib"] != float64(256) {
		t.Fatalf("alias cache_size_mib = %#v", got["cache_size_mib"])
	}
	got, err = Merge(dump, nil, []string{"TRANSMISSION_CACHE_SIZE_MIB=0"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["cache_size_mib"] != float64(0) {
		t.Fatalf("zero cache = %#v", got["cache_size_mib"])
	}
}

func TestMergeCacheEnvRejects(t *testing.T) {
	dump := cacheDump()
	if _, err := Merge(dump, nil, []string{"TRANSMISSION_CACHE_SIZE_MIB=-1"}, Options{}); err == nil {
		t.Fatal("expected negative rejection")
	}
	if _, err := Merge(dump, nil, []string{"TRANSMISSION_CACHE_SIZE_MIB=512.5"}, Options{}); err == nil {
		t.Fatal("expected fractional rejection")
	}
	if _, err := Merge(dump, nil, []string{"TRANSMISSION_CACHE_SIZE_MIB=512", "TRANSMISSION_CACHE_SIZE_MB=256"}, Options{}); err == nil {
		t.Fatal("expected disagreeing cache env rejection")
	}
	got, err := Merge(dump, nil, []string{"TRANSMISSION_CACHE_SIZE_MIB=512", "TRANSMISSION_CACHE_SIZE_MB=512"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["cache_size_mib"] != float64(512) {
		t.Fatalf("agreeing env cache_size_mib = %#v", got["cache_size_mib"])
	}
}

func cacheDump() map[string]any {
	return map[string]any{
		"cache-size-mb":          float64(4),
		"download_dir":           "/root/Downloads",
		"incomplete_dir":         "/root/Downloads",
		"incomplete_dir_enabled": false,
		"watch_dir":              "",
		"watch_dir_enabled":      false,
		"rpc_whitelist_enabled":  true,
	}
}

func TestMessageLevelNotImplied(t *testing.T) {
	dump := map[string]any{"message_level": float64(4), "download_dir": "/root/Downloads", "incomplete_dir": "/root/Downloads", "incomplete_dir_enabled": false, "watch_dir": "", "watch_dir_enabled": false, "rpc_whitelist_enabled": true}
	got, err := Merge(dump, nil, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got["message_level"] != float64(4) {
		t.Fatalf("message_level = %#v", got["message_level"])
	}
	if got["download_dir"] != "/data/completed" {
		t.Fatalf("download_dir = %#v", got["download_dir"])
	}
}
