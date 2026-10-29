// Package transmission merges settings.json and talks to the daemon's RPC port.
package transmission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
)

// Options are the container overrides applied after the user's file and env.
type Options struct {
	AllowUPnP     bool
	AllowScripts  bool
	RPCUser       string
	RPCPassword   string
	TunIPv4       string
	DownloadDir   string
	IncompleteDir string
	WatchDir      string
}

// Merge unions dump, then the user file, then TRANSMISSION_* env, then container defaults, then security overrides.
// message_level is not forced. Transmission 4.1's info level is 4; 2 is error.
func Merge(dump, user map[string]any, env []string, opt Options) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range dump {
		out[snake(k)] = v
	}
	for k, v := range user {
		out[snake(k)] = v
	}
	// Transmission 4.1 reads cache_size_mib. snake("cache-size-mb") is cache_size_mb, which it ignores.
	promoteCache(out, user)
	em := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			em[k] = v
		}
	}
	if err := applyCacheEnv(out, em); err != nil {
		return nil, err
	}
	envSet := map[string]bool{}
	for key := range out {
		if isCacheKey(key) {
			continue
		}
		name := envName(key)
		raw, ok := em[name]
		if !ok {
			continue
		}
		sample := out[key]
		if d, ok := dump[key]; ok {
			sample = d
		}
		val, err := coerce(sample, raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		set(out, key, val)
		envSet[key] = true
		envSet[alternate(key)] = true
	}
	defaults := []struct {
		key string
		val any
	}{
		{"download_dir", opt.dir(opt.DownloadDir, "/data/completed")},
		{"incomplete_dir", opt.dir(opt.IncompleteDir, "/data/incomplete")},
		{"incomplete_dir_enabled", true},
		{"watch_dir", opt.dir(opt.WatchDir, "/data/watch")},
		{"watch_dir_enabled", true},
	}
	for _, d := range defaults {
		if envSet[d.key] || envSet[alternate(d.key)] {
			continue
		}
		if !same(out[d.key], dump[d.key]) {
			continue
		}
		set(out, d.key, d.val)
	}
	if !envSet["rpc_whitelist_enabled"] && !envSet["rpc-whitelist-enabled"] && same(out["rpc_whitelist_enabled"], dump["rpc_whitelist_enabled"]) {
		if b, ok := out["rpc_whitelist_enabled"].(bool); !ok || b {
			set(out, "rpc_whitelist_enabled", false)
		}
	}
	if !opt.AllowUPnP {
		set(out, "port_forwarding_enabled", false)
	}
	set(out, "lpd_enabled", false)
	set(out, "rpc_bind_address", "0.0.0.0")
	if opt.TunIPv4 != "" {
		set(out, "bind_address_ipv4", opt.TunIPv4)
	}
	if !opt.AllowScripts {
		set(out, "script_torrent_done_enabled", false)
		set(out, "script_torrent_done_seeding_enabled", false)
		set(out, "script_torrent_added_enabled", false)
	}
	if opt.RPCUser != "" || opt.RPCPassword != "" {
		set(out, "rpc_authentication_required", true)
		if opt.RPCUser != "" {
			set(out, "rpc_username", opt.RPCUser)
		}
		if opt.RPCPassword != "" {
			set(out, "rpc_password", opt.RPCPassword)
		}
	}
	return out, nil
}

func (o Options) dir(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func envName(key string) string {
	return "TRANSMISSION_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

func isCacheKey(key string) bool {
	switch snake(key) {
	case "cache_size_mb", "cache_size_mib":
		return true
	default:
		return false
	}
}

// cacheFrom reads the disk-cache value from a settings object.
// Later keys win: obsolete cache_size_mb, then the 4.0 name cache-size-mb, then cache_size_mib.
func cacheFrom(m map[string]any) (any, bool) {
	var val any
	found := false
	for _, key := range []string{"cache_size_mb", "cache-size-mb", "cache-size-mib", "cache_size_mib"} {
		v, ok := m[key]
		if !ok {
			continue
		}
		val = v
		found = true
	}
	return val, found
}

func promoteCache(out, user map[string]any) {
	if v, ok := cacheFrom(user); ok {
		out["cache_size_mib"] = v
	} else if _, ok := out["cache_size_mib"]; !ok {
		if v, ok := out["cache_size_mb"]; ok {
			out["cache_size_mib"] = v
		}
	}
	delete(out, "cache_size_mb")
	delete(out, "cache-size-mb")
	delete(out, "cache-size-mib")
}

func applyCacheEnv(out map[string]any, em map[string]string) error {
	mibRaw, hasMIB := em["TRANSMISSION_CACHE_SIZE_MIB"]
	mbRaw, hasMB := em["TRANSMISSION_CACHE_SIZE_MB"]
	if !hasMIB && !hasMB {
		return nil
	}
	if hasMIB && hasMB && strings.TrimSpace(mibRaw) != strings.TrimSpace(mbRaw) {
		return fmt.Errorf("TRANSMISSION_CACHE_SIZE_MIB and TRANSMISSION_CACHE_SIZE_MB disagree")
	}
	raw := mbRaw
	name := "TRANSMISSION_CACHE_SIZE_MB"
	if hasMIB {
		raw = mibRaw
		name = "TRANSMISSION_CACHE_SIZE_MIB"
	}
	n, err := parseCacheMiB(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	out["cache_size_mib"] = float64(n)
	delete(out, "cache_size_mb")
	return nil
}

func parseCacheMiB(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("want a non-negative integer, got %q", raw)
	}
	return n, nil
}

func snake(key string) string {
	return strings.ReplaceAll(key, "-", "_")
}

func alternate(key string) string {
	if strings.Contains(key, "-") {
		return strings.ReplaceAll(key, "-", "_")
	}
	return strings.ReplaceAll(key, "_", "-")
}

func set(m map[string]any, key string, val any) {
	m[key] = val
	alt := alternate(key)
	if _, ok := m[alt]; ok {
		m[alt] = val
	}
}

func same(a, b any) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

func coerce(sample any, raw string) (any, error) {
	switch sample.(type) {
	case bool:
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no":
			return false, nil
		default:
			return nil, fmt.Errorf("want a boolean, got %q", raw)
		}
	case float64:
		n, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("want a finite number, got %q", raw)
		}
		return n, nil
	case string:
		return raw, nil
	case []any:
		if strings.TrimSpace(raw) == "" {
			return []any{}, nil
		}
		parts := strings.Split(raw, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			out = append(out, strings.TrimSpace(p))
		}
		return out, nil
	default:
		return raw, nil
	}
}

// Int reads a JSON number from a merged settings object.
func Int(m map[string]any, key string, def int) int {
	v, ok := m[key]
	if !ok {
		v, ok = m[alternate(key)]
	}
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return def
		}
		return int(i)
	default:
		return def
	}
}

// DumpSettings runs the daemon's upstream defaults. It does not read the user's settings.json.
func DumpSettings(bin string) (map[string]any, error) {
	if bin == "" {
		bin = "transmission-daemon"
	}
	dir, err := mkdirTemp()
	if err != nil {
		return nil, err
	}
	defer removeAll(dir)
	cmd := exec.Command(bin, "--config-dir", dir, "--dump-settings")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("dump-settings: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	i := bytes.IndexByte(out, '{')
	if i < 0 {
		return nil, fmt.Errorf("dump-settings: no json")
	}
	var m map[string]any
	if err := json.Unmarshal(out[i:], &m); err != nil {
		return nil, err
	}
	return m, nil
}
