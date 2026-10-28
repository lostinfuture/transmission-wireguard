// Package supervisor is PID 1 for the transmission-wireguard image.
package supervisor

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
	"github.com/lostinfuture/transmission-wireguard/internal/wireguard"
)

// Config is the container contract for one run.
type Config struct {
	ConfigPath     string
	Dev            string
	Implementation string
	HandshakeWait  time.Duration
	Kill           bool
	IPv6           bool
	PeerDNS        bool
	Local          []netip.Prefix
	DropDefault    bool
	PUID           int
	PGID           int
	ApplyPerms     bool
	Home           string
	OpenFiles      int
	LogStdout      bool
	AllowUPnP      bool
	AllowScripts   bool
	RPCUser        string
	RPCPassword    string
	RPCPort        int
	HealthHost     string
	SelfHeal       bool
	Rustnet        bool
	RustnetRefresh int
	RustnetPcap    string
	RootWarned     bool
	WebHome        string
	// CacheMiB is nil when neither cache variable is set. Zero turns the cache off.
	CacheMiB *int
}

// Load reads the process environment.
func Load() (Config, error) {
	return LoadFrom(os.Environ())
}

// LoadFrom reads env in KEY=VALUE form.
func LoadFrom(env []string) (Config, error) {
	m := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	for _, name := range denied {
		if _, ok := m[name]; ok {
			return Config{}, fmt.Errorf("this image is not transmission-openvpn; unset %s", name)
		}
	}
	cfg := Config{
		Dev:            "wg0",
		ConfigPath:     "/etc/wireguard/wg0.conf",
		Implementation: "kernel",
		HandshakeWait:  30 * time.Second,
		Kill:           true,
		PeerDNS:        true,
		PUID:           1000,
		PGID:           1000,
		ApplyPerms:     true,
		Home:           "/config/transmission-home",
		OpenFiles:      8192,
		LogStdout:      true,
		RPCPort:        9091,
		RustnetRefresh: 5000,
	}
	name := strings.TrimSpace(m["WIREGUARD_CONFIG"])
	if name == "" {
		name = "wg0"
	}
	if err := wireguard.ValidDev(name); err != nil {
		return Config{}, err
	}
	cfg.Dev = name
	cfg.ConfigPath = "/etc/wireguard/" + name + ".conf"
	switch m["WG_IMPLEMENTATION"] {
	case "", "kernel":
	case "userspace":
		return Config{}, errors.New("WG_IMPLEMENTATION=userspace is not in this release")
	default:
		return Config{}, errors.New("WG_IMPLEMENTATION must be kernel or userspace")
	}
	if v := m["WG_HANDSHAKE_TIMEOUT"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 5 || n > 120 {
			return Config{}, fmt.Errorf("WG_HANDSHAKE_TIMEOUT must be an integer from 5 to 120")
		}
		cfg.HandshakeWait = time.Duration(n) * time.Second
	}
	var err error
	if cfg.Kill, err = boolEnv(m, "ENABLE_KILLSWITCH", true); err != nil {
		return Config{}, err
	}
	if cfg.IPv6, err = boolEnv(m, "ENABLE_IPV6", false); err != nil {
		return Config{}, err
	}
	if cfg.PeerDNS, err = boolEnv(m, "PEER_DNS", true); err != nil {
		return Config{}, err
	}
	if cfg.DropDefault, err = boolEnv(m, "DROP_DEFAULT_ROUTE", false); err != nil {
		return Config{}, err
	}
	if cfg.ApplyPerms, err = boolEnv(m, "GLOBAL_APPLY_PERMISSIONS", true); err != nil {
		return Config{}, err
	}
	if cfg.LogStdout, err = boolEnv(m, "LOG_TO_STDOUT", true); err != nil {
		return Config{}, err
	}
	if cfg.AllowUPnP, err = boolEnv(m, "ALLOW_UPNP", false); err != nil {
		return Config{}, err
	}
	if cfg.AllowScripts, err = boolEnv(m, "ALLOW_TORRENT_SCRIPTS", false); err != nil {
		return Config{}, err
	}
	if cfg.SelfHeal, err = boolEnv(m, "SELFHEAL", false); err != nil {
		return Config{}, err
	}
	if cfg.Rustnet, err = boolEnv(m, "ENABLE_RUSTNET", false); err != nil {
		return Config{}, err
	}
	if v := m["TRANSMISSION_HOME"]; v != "" {
		cfg.Home = v
	}
	if v := m["OPEN_FILES_LIMIT"]; v != "" {
		n, nerr := strconv.Atoi(v)
		if nerr != nil || n < 1 {
			return Config{}, fmt.Errorf("OPEN_FILES_LIMIT %q", v)
		}
		cfg.OpenFiles = n
	}
	cfg.HealthHost = m["HEALTH_CHECK_HOST"]
	cfg.RustnetRefresh = 5000
	if v := strings.TrimSpace(m["RUSTNET_REFRESH_MS"]); v != "" {
		n, nerr := strconv.Atoi(v)
		if nerr != nil || n < 1000 {
			return Config{}, fmt.Errorf("RUSTNET_REFRESH_MS must be an integer >= 1000")
		}
		cfg.RustnetRefresh = n
	}
	pcap, err := rustnetPcap(m["RUSTNET_PCAP"])
	if err != nil {
		return Config{}, err
	}
	cfg.RustnetPcap = pcap
	cfg.RPCUser = first(m["TRANSMISSION_RPC_USERNAME"], m["TRANSMISSION_RPC_USER"])
	cfg.RPCPassword = m["TRANSMISSION_RPC_PASSWORD"]
	if (cfg.RPCUser == "") != (cfg.RPCPassword == "") {
		return Config{}, errors.New("set both TRANSMISSION_RPC_USERNAME and TRANSMISSION_RPC_PASSWORD, or neither")
	}
	if v := m["TRANSMISSION_RPC_PORT"]; v != "" {
		n, nerr := strconv.Atoi(v)
		if nerr != nil || n < 1 || n > 65535 {
			return Config{}, fmt.Errorf("TRANSMISSION_RPC_PORT %q", v)
		}
		cfg.RPCPort = n
	}
	cache, err := applyCache(m)
	if err != nil {
		return Config{}, err
	}
	cfg.CacheMiB = cache
	puidSet := m["PUID"] != ""
	pgidSet := m["PGID"] != ""
	if puidSet {
		cfg.PUID, err = strconv.Atoi(m["PUID"])
		if err != nil || cfg.PUID < 0 {
			return Config{}, fmt.Errorf("PUID %q", m["PUID"])
		}
	}
	if pgidSet {
		cfg.PGID, err = strconv.Atoi(m["PGID"])
		if err != nil || cfg.PGID < 0 {
			return Config{}, fmt.Errorf("PGID %q", m["PGID"])
		}
	}
	if puidSet && !pgidSet {
		cfg.PGID = cfg.PUID
	}
	if pgidSet && !puidSet {
		cfg.PUID = cfg.PGID
	}
	cfg.RootWarned = cfg.PUID == 0
	local, err := parseNets(m["LOCAL_NETWORK"], cfg.IPv6)
	if err != nil {
		return Config{}, err
	}
	cfg.Local = local
	if m["TRANSMISSION_WEB_HOME"] == "" {
		home, err := webHome(m["TRANSMISSION_WEB_UI"])
		if err != nil {
			return Config{}, err
		}
		cfg.WebHome = home
	}
	return cfg, nil
}

// NoteRustnet logs once when Rustnet was requested and /usr/bin/rustnet is missing.
// v0.1.0 does not ship the binary. Callers continue either way.
func NoteRustnet(enabled bool) {
	if !enabled {
		return
	}
	if _, err := os.Stat("/usr/bin/rustnet"); err != nil {
		logx.Info("supervisor", "this arch has no Rustnet")
	}
}

var denied = []string{
	"ENABLE_UFW",
	"UFW_EXTRA_PORTS",
	"UFW_ALLOW_GW_NET",
	"CREATE_TUN_DEVICE",
	"OPENVPN_PROVIDER",
	"OPENVPN_CONFIG",
	"OPENVPN_USERNAME",
	"OPENVPN_PASSWORD",
	"OPENVPN_OPTS",
	"OPENVPN_DCO",
	"VPN_CONFIG_SOURCE",
	"GITHUB_CONFIG_SOURCE_REPO",
	"GITHUB_CONFIG_SOURCE_REVISION",
	"PORT_FORWARD",
	"DISABLE_PORT_UPDATER",
	"PIA_TOKEN",
	"NORDVPN_COUNTRY",
	"NORDVPN_CATEGORY",
	"NORDVPN_PROTOCOL",
}

func parseNets(raw string, ipv6 bool) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("LOCAL_NETWORK %q: %w", part, err)
		}
		// Lengths from 8 through 15 are legal. Run warns; a normal IPv6 /64 does not.
		if p.Bits() < 8 {
			return nil, fmt.Errorf("LOCAL_NETWORK %s is rejected", p)
		}
		if !ipv6 && !p.Addr().Is4() {
			return nil, fmt.Errorf("LOCAL_NETWORK %s is rejected: ipv6 is disabled", p)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

const floodWebHome = "/opt/transmission-ui/flood-for-transmission"
const transmissionicWebHome = "/opt/transmission-ui/transmissionic"

func webHome(v string) (string, error) {
	switch v {
	case "", "stock":
		return "", nil
	case "flood", "flood-for-transmission":
		return floodWebHome, nil
	case "transmissionic":
		return transmissionicWebHome, nil
	default:
		return "", fmt.Errorf("TRANSMISSION_WEB_UI=%q is not supported", v)
	}
}

func boolEnv(m map[string]string, key string, def bool) (bool, error) {
	v, ok := m[key]
	if !ok || v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", key)
	}
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func applyCache(m map[string]string) (*int, error) {
	mibRaw, hasMIB := m["TRANSMISSION_CACHE_SIZE_MIB"]
	mbRaw, hasMB := m["TRANSMISSION_CACHE_SIZE_MB"]
	if !hasMIB && !hasMB {
		return nil, nil
	}
	if hasMIB && hasMB && strings.TrimSpace(mibRaw) != strings.TrimSpace(mbRaw) {
		return nil, errors.New("TRANSMISSION_CACHE_SIZE_MIB and TRANSMISSION_CACHE_SIZE_MB disagree")
	}
	raw := mbRaw
	name := "TRANSMISSION_CACHE_SIZE_MB"
	if hasMIB {
		raw = mibRaw
		name = "TRANSMISSION_CACHE_SIZE_MIB"
	}
	n, err := parseCacheMiB(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &n, nil
}

func parseCacheMiB(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("want a non-negative integer, got %q", raw)
	}
	return n, nil
}

func rustnetPcap(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("RUSTNET_PCAP must be an absolute path under /config")
	}
	clean := filepath.Clean(raw)
	if !strings.HasPrefix(clean, "/config/") {
		return "", errors.New("RUSTNET_PCAP must be under /config")
	}
	return clean, nil
}
