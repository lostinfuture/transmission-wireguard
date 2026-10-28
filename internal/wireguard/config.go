// Package wireguard reads one mounted wg-quick-shaped config.
// The supervisor applies it with ip and wg. It does not run wg-quick.
package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

const maxConfigBytes = 64 * 1024

// Config is one accepted WireGuard file. Key fields are the 44-character
// base64 line. They are never written to a log.
type Config struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	Search     []string
	MTU        *int
	ListenPort *int
	PublicKey  string
	// PresharedKey is empty when the file does not set one.
	PresharedKey string
	EndpointHost string
	EndpointPort int
	AllowedIPs   []netip.Prefix
	// Keepalive is nil when the key is absent. Zero is a set value.
	Keepalive *int
}

// ValidDev reports whether name can be a WireGuard interface.
// Length is 1–15 and characters are [A-Za-z0-9_-].
func ValidDev(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("bad device %q", name)
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return fmt.Errorf("bad device %q", name)
		}
	}
	return nil
}

// Open reads dir/name.conf. dir and the file must be real root-owned nodes,
// not group- or other-writable, and the file must be at most 64 KiB.
// A symlink is rejected. ipv6 is ENABLE_IPV6.
func Open(dir, name string, ipv6 bool) (Config, error) {
	if err := ValidDev(name); err != nil {
		return Config{}, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return Config{}, err
	}
	if err := checkNode(st, true); err != nil {
		return Config{}, fmt.Errorf("%s: %w", dir, err)
	}
	path := filepath.Join(dir, name+".conf")
	st, err = os.Lstat(path)
	if err != nil {
		return Config{}, err
	}
	if err := checkNode(st, false); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := checkSize(st.Size()); err != nil {
		return Config{}, err
	}
	b, err := readNoFollow(path, maxConfigBytes)
	if err != nil {
		return Config{}, err
	}
	return Parse(string(b), dir, ipv6)
}

// Parse reads conf text. keyDir is the mount path key files must live under.
// Inline keys do not use it. ipv6 is ENABLE_IPV6; an IPv6 literal while it is
// false is an error. The MTU floor of 1280 is not applied here.
func Parse(text, keyDir string, ipv6 bool) (Config, error) {
	if strings.HasPrefix(text, "\uFEFF") {
		return Config{}, errors.New("config starts with a UTF-8 BOM")
	}
	if !utf8.ValidString(text) {
		return Config{}, errors.New("config is not utf-8")
	}
	if len(text) > maxConfigBytes {
		return Config{}, errors.New("config exceeds 64 KiB")
	}
	b := builder{ipv6: ipv6, keyDir: keyDir, seen: map[string]bool{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") {
			if err := b.section(trim); err != nil {
				return Config{}, err
			}
			continue
		}
		key, val, ok := strings.Cut(trim, "=")
		if !ok {
			return Config{}, fmt.Errorf("expected key = value, got %q", trim)
		}
		if err := b.key(strings.TrimSpace(key), strings.TrimSpace(val)); err != nil {
			return Config{}, err
		}
	}
	if err := b.finish(); err != nil {
		return Config{}, err
	}
	return b.cfg, nil
}

const (
	secNone = iota
	secInterface
	secPeer
)

type builder struct {
	cfg    Config
	ipv6   bool
	keyDir string
	sec    int
	seen   map[string]bool
}

func (b *builder) section(name string) error {
	switch name {
	case "[Interface]":
		if b.sec != secNone {
			return errors.New("config needs exactly one [Interface]")
		}
		b.sec = secInterface
	case "[Peer]":
		if b.sec == secPeer {
			return errors.New("second peer")
		}
		if b.sec != secInterface {
			return errors.New("config needs one [Interface] before [Peer]")
		}
		b.sec = secPeer
	default:
		return fmt.Errorf("unknown section %s", name)
	}
	return nil
}

func (b *builder) key(key, val string) error {
	switch key {
	case "Table", "PostUp", "PostDown", "PreUp", "PreDown", "SaveConfig", "FwMark":
		return fmt.Errorf("%s is not allowed", key)
	}
	if strings.Contains(val, "#") {
		return fmt.Errorf("%s: comment in value", key)
	}
	switch b.sec {
	case secInterface:
		return b.iface(key, val)
	case secPeer:
		return b.peer(key, val)
	default:
		return errors.New("key outside a section")
	}
}

func (b *builder) iface(key, val string) error {
	switch key {
	case "PrivateKey":
		if err := b.once(key); err != nil {
			return err
		}
		got, err := normalizeKey(val, b.keyDir)
		if err != nil {
			return fmt.Errorf("private key: %w", err)
		}
		b.cfg.PrivateKey = got
	case "Address":
		addrs, err := parseAddresses(val, b.ipv6)
		if err != nil {
			return err
		}
		b.cfg.Addresses = append(b.cfg.Addresses, addrs...)
	case "DNS":
		addrs, search, err := parseDNS(val, b.ipv6)
		if err != nil {
			return err
		}
		b.cfg.DNS = append(b.cfg.DNS, addrs...)
		b.cfg.Search = append(b.cfg.Search, search...)
	case "MTU":
		if err := b.once(key); err != nil {
			return err
		}
		mtu, err := parseInt(val)
		if err != nil || mtu < 576 || mtu > 1500 {
			return fmt.Errorf("mtu %q is outside 576-1500", val)
		}
		b.cfg.MTU = &mtu
	case "ListenPort":
		if err := b.once(key); err != nil {
			return err
		}
		port, err := parsePort(val)
		if err != nil {
			return fmt.Errorf("listen port: %w", err)
		}
		b.cfg.ListenPort = &port
	case "PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive":
		return fmt.Errorf("%s is not valid in [Interface]", key)
	default:
		return fmt.Errorf("unknown key %s", key)
	}
	return nil
}

func (b *builder) peer(key, val string) error {
	switch key {
	case "PublicKey":
		if err := b.once(key); err != nil {
			return err
		}
		got, err := decodeKeyLine(val)
		if err != nil {
			return fmt.Errorf("public key: %w", err)
		}
		b.cfg.PublicKey = got
	case "PresharedKey":
		if err := b.once(key); err != nil {
			return err
		}
		got, err := normalizeKey(val, b.keyDir)
		if err != nil {
			return fmt.Errorf("preshared key: %w", err)
		}
		b.cfg.PresharedKey = got
	case "Endpoint":
		if err := b.once(key); err != nil {
			return err
		}
		host, port, err := parseEndpoint(val, b.ipv6)
		if err != nil {
			return err
		}
		b.cfg.EndpointHost = host
		b.cfg.EndpointPort = port
	case "AllowedIPs":
		prefixes, err := parseAllowed(val, b.ipv6)
		if err != nil {
			return err
		}
		b.cfg.AllowedIPs = append(b.cfg.AllowedIPs, prefixes...)
	case "PersistentKeepalive":
		if err := b.once(key); err != nil {
			return err
		}
		keep, err := parseInt(val)
		if err != nil || keep > 65535 {
			return fmt.Errorf("persistent keepalive %q", val)
		}
		b.cfg.Keepalive = &keep
	case "PrivateKey", "Address", "DNS", "MTU", "ListenPort":
		return fmt.Errorf("%s is not valid in [Peer]", key)
	default:
		return fmt.Errorf("unknown key %s", key)
	}
	return nil
}

func (b *builder) once(key string) error {
	if b.seen[key] {
		return fmt.Errorf("duplicate key %s", key)
	}
	b.seen[key] = true
	return nil
}

func (b *builder) finish() error {
	if b.sec != secPeer {
		return errors.New("config needs one [Interface] and one [Peer]")
	}
	if b.cfg.PrivateKey == "" {
		return errors.New("private key is required")
	}
	if len(b.cfg.Addresses) == 0 {
		return errors.New("address is required")
	}
	if !has4(b.cfg.Addresses) {
		return errors.New("address needs an ipv4")
	}
	if b.cfg.PublicKey == "" {
		return errors.New("public key is required")
	}
	if b.cfg.EndpointHost == "" || b.cfg.EndpointPort == 0 {
		return errors.New("endpoint is required")
	}
	if len(b.cfg.AllowedIPs) == 0 {
		return errors.New("allowed ips is required")
	}
	return nil
}

func has4(ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Addr().Is4() {
			return true
		}
	}
	return false
}

func parseAddresses(val string, ipv6 bool) ([]netip.Prefix, error) {
	parts, err := splitList(val)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("address is required")
	}
	out := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		p, err := parseHostPrefix(part)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", part, err)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("address %s has prefix length 0", p)
		}
		if err := reject6(ipv6, p.Addr(), "address"); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseAllowed(val string, ipv6 bool) ([]netip.Prefix, error) {
	parts, err := splitList(val)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("allowed ips is required")
	}
	out := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		p, err := parseHostPrefix(part)
		if err != nil {
			return nil, fmt.Errorf("allowed ips %q: %w", part, err)
		}
		if err := reject6(ipv6, p.Addr(), "allowed ip"); err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func parseDNS(val string, ipv6 bool) ([]netip.Addr, []string, error) {
	parts, err := splitList(val)
	if err != nil {
		return nil, nil, err
	}
	var addrs []netip.Addr
	var search []string
	for _, part := range parts {
		if strings.ContainsAny(part, " \t/") {
			return nil, nil, fmt.Errorf("dns %q is not an ip or a domain", part)
		}
		if addr, err := netip.ParseAddr(part); err == nil {
			if err := reject6(ipv6, addr, "dns"); err != nil {
				return nil, nil, err
			}
			addrs = append(addrs, addr.Unmap())
			continue
		}
		search = append(search, part)
	}
	return addrs, search, nil
}

func splitList(val string) ([]string, error) {
	if strings.TrimSpace(val) == "" {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out, nil
}

func parseHostPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if !addr.Is4() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

func reject6(ipv6 bool, addr netip.Addr, what string) error {
	if ipv6 || addr.Is4() {
		return nil
	}
	return fmt.Errorf("ipv6 is disabled: %s %s", what, addr)
}

func parseEndpoint(val string, ipv6 bool) (string, int, error) {
	host, portStr, err := net.SplitHostPort(val)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("endpoint %q needs a host and port", val)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("endpoint port: %w", err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := reject6(ipv6, addr, "endpoint"); err != nil {
			return "", 0, err
		}
		return addr.String(), port, nil
	}
	return host, port, nil
}

func parsePort(val string) (int, error) {
	n, err := parseInt(val)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q", val)
	}
	return n, nil
}

func parseInt(s string) (int, error) {
	if s == "" || len(s) > 6 {
		return 0, fmt.Errorf("bad integer %q", s)
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("bad integer %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func normalizeKey(val, keyDir string) (string, error) {
	if strings.HasPrefix(val, "/") {
		if err := underDir(keyDir, val); err != nil {
			return "", err
		}
		body, err := readKeyFile(keyDir, val)
		if err != nil {
			return "", err
		}
		val = body
	}
	return decodeKeyLine(val)
}

func decodeKeyLine(val string) (string, error) {
	val = stripOneNewline(val)
	if strings.ContainsAny(val, "\r\n") {
		return "", errors.New("key must be a single line")
	}
	if len(val) != 44 {
		return "", errors.New("key must be 44 base64 characters")
	}
	raw, err := base64.StdEncoding.DecodeString(val)
	if err != nil || len(raw) != 32 {
		return "", errors.New("key must decode to 32 bytes")
	}
	return val, nil
}

func stripOneNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	if strings.HasSuffix(s, "\r") {
		s = s[:len(s)-1]
	}
	return s
}

func underDir(dir, path string) error {
	if dir == "" || !filepath.IsAbs(path) {
		return errors.New("key path must be an absolute path under the config directory")
	}
	dir = filepath.Clean(dir)
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(dir, clean)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("key path %s is outside %s", path, dir)
	}
	return nil
}

func readKeyFile(dir, path string) (string, error) {
	st, err := lstatWithin(dir, path)
	if err != nil {
		return "", err
	}
	if err := checkNode(st, false); err != nil {
		return "", err
	}
	if st.Size() > 128 {
		return "", errors.New("key must be 44 base64 characters")
	}
	b, err := readNoFollow(path, 128)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// lstatWithin rejects a symlink at any component under dir, including the file.
func lstatWithin(dir, full string) (os.FileInfo, error) {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(full))
	if err != nil {
		return nil, err
	}
	cur := filepath.Clean(dir)
	var st os.FileInfo
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		st, err = os.Lstat(cur)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink")
		}
	}
	if st == nil {
		return nil, errors.New("key path must be an absolute path under the config directory")
	}
	return st, nil
}

func checkSize(n int64) error {
	if n > maxConfigBytes {
		return errors.New("config exceeds 64 KiB")
	}
	return nil
}

func checkNode(st os.FileInfo, wantDir bool) error {
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	if wantDir {
		if !st.IsDir() {
			return errors.New("not a directory")
		}
	} else if !st.Mode().IsRegular() {
		return errors.New("not a file")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return errors.New("not owned by root")
	}
	if st.Mode()&0o022 != 0 {
		return errors.New("writable by group or other")
	}
	return nil
}

func readNoFollow(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("symlink")
		}
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("config exceeds 64 KiB")
	}
	return b, nil
}
