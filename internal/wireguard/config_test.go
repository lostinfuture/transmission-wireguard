package wireguard

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var (
	kPriv string
	kPub  string
	kPsk  string
)

func init() {
	kPriv = keyByte(1)
	kPub = keyByte(2)
	kPsk = keyByte(3)
}

func keyByte(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func baseConf() string {
	return "[Interface]\nPrivateKey = " + kPriv + "\nAddress = 10.67.0.2/32\n\n[Peer]\nPublicKey = " + kPub + "\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func TestZeroKeyLine(t *testing.T) {
	got := keyByte(0)
	want := strings.Repeat("A", 43) + "="
	if got != want || len(got) != 44 {
		t.Fatal("zero key is not the 44-character line")
	}
	raw, err := base64.StdEncoding.DecodeString(got)
	if err != nil || len(raw) != 32 {
		t.Fatal("zero key does not decode to 32 bytes")
	}
}

func TestParseMinimal(t *testing.T) {
	cfg := mustParse(t, baseConf(), false)
	requireKey(t, "private", cfg.PrivateKey, kPriv)
	requireKey(t, "public", cfg.PublicKey, kPub)
	if cfg.PresharedKey != "" || cfg.MTU != nil || cfg.ListenPort != nil || cfg.Keepalive != nil {
		t.Fatal("optional fields were set")
	}
	if cfg.EndpointHost != "203.0.113.10" || cfg.EndpointPort != 51820 {
		t.Fatalf("endpoint %s:%d", cfg.EndpointHost, cfg.EndpointPort)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.67.0.2/32" {
		t.Fatal(cfg.Addresses)
	}
	if len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Fatal(cfg.AllowedIPs)
	}
}

func TestParseAccepts(t *testing.T) {
	body := "" +
		"# comment\n" +
		"; also a comment\n" +
		"\n" +
		"[Interface]\r\n" +
		"PrivateKey=" + kPriv + "\r\n" +
		"Address = 10.67.0.2, 10.67.0.3/24\r\n" +
		"Address = 10.8.0.1/16\r\n" +
		"DNS = 10.64.0.1, home.arpa\r\n" +
		"DNS = lan.example\r\n" +
		"MTU = 1200\r\n" +
		"ListenPort = 51820\r\n" +
		"\r\n" +
		"[Peer]\r\n" +
		"PublicKey = " + kPub + "\r\n" +
		"PresharedKey = " + kPsk + "\r\n" +
		"Endpoint = VPN.Example:51820\r\n" +
		"AllowedIPs = 0.0.0.0/0, 10.1.2.3/24\r\n" +
		"AllowedIPs = 10.9.0.0/16\r\n" +
		"PersistentKeepalive = 25\r\n"
	cfg := mustParse(t, body, false)
	requireKey(t, "psk", cfg.PresharedKey, kPsk)
	if cfg.EndpointHost != "VPN.Example" || cfg.EndpointPort != 51820 {
		t.Fatalf("endpoint %s:%d", cfg.EndpointHost, cfg.EndpointPort)
	}
	if cfg.MTU == nil || *cfg.MTU != 1200 {
		t.Fatalf("mtu %v", cfg.MTU)
	}
	if cfg.ListenPort == nil || *cfg.ListenPort != 51820 {
		t.Fatalf("port %v", cfg.ListenPort)
	}
	if cfg.Keepalive == nil || *cfg.Keepalive != 25 {
		t.Fatalf("keepalive %v", cfg.Keepalive)
	}
	gotAddr := make([]string, len(cfg.Addresses))
	for i, p := range cfg.Addresses {
		gotAddr[i] = p.String()
	}
	if strings.Join(gotAddr, ",") != "10.67.0.2/32,10.67.0.3/24,10.8.0.1/16" {
		t.Fatal(gotAddr)
	}
	gotAllow := make([]string, len(cfg.AllowedIPs))
	for i, p := range cfg.AllowedIPs {
		gotAllow[i] = p.String()
	}
	if strings.Join(gotAllow, ",") != "0.0.0.0/0,10.1.2.0/24,10.9.0.0/16" {
		t.Fatal(gotAllow)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "10.64.0.1" {
		t.Fatal(cfg.DNS)
	}
	if strings.Join(cfg.Search, ",") != "home.arpa,lan.example" {
		t.Fatal(cfg.Search)
	}
}

func TestParseKeepaliveZero(t *testing.T) {
	cfg := mustParse(t, strings.Replace(baseConf(), "AllowedIPs = 0.0.0.0/0\n", "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 0\n", 1), false)
	if cfg.Keepalive == nil || *cfg.Keepalive != 0 {
		t.Fatal(cfg.Keepalive)
	}
}

func TestParseMTUBounds(t *testing.T) {
	for _, n := range []string{"576", "1200", "1500"} {
		body := strings.Replace(baseConf(), "Address = 10.67.0.2/32\n", "Address = 10.67.0.2/32\nMTU = "+n+"\n", 1)
		cfg := mustParse(t, body, true)
		if cfg.MTU == nil || *cfg.MTU < 576 || *cfg.MTU > 1500 {
			t.Fatalf("mtu %s -> %v", n, cfg.MTU)
		}
	}
}

func TestParseBareIPv6(t *testing.T) {
	body := "" +
		"[Interface]\n" +
		"PrivateKey = " + kPriv + "\n" +
		"Address = 10.67.0.2\n" +
		"Address = 2001:db8::5\n" +
		"DNS = 2001:db8::53\n" +
		"\n[Peer]\n" +
		"PublicKey = " + kPub + "\n" +
		"Endpoint = [2001:db8::10]:51820\n" +
		"AllowedIPs = ::/0, 2001:db8:1::1\n"
	cfg := mustParse(t, body, true)
	got := []string{}
	for _, p := range cfg.Addresses {
		got = append(got, p.String())
	}
	if strings.Join(got, ",") != "10.67.0.2/32,2001:db8::5/128" {
		t.Fatal(got)
	}
	if cfg.EndpointHost != "2001:db8::10" || cfg.EndpointPort != 51820 {
		t.Fatalf("endpoint %s:%d", cfg.EndpointHost, cfg.EndpointPort)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "2001:db8::53" {
		t.Fatal(cfg.DNS)
	}
	allow := []string{}
	for _, p := range cfg.AllowedIPs {
		allow = append(allow, p.String())
	}
	if strings.Join(allow, ",") != "::/0,2001:db8:1::1/128" {
		t.Fatal(allow)
	}
}

func TestParseRejects(t *testing.T) {
	peer := "PublicKey = " + kPub + "\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n"
	iface := "PrivateKey = " + kPriv + "\nAddress = 10.67.0.2/32\n"
	cases := []struct {
		name string
		body string
		v6   bool
		want string
	}{
		{"second peer", baseConf() + "[Peer]\n" + peer, false, "second peer"},
		{"second interface", "[Interface]\n" + iface + "[Interface]\n" + iface + "[Peer]\n" + peer, false, "one [Interface]"},
		{"peer first", "[Peer]\n" + peer + "[Interface]\n" + iface, false, "before [Peer]"},
		{"postup", strings.Replace(baseConf(), "[Peer]", "PostUp = iptables -A OUTPUT -j ACCEPT\n[Peer]", 1), false, "PostUp is not allowed"},
		{"preup", strings.Replace(baseConf(), "[Peer]", "PreUp = true\n[Peer]", 1), false, "PreUp is not allowed"},
		{"postdown", strings.Replace(baseConf(), "[Peer]", "PostDown = true\n[Peer]", 1), false, "PostDown is not allowed"},
		{"predown", strings.Replace(baseConf(), "[Peer]", "PreDown = true\n[Peer]", 1), false, "PreDown is not allowed"},
		{"table off", strings.Replace(baseConf(), "[Peer]", "Table = off\n[Peer]", 1), false, "Table is not allowed"},
		{"table auto", strings.Replace(baseConf(), "[Peer]", "Table = auto\n[Peer]", 1), false, "Table is not allowed"},
		{"savconfig false", strings.Replace(baseConf(), "[Peer]", "SaveConfig = false\n[Peer]", 1), false, "SaveConfig is not allowed"},
		{"savconfig true", strings.Replace(baseConf(), "[Peer]", "SaveConfig = true\n[Peer]", 1), false, "SaveConfig is not allowed"},
		{"fwmark", strings.Replace(baseConf(), "[Peer]", "FwMark = 51820\n[Peer]", 1), false, "FwMark is not allowed"},
		{"fwmark empty", strings.Replace(baseConf(), "[Peer]", "FwMark =\n[Peer]", 1), false, "FwMark is not allowed"},
		{"comment in value", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 10.67.0.2/32 # lan", 1), false, "comment in value"},
		{"bom", "\uFEFF" + baseConf(), false, "BOM"},
		{"utf8", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 10.67.0.2/32\xff", 1), false, "utf-8"},
		{"too big", strings.Repeat("a", maxConfigBytes+1), false, "64 KiB"},
		{"exact cap is not the size error", strings.Repeat("a", maxConfigBytes), false, "key = value"},
		{"duplicate private", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "PrivateKey = "+kPriv+"\nAddress = 10.67.0.2/32", 1), false, "duplicate key PrivateKey"},
		{"duplicate public", strings.Replace(baseConf(), "Endpoint =", "PublicKey = "+kPub+"\nEndpoint =", 1), false, "duplicate key PublicKey"},
		{"duplicate endpoint", strings.Replace(baseConf(), "AllowedIPs =", "Endpoint = 203.0.113.10:51820\nAllowedIPs =", 1), false, "duplicate key Endpoint"},
		{"duplicate mtu", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "MTU = 1400\nMTU = 1400\nAddress = 10.67.0.2/32", 1), false, "duplicate key MTU"},
		{"duplicate listen", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "ListenPort = 1\nListenPort = 2\nAddress = 10.67.0.2/32", 1), false, "duplicate key ListenPort"},
		{"duplicate keepalive", baseConf() + "PersistentKeepalive = 1\nPersistentKeepalive = 1\n", false, "duplicate key PersistentKeepalive"},
		{"duplicate psk", strings.Replace(baseConf(), "Endpoint =", "PresharedKey = "+kPsk+"\nPresharedKey = "+kPsk+"\nEndpoint =", 1), false, "duplicate key PresharedKey"},
		{"mtu low", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "MTU = 575\nAddress = 10.67.0.2/32", 1), false, "575"},
		{"mtu high", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "MTU = 1501\nAddress = 10.67.0.2/32", 1), false, "1501"},
		{"mtu junk", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "MTU = abc\nAddress = 10.67.0.2/32", 1), false, "abc"},
		{"listen 0", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "ListenPort = 0\nAddress = 10.67.0.2/32", 1), false, "listen port"},
		{"listen high", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "ListenPort = 65536\nAddress = 10.67.0.2/32", 1), false, "listen port"},
		{"keepalive high", baseConf() + "PersistentKeepalive = 65536\n", false, "keepalive"},
		{"short key", strings.Replace(baseConf(), kPriv, "aaaa", 1), false, "44 base64"},
		{"bad base64", strings.Replace(baseConf(), kPriv, strings.Repeat("A", 44), 1), false, "32 bytes"},
		{"raw-looking short", strings.Replace(baseConf(), kPriv, strings.Repeat("\x00", 32), 1), false, "44 base64"},
		{"address v6", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 2001:db8::1/128", 1), false, "ipv6 is disabled"},
		{"address bare v6", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 2001:db8::1", 1), false, "ipv6 is disabled"},
		{"dns v6", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 10.67.0.2/32\nDNS = 2001:db8::53", 1), false, "ipv6 is disabled"},
		{"allowed v6", strings.Replace(baseConf(), "AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0", 1), false, "ipv6 is disabled"},
		{"endpoint v6", strings.Replace(baseConf(), "Endpoint = 203.0.113.10:51820", "Endpoint = [2001:db8::1]:51820", 1), false, "ipv6 is disabled"},
		{"prefix 0", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 0.0.0.0/0", 1), false, "prefix length 0"},
		{"prefix 0 host", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 10.0.0.0/0", 1), false, "prefix length 0"},
		{"no port", strings.Replace(baseConf(), "Endpoint = 203.0.113.10:51820", "Endpoint = 203.0.113.10", 1), false, "host and port"},
		{"empty port host", strings.Replace(baseConf(), "Endpoint = 203.0.113.10:51820", "Endpoint = :51820", 1), false, "host and port"},
		{"port 0", strings.Replace(baseConf(), "Endpoint = 203.0.113.10:51820", "Endpoint = 203.0.113.10:0", 1), false, "endpoint port"},
		{"only v6 address", "[Interface]\nPrivateKey = " + kPriv + "\nAddress = 2001:db8::1/128\n\n[Peer]\n" + peer, true, "needs an ipv4"},
		{"no private", "[Interface]\nAddress = 10.67.0.2/32\n\n[Peer]\n" + peer, false, "private key is required"},
		{"no address", "[Interface]\nPrivateKey = " + kPriv + "\n\n[Peer]\n" + peer, false, "address is required"},
		{"no public", "[Interface]\n" + iface + "\n[Peer]\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\n", false, "public key is required"},
		{"no endpoint", "[Interface]\n" + iface + "\n[Peer]\nPublicKey = " + kPub + "\nAllowedIPs = 0.0.0.0/0\n", false, "endpoint is required"},
		{"no allowed", "[Interface]\n" + iface + "\n[Peer]\nPublicKey = " + kPub + "\nEndpoint = 203.0.113.10:51820\n", false, "allowed ips is required"},
		{"no sections", "# nothing\n", false, "one [Interface] and one [Peer]"},
		{"key outside", "PrivateKey = " + kPriv + "\n" + baseConf(), false, "outside a section"},
		{"no equals", strings.Replace(baseConf(), "[Peer]", "NotAKey\n[Peer]", 1), false, "key = value"},
		{"unknown key", strings.Replace(baseConf(), "[Peer]", "Foo = 1\n[Peer]", 1), false, "unknown key Foo"},
		{"unknown section", strings.Replace(baseConf(), "[Peer]", "[WireGuard]\n[Peer]", 1), false, "unknown section"},
		{"private in peer", baseConf() + "PrivateKey = " + kPriv + "\n", false, "not valid in [Peer]"},
		{"public in iface", strings.Replace(baseConf(), "[Peer]", "PublicKey = "+kPub+"\n[Peer]", 1), false, "not valid in [Interface]"},
		{"bad dns", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = 10.67.0.2/32\nDNS = 10.0.0.0/8", 1), false, "dns"},
		{"bad address", strings.Replace(baseConf(), "Address = 10.67.0.2/32", "Address = not-an-ip", 1), false, "address"},
		{"public path", strings.Replace(baseConf(), kPub, "/etc/wireguard/public", 1), false, "44 base64"},
		{"relative key", strings.Replace(baseConf(), kPriv, "privatekey", 1), false, "44 base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustReject(t, tc.body, tc.v6, tc.want)
		})
	}
}

func TestParseKeyPath(t *testing.T) {
	dir := t.TempDir()
	rejectIn := func(body, want string) {
		t.Helper()
		_, err := Parse(body, dir, false)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error %v, want substring %q", err, want)
		}
	}
	rejectIn(strings.Replace(baseConf(), kPriv, "/etc/passwd", 1), "outside")

	link := filepath.Join(dir, "k")
	if err := os.Symlink(filepath.Join(dir, "missing"), link); err != nil {
		t.Fatal(err)
	}
	rejectIn(strings.Replace(baseConf(), kPriv, link, 1), "symlink")

	sub := filepath.Join(dir, "sub")
	if err := os.Symlink(dir, sub); err != nil {
		t.Fatal(err)
	}
	rejectIn(strings.Replace(baseConf(), kPriv, filepath.Join(sub, "private"), 1), "symlink")

	pskLink := filepath.Join(dir, "psk")
	if err := os.Symlink(link, pskLink); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(baseConf(), "Endpoint =", "PresharedKey = "+pskLink+"\nEndpoint =", 1)
	rejectIn(body, "symlink")

	if os.Geteuid() != 0 {
		t.Skip("reading a root-owned key file requires root")
	}
	keyPath := filepath.Join(dir, "privatekey")
	if err := os.WriteFile(keyPath, []byte(kPriv+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(strings.Replace(baseConf(), kPriv, keyPath, 1), dir, false)
	if err != nil {
		t.Fatal(err)
	}
	requireKey(t, "private", cfg.PrivateKey, kPriv)

	pskPath := filepath.Join(dir, "presharedkey")
	if err := os.WriteFile(pskPath, []byte(kPsk+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body = strings.Replace(baseConf(), "Endpoint =", "PresharedKey = "+pskPath+"\nEndpoint =", 1)
	cfg, err = Parse(body, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	requireKey(t, "psk", cfg.PresharedKey, kPsk)

	raw := filepath.Join(dir, "raw")
	if err := os.WriteFile(raw, bytes.Repeat([]byte{0}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	rejectIn(strings.Replace(baseConf(), kPriv, raw, 1), "44 base64")

	huge := filepath.Join(dir, "huge")
	if err := os.WriteFile(huge, bytes.Repeat([]byte{'A'}, 200), 0o600); err != nil {
		t.Fatal(err)
	}
	rejectIn(strings.Replace(baseConf(), kPriv, huge, 1), "44 base64")

	if err := os.Chmod(keyPath, 0o666); err != nil {
		t.Fatal(err)
	}
	rejectIn(strings.Replace(baseConf(), kPriv, keyPath, 1), "writable by group or other")
}

func TestValidDev(t *testing.T) {
	ok := []string{"w", "wg0", "wg_0", "wg-0", strings.Repeat("a", 15)}
	for _, name := range ok {
		if err := ValidDev(name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := []string{"", strings.Repeat("a", 16), "wg0.conf", "../x", `wg\0`, "wg.0", "..", "has space"}
	for _, name := range bad {
		if err := ValidDev(name); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
}

func TestOpen(t *testing.T) {
	parent := t.TempDir()
	link := filepath.Join(parent, "link")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, "wg0", false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	if _, err := Open(parent, "wg0.conf", false); err == nil || !strings.Contains(err.Error(), "bad device") {
		t.Fatal(err)
	}
	if _, err := Open(parent, "wg0", false); err == nil {
		t.Fatal("missing file was accepted")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(path, []byte(baseConf()), 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		cfg, err := Open(dir, "wg0", false)
		if err != nil {
			t.Fatal(err)
		}
		requireKey(t, "private", cfg.PrivateKey, kPriv)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, "wg0", false); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, "wg0", false); err == nil || !strings.Contains(err.Error(), "not owned by root") {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
		big := filepath.Join(dir, "wide.conf")
		// Device name is the basename without .conf. Use a fresh directory for size.
		sizeDir := t.TempDir()
		big = filepath.Join(sizeDir, "wg0.conf")
		if err := os.WriteFile(big, bytes.Repeat([]byte{'a'}, maxConfigBytes+1), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(sizeDir, "wg0", false); err == nil || !strings.Contains(err.Error(), "64 KiB") {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, "wg0", false); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatal(err)
		}
		owned := t.TempDir()
		if err := os.Chown(owned, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(owned, "wg0", false); err == nil || !strings.Contains(err.Error(), "not owned by root") {
			t.Fatal(err)
		}
		// dir is now 0777; the symlink-file check needs a root-owned directory.
		clean := t.TempDir()
		if err := os.WriteFile(filepath.Join(clean, "target"), []byte(baseConf()), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(clean, "target"), filepath.Join(clean, "wg0.conf")); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(clean, "wg0", false); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatal(err)
		}
		return
	}
	if _, err := Open(dir, "wg0", false); err == nil || !strings.Contains(err.Error(), "not owned by root") {
		t.Fatal(err)
	}
}

func TestCheckNode(t *testing.T) {
	cases := []struct {
		name    string
		info    fakeInfo
		dir     bool
		want    string
		wantNil bool
	}{
		{name: "file", info: fakeInfo{mode: 0o644, uid: 0}, wantNil: true},
		{name: "file 600", info: fakeInfo{mode: 0o600, uid: 0}, wantNil: true},
		{name: "group write", info: fakeInfo{mode: 0o664, uid: 0}, want: "writable"},
		{name: "other write", info: fakeInfo{mode: 0o646, uid: 0}, want: "writable"},
		{name: "uid", info: fakeInfo{mode: 0o644, uid: 1000}, want: "not owned by root"},
		{name: "symlink", info: fakeInfo{mode: os.ModeSymlink | 0o777, uid: 0}, want: "symlink"},
		{name: "dir", info: fakeInfo{mode: 0o755, uid: 0, dir: true}, dir: true, wantNil: true},
		{name: "dir write", info: fakeInfo{mode: 0o777, uid: 0, dir: true}, dir: true, want: "writable"},
		{name: "file as dir", info: fakeInfo{mode: 0o644, uid: 0}, dir: true, want: "not a directory"},
		{name: "dir as file", info: fakeInfo{mode: os.ModeDir | 0o755, uid: 0, dir: true}, want: "not a file"},
		{name: "bad sys", info: fakeInfo{mode: 0o644, uid: 0, sys: "nope"}, want: "not owned by root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNode(tc.info, tc.dir)
			if tc.wantNil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRealSymlinkAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := checkNode(st, false); err != nil {
			t.Fatal(err)
		}
	} else if err := checkNode(st, false); err == nil || !strings.Contains(err.Error(), "not owned by root") {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	lst, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNode(lst, false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	if _, err := readNoFollow(link, maxConfigBytes); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	got, err := readNoFollow(path, 10)
	if err != nil || string(got) != "abc" {
		t.Fatal(err, string(got))
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte{'a'}, maxConfigBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readNoFollow(big, maxConfigBytes); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatal(err)
	}
	if err := checkSize(maxConfigBytes); err != nil {
		t.Fatal(err)
	}
	if err := checkSize(maxConfigBytes + 1); err == nil {
		t.Fatal("expected size error")
	}
	if _, err := lstatWithin(dir, path); err != nil {
		t.Fatal(err)
	}
	if _, err := lstatWithin(dir, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	if err := underDir("", "/etc/wireguard/k"); err == nil {
		t.Fatal("empty dir accepted")
	}
	if err := underDir(dir, dir); err == nil {
		t.Fatal("directory itself accepted as a key path")
	}
}

type fakeInfo struct {
	mode os.FileMode
	uid  uint32
	dir  bool
	sys  any
}

func (f fakeInfo) Name() string       { return "n" }
func (f fakeInfo) Size() int64        { return 1 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.dir }
func (f fakeInfo) Sys() any {
	if f.sys != nil {
		return f.sys
	}
	return &syscall.Stat_t{Uid: f.uid}
}

func mustParse(t *testing.T, body string, ipv6 bool) Config {
	t.Helper()
	cfg, err := Parse(body, t.TempDir(), ipv6)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func mustReject(t *testing.T, body string, ipv6 bool, want string) {
	t.Helper()
	_, err := Parse(body, t.TempDir(), ipv6)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v, want substring %q", err, want)
	}
}

func requireKey(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s mismatch", name)
	}
}
