package wireguard

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseHandshakes(t *testing.T) {
	text := "abc\t1700000000\n\ndef\t0\n"
	got, err := ParseHandshakes(text)
	if err != nil {
		t.Fatal(err)
	}
	if got["abc"] != 1700000000 || got["def"] != 0 {
		t.Fatalf("%#v", got)
	}
	if _, err := ParseHandshakes("onlyone"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseHandshakes("k -1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFresh(t *testing.T) {
	cases := []struct {
		name     string
		ts, now  int64
		recorded int64
		newer    bool
		want     bool
	}{
		{"zero", 0, 100, 0, false, false},
		{"not newer", 100, 100, 100, true, false},
		{"newer", 100, 100, 99, true, true},
		{"age 5", 95, 100, 0, false, true},
		{"age 6", 94, 100, 0, false, false},
		{"future 5", 105, 100, 0, false, true},
		{"future 6", 106, 100, 0, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Fresh(tc.ts, tc.now, tc.recorded, tc.newer); got != tc.want {
				t.Fatalf("Fresh = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeriveMTU(t *testing.T) {
	n, note, err := DeriveMTU(nil, 1500, true, false)
	if err != nil || n != 1420 || note != "" {
		t.Fatalf("1500: %d %q %v", n, note, err)
	}
	n, _, err = DeriveMTU(nil, 1450, true, false)
	if err != nil || n != 1370 {
		t.Fatalf("1450: %d %v", n, err)
	}
	n, note, err = DeriveMTU(nil, 0, false, false)
	if err != nil || n != 1420 || note != "extif mtu unknown, using 1420" {
		t.Fatalf("unknown: %d %q %v", n, note, err)
	}
	n, _, err = DeriveMTU(nil, 9000, true, false)
	if err != nil || n != 1420 {
		t.Fatalf("jumbo: %d %v", n, err)
	}
	set := 1200
	n, _, err = DeriveMTU(&set, 1500, true, false)
	if err != nil || n != 1200 {
		t.Fatalf("configured: %d %v", n, err)
	}
	_, _, err = DeriveMTU(&set, 1500, true, true)
	if err == nil || !strings.Contains(err.Error(), "below 1280") {
		t.Fatal(err)
	}
	_, _, err = DeriveMTU(nil, 600, true, false)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatal(err)
	}
}

func TestSetArgvUsesKeyPaths(t *testing.T) {
	old := keyDir
	keyDir = "/run/wg-supervisor"
	t.Cleanup(func() { keyDir = old })
	priv := strings.Repeat("A", 43) + "="
	pub := strings.Repeat("B", 43) + "="
	keep := 0
	listen := 51820
	args := SetArgv("wg0", pub, "203.0.113.10:51820", &listen, true, []string{"0.0.0.0/0", "10.1.2.0/24"}, &keep)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, priv) {
		t.Fatal("private key appeared in argv")
	}
	if !strings.Contains(joined, "private-key /run/wg-supervisor/privatekey") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "preshared-key /run/wg-supervisor/presharedkey") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "persistent-keepalive") {
		t.Fatal("keepalive 0 was passed")
	}
	if !strings.Contains(joined, "listen-port 51820") || !strings.Contains(joined, "allowed-ips 0.0.0.0/0,10.1.2.0/24") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, pub) {
		t.Fatal("public key missing")
	}
	keep = 25
	args = SetArgv("wg0", pub, "203.0.113.10:51820", nil, false, []string{"10.8.0.0/24"}, &keep)
	joined = strings.Join(args, " ")
	if !strings.Contains(joined, "persistent-keepalive 25") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "listen-port") || strings.Contains(joined, "preshared-key") {
		t.Fatal(joined)
	}
}

func TestApplyUnlinksKeyFiles(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldRun := keyDir, runCmd
	keyDir = dir
	t.Cleanup(func() {
		keyDir = oldDir
		runCmd = oldRun
	})
	priv := strings.Repeat("A", 43) + "="
	psk := strings.Repeat("C", 43) + "="
	pub := strings.Repeat("B", 43) + "="
	cfg := Config{PrivateKey: priv, PublicKey: pub, PresharedKey: psk, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	check := func(fail bool) {
		t.Helper()
		runCmd = func(name string, args ...string) ([]byte, error) {
			if name != "wg" {
				t.Fatalf("command %s", name)
			}
			joined := strings.Join(args, " ")
			if strings.Contains(joined, priv) || strings.Contains(joined, psk) {
				t.Fatal("key bytes in argv")
			}
			st, err := os.Stat(filepath.Join(dir, "privatekey"))
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("mode %o", st.Mode().Perm())
			}
			body, err := os.ReadFile(filepath.Join(dir, "privatekey"))
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != priv+"\n" {
				t.Fatal("key file body")
			}
			dst, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if dst.Mode().Perm() != 0o700 {
				t.Fatalf("dir mode %o", dst.Mode().Perm())
			}
			if fail {
				return []byte("no"), errors.New("wg failed")
			}
			return nil, nil
		}
	}
	check(true)
	if err := Apply("wg0", cfg, "203.0.113.10:51820"); err == nil {
		t.Fatal("expected wg failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "privatekey")); !os.IsNotExist(err) {
		t.Fatal("private key remained after failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "presharedkey")); !os.IsNotExist(err) {
		t.Fatal("preshared key remained after failure")
	}
	check(false)
	if err := Apply("wg0", cfg, "203.0.113.10:51820"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "privatekey")); !os.IsNotExist(err) {
		t.Fatal("private key remained after success")
	}
}

func TestProvokeSequence(t *testing.T) {
	old := runCmd
	t.Cleanup(func() { runCmd = old })
	var got []string
	runCmd = func(name string, args ...string) ([]byte, error) {
		if name != "wg" {
			t.Fatalf("command %s", name)
		}
		got = append(got, args[len(args)-1])
		return nil, nil
	}
	pub := strings.Repeat("B", 43) + "="
	if err := Provoke("wg0", pub, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "1,0" {
		t.Fatalf("configured 0: %v", got)
	}
	got = nil
	if err := Provoke("wg0", pub, 1); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "1" {
		t.Fatalf("configured 1: %v", got)
	}
	got = nil
	if err := Provoke("wg0", pub, 25); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "1,25" {
		t.Fatalf("configured 25: %v", got)
	}
}

func TestRemovePeerMissing(t *testing.T) {
	old := runCmd
	t.Cleanup(func() { runCmd = old })
	runCmd = func(name string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "set wg0 peer PUB remove" {
			t.Fatal(args)
		}
		return []byte("Unable to find peer"), errors.New("exit")
	}
	if err := RemovePeer("wg0", "PUB"); err != nil {
		t.Fatal(err)
	}
	runCmd = func(name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit")
	}
	if err := RemovePeer("wg0", "PUB"); err == nil {
		t.Fatal("expected error")
	}
}

func TestAddPeerArgvOmitsKeyAndKeepalive(t *testing.T) {
	old := keyDir
	keyDir = "/run/wg-supervisor"
	t.Cleanup(func() { keyDir = old })
	pub := strings.Repeat("B", 43) + "="
	args := AddPeerArgv("wg0", pub, "203.0.113.10:51820", true, []string{"0.0.0.0/0"})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "private-key") || strings.Contains(joined, "listen-port") || strings.Contains(joined, "persistent-keepalive") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "preshared-key /run/wg-supervisor/presharedkey") || !strings.Contains(joined, "allowed-ips 0.0.0.0/0") {
		t.Fatal(joined)
	}
	joined = strings.Join(AddPeerArgv("wg0", pub, "203.0.113.10:51820", false, []string{"10.8.0.0/24"}), " ")
	if strings.Contains(joined, "preshared-key") {
		t.Fatal(joined)
	}
}

func TestReaddPeerUnlinks(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldRun := keyDir, runCmd
	keyDir = dir
	t.Cleanup(func() {
		keyDir = oldDir
		runCmd = oldRun
	})
	var joined string
	runCmd = func(name string, args ...string) ([]byte, error) {
		joined = strings.Join(args, " ")
		if _, err := os.Stat(filepath.Join(dir, "presharedkey")); err != nil {
			t.Fatal("psk missing during wg set")
		}
		return nil, nil
	}
	cfg := Config{
		PublicKey:    strings.Repeat("B", 43) + "=",
		PresharedKey: strings.Repeat("C", 43) + "=",
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
	if err := ReaddPeer("wg0", cfg, "203.0.113.10:51820"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(joined, "private-key") || strings.Contains(joined, "persistent-keepalive") || strings.Contains(joined, "listen-port") {
		t.Fatal(joined)
	}
	if _, err := os.Stat(filepath.Join(dir, "presharedkey")); !os.IsNotExist(err) {
		t.Fatal("psk remained")
	}
}

func TestKeepaliveEdgeRestores(t *testing.T) {
	var got []int
	set := func(n int) error {
		got = append(got, n)
		return nil
	}
	if err := ApplyKeepaliveEdge(set, 0, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ints(got), ",") != "0,1,0" {
		t.Fatalf("%v", got)
	}
	got = nil
	if err := ApplyKeepaliveEdge(set, 25, func() bool { return false }); err == nil || !strings.Contains(err.Error(), "not refreshed") {
		t.Fatal(err)
	}
	if strings.Join(ints(got), ",") != "0,25,25" {
		t.Fatalf("%v", got)
	}
	got = nil
	if err := ApplyKeepaliveEdge(set, 25, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ints(got), ",") != "0,25,25" {
		t.Fatalf("success path %v", got)
	}
}

func ints(n []int) []string {
	out := make([]string, len(n))
	for i, v := range n {
		out[i] = strconv.Itoa(v)
	}
	return out
}

func TestAddLinkErrors(t *testing.T) {
	old := runCmd
	t.Cleanup(func() { runCmd = old })
	runCmd = func(name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "show" {
			return []byte("2: wg0:"), nil
		}
		t.Fatal(args)
		return nil, nil
	}
	err := AddLink("wg0")
	if err == nil || err.Error() != "interface wg0 already exists" {
		t.Fatal(err)
	}
	runCmd = func(name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "show" {
			return []byte("does not exist"), errors.New("missing")
		}
		return []byte("RTNETLINK answers: File exists"), errors.New("add")
	}
	err = AddLink("wg0")
	if err == nil || err.Error() != "interface wg0 already exists" || strings.Contains(err.Error(), "no WireGuard") {
		t.Fatal(err)
	}
	runCmd = func(name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "show" {
			return nil, errors.New("missing")
		}
		return []byte("RTNETLINK answers: Operation not supported"), errors.New("add")
	}
	err = AddLink("wg0")
	if err == nil || !strings.Contains(err.Error(), MissingModule) || !strings.Contains(err.Error(), "Operation not supported") {
		t.Fatal(err)
	}
}
