package wireguard

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MissingModule is the stable error when the kernel has no WireGuard device type.
const MissingModule = "host kernel has no WireGuard device type (need Linux >= 5.6 with CONFIG_WIREGUARD loaded). This image does not modprobe and does not fall back to wireguard-go."

// keyDir holds the short-lived key files. Tests point it at a temp directory.
var keyDir = "/run/wg-supervisor"

// runCmd is the process runner. Tests replace it.
var runCmd = func(name string, args ...string) ([]byte, error) {
	return combined(name, args...)
}

// DeriveMTU returns the tunnel MTU. note is set when the external MTU could not be read.
// A configured value is used as-is. Otherwise the result is min(1420, extMTU-80).
func DeriveMTU(configured *int, extMTU int, extOK, ipv6 bool) (int, string, error) {
	var n int
	note := ""
	if configured != nil {
		n = *configured
	} else if !extOK {
		n = 1420
		note = "extif mtu unknown, using 1420"
	} else {
		n = extMTU - 80
		if n > 1420 {
			n = 1420
		}
	}
	if ipv6 && n < 1280 {
		return 0, "", fmt.Errorf("mtu %d is below 1280 with ipv6 enabled", n)
	}
	if n < 576 || n > 1500 {
		return 0, "", fmt.Errorf("mtu %d is outside 576-1500", n)
	}
	return n, note, nil
}

// ParseHandshakes reads `wg show <dev> latest-handshakes`.
func ParseHandshakes(text string) (map[string]int64, error) {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("latest-handshakes: %q", line)
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("latest-handshakes time %q", fields[1])
		}
		out[fields[0]] = n
	}
	return out, nil
}

// Fresh reports whether tsUnix is a usable handshake at nowUnix.
// requireNewer rejects a timestamp that is not strictly after recorded.
// Age and future skew are both five seconds.
func Fresh(tsUnix, nowUnix, recorded int64, requireNewer bool) bool {
	if tsUnix <= 0 {
		return false
	}
	if requireNewer && tsUnix <= recorded {
		return false
	}
	if nowUnix-tsUnix > 5 {
		return false
	}
	if tsUnix-nowUnix > 5 {
		return false
	}
	return true
}

// SetArgv is the one `wg set` argument list. Key material is file paths only.
func SetArgv(dev, pub, endpoint string, listen *int, psk bool, allowed []string, keep *int) []string {
	args := []string{"set", dev, "private-key", filepath.Join(keyDir, "privatekey")}
	if listen != nil {
		args = append(args, "listen-port", strconv.Itoa(*listen))
	}
	args = append(args, "peer", pub)
	if psk {
		args = append(args, "preshared-key", filepath.Join(keyDir, "presharedkey"))
	}
	args = append(args, "endpoint", endpoint, "allowed-ips", strings.Join(allowed, ","))
	if keep != nil && *keep > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(*keep))
	}
	return args
}

// Apply writes the key files, runs one wg set, and unlinks the files.
func Apply(dev string, cfg Config, endpoint string) error {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(keyDir, 0o700); err != nil {
		return err
	}
	priv := filepath.Join(keyDir, "privatekey")
	pskPath := filepath.Join(keyDir, "presharedkey")
	defer os.Remove(priv)
	defer os.Remove(pskPath)
	if err := writeKey(priv, cfg.PrivateKey); err != nil {
		return err
	}
	psk := cfg.PresharedKey != ""
	if psk {
		if err := writeKey(pskPath, cfg.PresharedKey); err != nil {
			return err
		}
	}
	allowed := make([]string, len(cfg.AllowedIPs))
	for i, p := range cfg.AllowedIPs {
		allowed[i] = p.String()
	}
	args := SetArgv(dev, cfg.PublicKey, endpoint, cfg.ListenPort, psk, allowed, cfg.Keepalive)
	out, err := runCmd("wg", args...)
	if err != nil {
		return fmt.Errorf("wg set: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeKey(path, line string) error {
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(line + "\n")
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// SetKeepalive sets one peer's persistent-keepalive.
func SetKeepalive(dev, pub string, seconds int) error {
	if seconds < 0 || seconds > 65535 {
		return fmt.Errorf("keepalive %d", seconds)
	}
	out, err := runCmd("wg", "set", dev, "peer", pub, "persistent-keepalive", strconv.Itoa(seconds))
	if err != nil {
		return fmt.Errorf("wg set keepalive: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Kick sends one initiation by moving keepalive from 0 to 1 and back to 0.
func Kick(dev, pub string) error {
	if err := SetKeepalive(dev, pub, 1); err != nil {
		return err
	}
	return SetKeepalive(dev, pub, 0)
}

// ApplyKeepaliveEdge is the healthcheck provoke.
// It sets 0, then 1 or the configured interval, waits, then restores the configured interval.
func ApplyKeepaliveEdge(set func(int) error, configured int, wait func() bool) error {
	if err := set(0); err != nil {
		return err
	}
	kick := 1
	if configured > 0 {
		kick = configured
	}
	if err := set(kick); err != nil {
		_ = set(configured)
		return err
	}
	ok := true
	if wait != nil {
		ok = wait()
	}
	err := set(configured)
	if !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("handshake was not refreshed")
	}
	return err
}

// AddLink creates a kernel WireGuard device. An existing name is left in place.
func AddLink(dev string) error {
	if err := ValidDev(dev); err != nil {
		return err
	}
	if _, err := runCmd("ip", "link", "show", "dev", dev); err == nil {
		return fmt.Errorf("interface %s already exists", dev)
	}
	out, err := runCmd("ip", "link", "add", "dev", dev, "type", "wireguard")
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "File exists") || strings.Contains(strings.ToLower(msg), "already exists") {
			return fmt.Errorf("interface %s already exists", dev)
		}
		stderr := strings.TrimSpace(msg)
		if stderr == "" {
			return fmt.Errorf("%s", MissingModule)
		}
		return fmt.Errorf("%s\n%s", MissingModule, stderr)
	}
	return nil
}

// ConfigureLink adds addresses and sets the MTU while the link is down.
func ConfigureLink(dev string, addrs []fmt.Stringer, mtu int) error {
	for _, a := range addrs {
		text := a.String()
		fam := "-4"
		if strings.Contains(text, ":") {
			fam = "-6"
		}
		out, err := runCmd("ip", fam, "address", "add", text, "dev", dev)
		if err != nil {
			return fmt.Errorf("ip address add %s: %w (%s)", text, err, strings.TrimSpace(string(out)))
		}
	}
	out, err := runCmd("ip", "link", "set", "dev", dev, "mtu", strconv.Itoa(mtu))
	if err != nil {
		return fmt.Errorf("ip link set mtu: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LinkUp brings the device up.
func LinkUp(dev string) error {
	out, err := runCmd("ip", "link", "set", "dev", dev, "up")
	if err != nil {
		return fmt.Errorf("ip link set up: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LinkDel deletes the device.
func LinkDel(dev string) error {
	out, err := runCmd("ip", "link", "del", "dev", dev)
	if err != nil {
		return fmt.Errorf("ip link del: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PeerHandshake returns the one peer's public key and handshake time.
// An empty key means wg has not printed a peer yet.
func PeerHandshake(dev string) (string, int64, error) {
	if err := ValidDev(dev); err != nil {
		return "", 0, err
	}
	out, err := runCmd("wg", "show", dev, "latest-handshakes")
	if err != nil {
		return "", 0, fmt.Errorf("wg show latest-handshakes: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	m, err := ParseHandshakes(string(out))
	if err != nil {
		return "", 0, err
	}
	for pub, ts := range m {
		return pub, ts, nil
	}
	return "", 0, nil
}

// Latest returns the handshake unix time for pub. Zero means the peer has not shaken hands.
func Latest(dev, pub string) (int64, error) {
	if err := ValidDev(dev); err != nil {
		return 0, err
	}
	out, err := runCmd("wg", "show", dev, "latest-handshakes")
	if err != nil {
		return 0, fmt.Errorf("wg show latest-handshakes: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	m, err := ParseHandshakes(string(out))
	if err != nil {
		return 0, err
	}
	return m[pub], nil
}

// ShowEndpoint reads `wg show <dev> endpoints` for one peer.
// The tools print "<public-key>\\t<ip>:<port>".
func ShowEndpoint(dev, pub string) (string, int, error) {
	out, err := runCmd("wg", "show", dev, "endpoints")
	if err != nil {
		return "", 0, fmt.Errorf("wg show endpoints: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return "", 0, fmt.Errorf("endpoints: %q", line)
		}
		if pub != "" && fields[0] != pub {
			continue
		}
		if fields[1] == "(none)" {
			return "", 0, fmt.Errorf("endpoint is unset")
		}
		host, portText, err := net.SplitHostPort(fields[1])
		if err != nil {
			return "", 0, fmt.Errorf("endpoint %q", fields[1])
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
	return "", 0, fmt.Errorf("endpoint is unset")
}
