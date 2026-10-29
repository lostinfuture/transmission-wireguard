package firewall

import (
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var defaultRouteRE = regexp.MustCompile(`default via (\S+) dev (\S+)`)
var mtuRE = regexp.MustCompile(`\bmtu (\d+)\b`)
var routeDevRE = regexp.MustCompile(`\bdev (\S+)`)

// DefaultRoute parses `ip route show default`.
func DefaultRoute(text string) (gw netip.Addr, dev string, err error) {
	m := defaultRouteRE.FindStringSubmatch(text)
	if m == nil {
		return netip.Addr{}, "", fmt.Errorf("no default route")
	}
	addr, err := netip.ParseAddr(m[1])
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("default gateway %q: %w", m[1], err)
	}
	if err := validateIf(m[2]); err != nil {
		return netip.Addr{}, "", err
	}
	return addr, m[2], nil
}

// ParseLinkMTU reads the mtu field from `ip link show`.
func ParseLinkMTU(text string) (int, error) {
	m := mtuRE.FindStringSubmatch(text)
	if m == nil {
		return 0, fmt.Errorf("no mtu")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("mtu %q", m[1])
	}
	return n, nil
}

// ReadDefaultRoute4 runs ip.
func ReadDefaultRoute4() (netip.Addr, string, error) {
	return readDefault("-4")
}

// ReadDefaultRoute6 runs ip.
func ReadDefaultRoute6() (netip.Addr, string, error) {
	return readDefault("-6")
}

func readDefault(fam string) (netip.Addr, string, error) {
	out, err := exec.Command("ip", fam, "route", "show", "default").CombinedOutput()
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("ip route: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return DefaultRoute(string(out))
}

// LinkMTU reads the MTU of dev.
func LinkMTU(dev string) (int, error) {
	if err := validateIf(dev); err != nil {
		return 0, err
	}
	out, err := exec.Command("ip", "link", "show", "dev", dev).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ip link show %s: %w (%s)", dev, err, strings.TrimSpace(string(out)))
	}
	return ParseLinkMTU(string(out))
}

// OriginalInstalled reports whether the saved default route is still in the main table.
func OriginalInstalled(gw netip.Addr, dev string) bool {
	if !gw.IsValid() {
		return false
	}
	fam := "-4"
	if gw.Is6() {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", "show", "default").CombinedOutput()
	if err != nil {
		return false
	}
	text := string(out)
	return strings.Contains(text, "default via "+gw.String()+" ") && strings.Contains(text, " dev "+dev)
}

// ReplaceVia installs prefix via gw dev extif. A family mismatch is refused before ip runs.
func ReplaceVia(prefix netip.Prefix, gw netip.Addr, extif string) error {
	return routeVia("replace", prefix, gw, extif)
}

// DelHostVia deletes a host route this process installed. A default prefix is refused.
func DelHostVia(prefix netip.Prefix, gw netip.Addr, extif string) error {
	return routeVia("del", prefix, gw, extif)
}

func routeVia(verb string, prefix netip.Prefix, gw netip.Addr, extif string) error {
	if err := validateIf(extif); err != nil {
		return err
	}
	if prefix.Bits() == 0 {
		return fmt.Errorf("refusing route %s", prefix)
	}
	if !prefix.Addr().IsValid() || !gw.IsValid() || prefix.Addr().Is4() != gw.Is4() {
		return fmt.Errorf("route family mismatch: %s via %s", prefix, gw)
	}
	fam := "-4"
	if gw.Is6() {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", verb, prefix.String(), "via", gw.String(), "dev", extif).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route %s %s: %w (%s)", verb, prefix, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ParseRouteGetDev reads the device from `ip route get`.
func ParseRouteGetDev(text string) (string, error) {
	m := routeDevRE.FindStringSubmatch(text)
	if m == nil {
		return "", fmt.Errorf("no device")
	}
	if err := validateIf(m[1]); err != nil {
		return "", err
	}
	return m[1], nil
}

// RouteGet runs `ip route get` and returns the device that would carry the packet.
func RouteGet(addr netip.Addr) (string, error) {
	if !addr.IsValid() {
		return "", fmt.Errorf("route address is required")
	}
	fam := "-4"
	if addr.Is6() {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", "get", addr.String()).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip route get %s: %w (%s)", addr, err, strings.TrimSpace(string(out)))
	}
	return ParseRouteGetDev(string(out))
}

// ReplaceDev installs prefix dev wg. A default prefix becomes `default dev wg`.
func ReplaceDev(prefix netip.Prefix, dev string) error {
	if err := validateIf(dev); err != nil {
		return err
	}
	fam := "-4"
	if prefix.Addr().Is6() {
		fam = "-6"
	} else if !prefix.Addr().Is4() {
		return fmt.Errorf("route family mismatch: %s", prefix)
	}
	args := []string{fam, "route", "replace"}
	if prefix.Bits() == 0 {
		args = append(args, "default", "dev", dev)
	} else {
		args = append(args, prefix.String(), "dev", dev)
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace %s: %w (%s)", prefix, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DelDefault deletes the original default route.
func DelDefault(gw netip.Addr, extif string) error {
	fam := "-4"
	if gw.Is6() {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", "del", "default", "via", gw.String(), "dev", extif).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route del default: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RestoreDefault puts the original default route back.
func RestoreDefault(gw netip.Addr, extif string) error {
	fam := "-4"
	if gw.Is6() {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", "replace", "default", "via", gw.String(), "dev", extif).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace default: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
