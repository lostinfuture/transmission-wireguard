// Package firewall installs the container kill switch.
package firewall

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

const chain = "WG_OUT"

// Firewall is the iptables policy for one container network namespace.
// AllowWG inserts -o dev -j ACCEPT. Install does not.
type Firewall struct {
	Bin          string
	Bin6         string
	ExtIf        string
	WGDev        string
	RPCPort      int
	PeerPort     int
	Local        []netip.Prefix
	Endpoint     netip.Addr
	EndpointPort int
	IPv6         bool
}

func (f Firewall) bin() string {
	if f.Bin != "" {
		return f.Bin
	}
	return "iptables"
}

func (f Firewall) bin6() string {
	if f.Bin6 != "" {
		return f.Bin6
	}
	return "ip6tables"
}

// V4Out is the pre-handshake WG_OUT rule list for IPv4.
func (f Firewall) V4Out() [][]string {
	rules := [][]string{
		{"-o", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	if f.Endpoint.Is4() {
		rules = append(rules, endpointOut(f.ExtIf, f.Endpoint.String(), f.EndpointPort))
	}
	for _, p := range f.Local {
		if p.Addr().Is4() {
			rules = append(rules, []string{"-o", f.ExtIf, "-d", p.String(), "-j", "ACCEPT"})
		}
	}
	rules = append(rules, []string{"-j", "DROP"})
	return rules
}

// V4In is the pre-handshake INPUT rule list for IPv4.
func (f Firewall) V4In() [][]string {
	rules := [][]string{
		{"-i", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-i", f.ExtIf, "-p", "icmp", "--icmp-type", "3", "-j", "ACCEPT"},
	}
	if f.Endpoint.Is4() {
		rules = append(rules, endpointIn(f.ExtIf, f.Endpoint.String(), f.EndpointPort))
	}
	rules = append(rules,
		[]string{"-i", f.ExtIf, "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "ACCEPT"},
		[]string{"-i", f.WGDev, "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "DROP"},
		[]string{"-i", f.WGDev, "-j", "DROP"},
	)
	return rules
}

// V6Out is the pre-handshake WG_OUT rule list for IPv6.
func (f Firewall) V6Out() [][]string {
	rules := [][]string{
		{"-o", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	if f.Endpoint.Is6() {
		rules = append(rules, endpointOut(f.ExtIf, f.Endpoint.String(), f.EndpointPort))
	}
	for _, p := range f.Local {
		if p.Addr().Is6() {
			rules = append(rules, []string{"-o", f.ExtIf, "-d", p.String(), "-j", "ACCEPT"})
		}
	}
	rules = append(rules, []string{"-j", "DROP"})
	return rules
}

// V6In is the pre-handshake INPUT rule list for IPv6.
func (f Firewall) V6In() [][]string {
	rules := [][]string{
		{"-i", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-i", f.ExtIf, "-p", "ipv6-icmp", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"},
	}
	if f.Endpoint.Is6() {
		rules = append(rules, endpointIn(f.ExtIf, f.Endpoint.String(), f.EndpointPort))
	}
	rules = append(rules,
		[]string{"-i", f.ExtIf, "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "ACCEPT"},
		[]string{"-i", f.WGDev, "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "DROP"},
		[]string{"-i", f.WGDev, "-j", "DROP"},
	)
	return rules
}

// Disabled6 is the policy installed when IPv6 is off.
func Disabled6() [][]string {
	return [][]string{
		{"-w", "-P", "INPUT", "DROP"},
		{"-w", "-P", "OUTPUT", "DROP"},
		{"-w", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"},
		{"-w", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"},
	}
}

func endpointOut(iface, ip string, port int) []string {
	return []string{"-o", iface, "-d", ip, "-p", "udp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
}

func endpointIn(iface, ip string, port int) []string {
	return []string{"-i", iface, "-s", ip, "-p", "udp", "--sport", strconv.Itoa(port), "-j", "ACCEPT"}
}

// Install sets the pre-handshake policy. WireGuard egress is not accepted yet.
func (f Firewall) Install() error {
	if err := validateIf(f.ExtIf); err != nil {
		return err
	}
	if err := validateIf(f.WGDev); err != nil {
		return err
	}
	if err := f.install4(); err != nil {
		return err
	}
	return f.install6()
}

func (f Firewall) install4() error {
	b := f.bin()
	if err := applyAppend(b, f.V4Out()); err != nil {
		return err
	}
	if err := run(b, "-w", "-I", "OUTPUT", "1", "-j", chain); err != nil {
		return err
	}
	if err := run(b, "-w", "-P", "INPUT", "DROP"); err != nil {
		return err
	}
	if err := run(b, "-w", "-F", "INPUT"); err != nil {
		return err
	}
	for _, rule := range f.V4In() {
		if err := run(b, append([]string{"-w", "-A", "INPUT"}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

func (f Firewall) install6() error {
	b := f.bin6()
	if !f.IPv6 {
		for _, args := range Disabled6() {
			if err := run(b, args...); err != nil {
				if ipv6Disabled(err) {
					return nil
				}
				return fmt.Errorf("ip6tables: %w", err)
			}
		}
		return nil
	}
	if err := applyAppend(b, f.V6Out()); err != nil {
		return err
	}
	if err := run(b, "-w", "-I", "OUTPUT", "1", "-j", chain); err != nil {
		return err
	}
	if err := run(b, "-w", "-P", "INPUT", "DROP"); err != nil {
		return err
	}
	if err := run(b, "-w", "-P", "OUTPUT", "DROP"); err != nil {
		return err
	}
	if err := run(b, "-w", "-F", "INPUT"); err != nil {
		return err
	}
	for _, rule := range f.V6In() {
		if err := run(b, append([]string{"-w", "-A", "INPUT"}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

func applyAppend(bin string, rules [][]string) error {
	if err := run(bin, "-w", "-N", chain); err != nil {
		return err
	}
	for _, rule := range rules {
		if err := run(bin, append([]string{"-w", "-A", chain}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

// AllowWG inserts the device egress accept and the peer-port input allows.
func (f Firewall) AllowWG() error {
	if err := validateIf(f.WGDev); err != nil {
		return err
	}
	if err := f.allowFam(f.bin()); err != nil {
		return err
	}
	if f.IPv6 {
		return f.allowFam(f.bin6())
	}
	return nil
}

func (f Firewall) allowFam(bin string) error {
	peer := strconv.Itoa(f.PeerPort)
	if err := insertOnce(bin, chain, "-o", f.WGDev, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := insertOnce(bin, "INPUT", "-i", f.WGDev, "-p", "udp", "--dport", peer, "-j", "ACCEPT"); err != nil {
		return err
	}
	return insertOnce(bin, "INPUT", "-i", f.WGDev, "-p", "tcp", "--dport", peer, "-j", "ACCEPT")
}

// RevokeWG removes the rules AllowWG inserted. The endpoint sport rule stays.
func (f Firewall) RevokeWG() error {
	if err := validateIf(f.WGDev); err != nil {
		return err
	}
	f.revokeFam(f.bin())
	if f.IPv6 {
		f.revokeFam(f.bin6())
	}
	return nil
}

func (f Firewall) revokeFam(bin string) {
	peer := strconv.Itoa(f.PeerPort)
	_ = deleteRule(bin, chain, "-o", f.WGDev, "-j", "ACCEPT")
	_ = deleteRule(bin, "INPUT", "-i", f.WGDev, "-p", "udp", "--dport", peer, "-j", "ACCEPT")
	_ = deleteRule(bin, "INPUT", "-i", f.WGDev, "-p", "tcp", "--dport", peer, "-j", "ACCEPT")
}

// HasWGAccept reports whether the device egress accept is installed.
func (f Firewall) HasWGAccept() bool {
	return has(f.bin(), chain, "-o", f.WGDev, "-j", "ACCEPT")
}

// ReplaceEndpoint moves the OUTPUT dport allow and the INPUT sport allow.
// The caller moves the host route.
func (f Firewall) ReplaceEndpoint(old, next netip.Addr, port int) error {
	if !old.IsValid() || !next.IsValid() {
		return fmt.Errorf("endpoint address is required")
	}
	if old.Is4() != next.Is4() {
		return fmt.Errorf("route family mismatch: %s to %s", old, next)
	}
	bin := f.bin()
	if old.Is6() {
		if !f.IPv6 {
			return fmt.Errorf("ipv6 is disabled")
		}
		bin = f.bin6()
	}
	_ = deleteRule(bin, chain, endpointOut(f.ExtIf, old.String(), port)...)
	_ = deleteRule(bin, "INPUT", endpointIn(f.ExtIf, old.String(), port)...)
	if err := insertOnce(bin, chain, endpointOut(f.ExtIf, next.String(), port)...); err != nil {
		return err
	}
	return insertOnce(bin, "INPUT", endpointIn(f.ExtIf, next.String(), port)...)
}

// Cleanup removes the chains this process installed and restores ACCEPT policies.
func (f Firewall) Cleanup() {
	b := f.bin()
	_ = run(b, "-w", "-D", "OUTPUT", "-j", chain)
	_ = run(b, "-w", "-F", chain)
	_ = run(b, "-w", "-X", chain)
	_ = run(b, "-w", "-P", "INPUT", "ACCEPT")
	_ = run(b, "-w", "-F", "INPUT")
	b6 := f.bin6()
	_ = run(b6, "-w", "-D", "OUTPUT", "-j", chain)
	_ = run(b6, "-w", "-F", chain)
	_ = run(b6, "-w", "-X", chain)
	_ = run(b6, "-w", "-P", "INPUT", "ACCEPT")
	_ = run(b6, "-w", "-P", "OUTPUT", "ACCEPT")
	_ = run(b6, "-w", "-F", "INPUT")
	_ = run(b6, "-w", "-F", "OUTPUT")
}

func insertOnce(bin, ch string, rule ...string) error {
	if has(bin, ch, rule...) {
		return nil
	}
	return run(bin, append([]string{"-w", "-I", ch, "1"}, rule...)...)
}

func deleteRule(bin, ch string, rule ...string) error {
	if !has(bin, ch, rule...) {
		return nil
	}
	return run(bin, append([]string{"-w", "-D", ch}, rule...)...)
}

func has(bin, ch string, rule ...string) bool {
	return run(bin, append([]string{"-w", "-C", ch}, rule...)...) == nil
}

func run(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ipv6Disabled(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "protocol not supported") || strings.Contains(msg, "address family not supported") || strings.Contains(msg, "can't initialize")
}

func validateIf(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("bad interface %q", name)
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return fmt.Errorf("bad interface %q", name)
		}
	}
	return nil
}
