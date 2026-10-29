package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// SelfTest installs the kill switch in this network namespace and removes it.
// It needs CAP_NET_ADMIN. It does not need the WireGuard module.
func SelfTest() error {
	_, dev, err := ReadDefaultRoute4()
	if err != nil {
		return err
	}
	fw := Firewall{
		ExtIf:        dev,
		WGDev:        "wg0",
		RPCPort:      9091,
		PeerPort:     51413,
		Endpoint:     netip.MustParseAddr("203.0.113.10"),
		EndpointPort: 51820,
	}
	if err := fw.Install(); err != nil {
		return err
	}
	defer fw.Cleanup()
	if !has(fw.bin(), chain, endpointOut(dev, "203.0.113.10", 51820)...) {
		return fmt.Errorf("endpoint allow is missing")
	}
	if !has(fw.bin(), "INPUT", endpointIn(dev, "203.0.113.10", 51820)...) {
		return fmt.Errorf("endpoint sport allow is missing")
	}
	if fw.HasWGAccept() {
		return fmt.Errorf("device accept was installed before the handshake")
	}
	next := netip.MustParseAddr("203.0.113.11")
	if err := fw.ReplaceEndpoint(fw.Endpoint, next, 51820); err != nil {
		return err
	}
	if has(fw.bin(), chain, endpointOut(dev, "203.0.113.10", 51820)...) {
		return fmt.Errorf("old endpoint allow remained")
	}
	if has(fw.bin(), "INPUT", endpointIn(dev, "203.0.113.10", 51820)...) {
		return fmt.Errorf("old endpoint sport allow remained")
	}
	if !has(fw.bin(), chain, endpointOut(dev, "203.0.113.11", 51820)...) {
		return fmt.Errorf("new endpoint allow is missing")
	}
	if !has(fw.bin(), "INPUT", endpointIn(dev, "203.0.113.11", 51820)...) {
		return fmt.Errorf("new endpoint sport allow is missing")
	}
	if err := proveDrop(fw.bin()); err != nil {
		return err
	}
	if err := fw.AllowWG(); err != nil {
		return err
	}
	if !fw.HasWGAccept() {
		return fmt.Errorf("device accept missing after the handshake")
	}
	if err := fw.RevokeWG(); err != nil {
		return err
	}
	if fw.HasWGAccept() {
		return fmt.Errorf("device accept remained after revoke")
	}
	return nil
}

// proveDrop writes one UDP byte through a veth that WG_OUT does not accept.
func proveDrop(bin string) error {
	const srcDev, dstDev = "wgself", "wgpeer"
	const srcIP, dstIP = "192.0.2.1", "192.0.2.2"
	const dstPort = 9999
	if err := addVeth(srcDev, dstDev, srcIP); err != nil {
		return err
	}
	defer func() { _ = runIP("link", "del", srcDev) }()

	if err := sendUDP(srcIP, dstIP, dstPort); err == nil {
		return fmt.Errorf("udp send succeeded; WG_OUT did not drop %s", srcDev)
	}
	outRule := []string{"-o", srcDev, "-p", "udp", "--dport", strconv.Itoa(dstPort), "-j", "ACCEPT"}
	if err := insertRule(bin, chain, outRule); err != nil {
		return err
	}
	if err := sendUDP(srcIP, dstIP, dstPort); err != nil {
		_ = deleteRule(bin, chain, outRule...)
		return fmt.Errorf("udp send failed after accepting %s: %w", srcDev, err)
	}
	if err := deleteRule(bin, chain, outRule...); err != nil {
		return err
	}
	if err := sendUDP(srcIP, dstIP, dstPort); err == nil {
		return fmt.Errorf("udp send succeeded after the %s accept was removed", srcDev)
	}
	return nil
}

func insertRule(bin, ch string, rule []string) error {
	return run(bin, append([]string{"-w", "-I", ch, "1"}, rule...)...)
}

func sendUDP(localIP, remote string, port int) error {
	conn, err := net.DialUDP("udp4",
		&net.UDPAddr{IP: net.ParseIP(localIP)},
		&net.UDPAddr{IP: net.ParseIP(remote), Port: port},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte{0})
	return err
}

func addVeth(srcDev, dstDev, srcIP string) error {
	_ = runIP("link", "del", srcDev)
	if err := runIP("link", "add", "name", srcDev, "type", "veth", "peer", "name", dstDev); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = runIP("link", "del", srcDev)
		}
	}()
	if err := runIP("addr", "add", srcIP+"/24", "dev", srcDev); err != nil {
		return err
	}
	if err := runIP("link", "set", srcDev, "up"); err != nil {
		return err
	}
	if err := runIP("link", "set", dstDev, "up"); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
