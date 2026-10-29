package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// lookupNetIP is replaced by tests.
var lookupNetIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// Resolve pins one address for host. Literals are not looked up.
// unused is how many usable answers were not selected.
func Resolve(host string, ipv6 bool) (netip.Addr, int, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if !ipv6 && addr.Is6() {
			return netip.Addr{}, 0, fmt.Errorf("ipv6 is disabled: endpoint %s", addr)
		}
		return addr, 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := lookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("endpoint %s: %w", host, err)
	}
	var usable []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() {
			continue
		}
		if ip.Is6() && !ipv6 {
			continue
		}
		if ip.Is4() || ip.Is6() {
			usable = append(usable, ip)
		}
	}
	var pick netip.Addr
	found := false
	for _, ip := range usable {
		if ip.Is4() {
			pick = ip
			found = true
			break
		}
	}
	if !found {
		for _, ip := range usable {
			if ip.Is6() {
				pick = ip
				found = true
				break
			}
		}
	}
	if !found {
		return netip.Addr{}, 0, fmt.Errorf("endpoint %s has no usable address", host)
	}
	return pick, len(usable) - 1, nil
}
