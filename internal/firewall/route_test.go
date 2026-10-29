package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDefaultRouteAndMTU(t *testing.T) {
	gw, dev, err := DefaultRoute("default via 172.17.0.1 dev eth0\n")
	if err != nil || gw.String() != "172.17.0.1" || dev != "eth0" {
		t.Fatalf("%s %s %v", gw, dev, err)
	}
	gw, dev, err = DefaultRoute("default via fe80::1 dev eth0 proto ra metric 1024\n")
	if err != nil || gw.String() != "fe80::1" || dev != "eth0" {
		t.Fatalf("v6 %s %s %v", gw, dev, err)
	}
	if _, _, err := DefaultRoute("10.0.0.0/8 dev eth0\n"); err == nil {
		t.Fatal("missing default accepted")
	}
	n, err := ParseLinkMTU("2: eth0: <UP> mtu 1500 qdisc noqueue")
	if err != nil || n != 1500 {
		t.Fatalf("%d %v", n, err)
	}
	n, err = ParseLinkMTU("2: eth0: mtu 1450")
	if err != nil || n != 1450 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := ParseLinkMTU("no mtu here"); err == nil {
		t.Fatal("expected error")
	}
}

func TestReplaceViaFamily(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8:1::/64")
	v4 := netip.MustParseAddr("192.168.1.1")
	err := ReplaceVia(v6, v4, "eth0")
	if err == nil || !strings.Contains(err.Error(), "family mismatch") {
		t.Fatal(err)
	}
	err = ReplaceVia(netip.MustParsePrefix("0.0.0.0/0"), v4, "eth0")
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatal(err)
	}
}
