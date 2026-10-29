package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestResolveSelection(t *testing.T) {
	old := lookupNetIP
	t.Cleanup(func() { lookupNetIP = old })
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("203.0.113.11"),
		}, nil
	}
	got, unused, err := Resolve("peer.test", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "203.0.113.10" || unused != 1 {
		t.Fatalf("pin=%s unused=%d", got, unused)
	}
	got, unused, err = Resolve("peer.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "203.0.113.10" || unused != 2 {
		t.Fatalf("v6 pin=%s unused=%d", got, unused)
	}
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::9")}, nil
	}
	if _, _, err := Resolve("peer.test", false); err == nil || !strings.Contains(err.Error(), "no usable address") {
		t.Fatal(err)
	}
	got, unused, err = Resolve("peer.test", true)
	if err != nil || got.String() != "2001:db8::9" || unused != 0 {
		t.Fatalf("%s %d %v", got, unused, err)
	}
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("timeout")
	}
	if _, _, err := Resolve("peer.test", false); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatal(err)
	}
	got, unused, err = Resolve("198.51.100.8", false)
	if err != nil || got.String() != "198.51.100.8" || unused != 0 {
		t.Fatalf("literal %s %d %v", got, unused, err)
	}
	if _, _, err := Resolve("2001:db8::2", false); err == nil || !strings.Contains(err.Error(), "ipv6 is disabled") {
		t.Fatal(err)
	}
}
