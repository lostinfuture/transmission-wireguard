package supervisor

import (
	"net/netip"
	"testing"
)

func TestHealTick(t *testing.T) {
	cases := []struct {
		name   string
		up     bool
		has    bool
		stale  bool
		host   string
		dial   bool
		fails  int
		next   int
		heal   bool
		reason string
	}{
		{"down resets", false, true, true, "h", false, 2, 0, false, ""},
		{"missing address", true, false, false, "h", false, 2, 0, true, "wg address is missing"},
		{"stale with empty host", true, true, true, "", false, 1, 0, true, "handshake is stale"},
		{"fresh empty host", true, true, false, "", false, 1, 0, false, ""},
		{"dial ok", true, true, false, "h", true, 2, 0, false, ""},
		{"dial fail 1", true, true, false, "h", false, 0, 1, false, ""},
		{"dial fail 2", true, true, false, "h", false, 1, 2, false, ""},
		{"dial fail 3", true, true, false, "h", false, 2, 0, true, "health dial failed three times"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next, heal, reason := healTick(tc.up, tc.has, tc.stale, tc.host, tc.dial, tc.fails)
			if next != tc.next || heal != tc.heal || reason != tc.reason {
				t.Fatalf("got %d %v %q", next, heal, reason)
			}
		})
	}
}

func TestConsiderHealSkipsDialWhenStale(t *testing.T) {
	called := false
	next, heal, reason := considerHeal(true, true, true, "example.com", 2, func() bool {
		called = true
		return false
	})
	if called || !heal || reason != "handshake is stale" || next != 0 {
		t.Fatalf("called %v heal %v reason %q next %d", called, heal, reason, next)
	}
	called = false
	next, heal, reason = considerHeal(false, true, false, "example.com", 2, func() bool {
		called = true
		return false
	})
	if called || heal || next != 0 || reason != "" {
		t.Fatalf("down called %v heal %v next %d", called, heal, next)
	}
}

func TestEndpointLiteral(t *testing.T) {
	if !endpointLiteral("82.29.100.2") || !endpointLiteral("203.0.113.10") || !endpointLiteral("2001:db8::1") {
		t.Fatal("literal rejected")
	}
	if endpointLiteral("vpn.example") || endpointLiteral("") {
		t.Fatal("hostname accepted")
	}
}

func TestParseNameservers(t *testing.T) {
	text := "# resolver\nnameserver 127.0.0.11\nnameserver\t1.1.1.1\nsearch example\nnameserver not-an-ip\nnameserver 2001:db8::53\n"
	got := parseNameservers([]byte(text))
	want := []string{"127.0.0.11", "1.1.1.1", "2001:db8::53"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i, addr := range got {
		if addr.String() != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

func TestPlanDNS(t *testing.T) {
	gw4 := netip.MustParseAddr("192.0.2.1")
	gw6 := netip.MustParseAddr("2001:db8::1")
	devOf := func(a netip.Addr) (string, bool) {
		switch a.String() {
		case "1.1.1.1":
			return "wg0", true
		case "9.9.9.9":
			return "eth0", true
		case "2001:db8::53":
			return "wg0", true
		default:
			return "", false
		}
	}
	servers := []netip.Addr{
		netip.MustParseAddr("127.0.0.11"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("2001:db8::53"),
	}
	hops := planDNS(servers, gw4, gw6, "eth0", false, true, false, devOf)
	if len(hops) != 3 {
		t.Fatalf("ipv4 hops %d %#v", len(hops), hops)
	}
	if hops[0].Route.IsValid() || hops[0].Allow != gw4 {
		t.Fatalf("loopback %#v", hops[0])
	}
	if hops[1].Route.String() != "1.1.1.1" || hops[1].Allow.String() != "1.1.1.1" {
		t.Fatalf("tunnel dns %#v", hops[1])
	}
	if hops[2].Route.IsValid() || hops[2].Allow.String() != "9.9.9.9" {
		t.Fatalf("clearnet dns %#v", hops[2])
	}

	hops = planDNS(servers, gw4, gw6, "eth0", false, false, false, devOf)
	if len(hops) != 1 || hops[0].Allow.IsValid() || hops[0].Route.String() != "1.1.1.1" {
		t.Fatalf("kill off %#v", hops)
	}

	v6servers := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("2001:db8::53")}
	hops = planDNS(v6servers, gw4, gw6, "eth0", true, true, true, devOf)
	if len(hops) != 2 {
		t.Fatalf("v6 %#v", hops)
	}
	if hops[0].Route.IsValid() || hops[0].Allow != gw6 {
		t.Fatalf("v6 loop %#v", hops[0])
	}
	if hops[1].Route.String() != "2001:db8::53" || hops[1].Allow.String() != "2001:db8::53" {
		t.Fatalf("v6 ns %#v", hops[1])
	}
}
