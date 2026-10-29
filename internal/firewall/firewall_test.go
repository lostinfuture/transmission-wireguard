package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func TestGoldenRules(t *testing.T) {
	fw := Firewall{
		ExtIf:        "eth0",
		WGDev:        "wg0",
		RPCPort:      9091,
		PeerPort:     51413,
		Endpoint:     netip.MustParseAddr("203.0.113.10"),
		EndpointPort: 51820,
		Local:        []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
	out := join(fw.V4Out())
	wantOut := strings.Join([]string{
		"-o lo -j ACCEPT",
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-o eth0 -d 203.0.113.10 -p udp --dport 51820 -j ACCEPT",
		"-o eth0 -d 192.168.1.0/24 -j ACCEPT",
		"-j DROP",
	}, "\n")
	if out != wantOut {
		t.Fatalf("v4 out:\n%s", out)
	}
	in := join(fw.V4In())
	wantIn := strings.Join([]string{
		"-i lo -j ACCEPT",
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-i eth0 -p icmp --icmp-type 3 -j ACCEPT",
		"-i eth0 -s 203.0.113.10 -p udp --sport 51820 -j ACCEPT",
		"-i eth0 -p tcp --dport 9091 -j ACCEPT",
		"-i wg0 -p tcp --dport 9091 -j DROP",
		"-i wg0 -j DROP",
	}, "\n")
	if in != wantIn {
		t.Fatalf("v4 in:\n%s", in)
	}
	if join(Disabled6()) != strings.Join([]string{
		"-w -P INPUT DROP",
		"-w -P OUTPUT DROP",
		"-w -I INPUT 1 -i lo -j ACCEPT",
		"-w -I OUTPUT 1 -o lo -j ACCEPT",
	}, "\n") {
		t.Fatal(join(Disabled6()))
	}
	fw.IPv6 = true
	fw.Endpoint = netip.MustParseAddr("2001:db8::10")
	fw.Local = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	if !strings.Contains(join(fw.V6Out()), "-o eth0 -d 2001:db8::10 -p udp --dport 51820 -j ACCEPT") {
		t.Fatal(join(fw.V6Out()))
	}
	if !strings.Contains(join(fw.V6In()), "--sport 51820") || !strings.Contains(join(fw.V6In()), "packet-too-big") {
		t.Fatal(join(fw.V6In()))
	}
	if strings.Contains(join(fw.V6Out()), "203.0.113.10") {
		t.Fatal("v4 endpoint leaked into v6 rules")
	}
}

func TestReplaceEndpointShape(t *testing.T) {
	old := endpointOut("eth0", "203.0.113.10", 51820)
	next := endpointOut("eth0", "203.0.113.11", 51820)
	if strings.Join(old, " ") == strings.Join(next, " ") {
		t.Fatal("rules did not change")
	}
	in := endpointIn("eth0", "203.0.113.11", 51820)
	if !strings.Contains(strings.Join(in, " "), "--sport 51820") || !strings.Contains(strings.Join(in, " "), "-s 203.0.113.11") {
		t.Fatal(in)
	}
}

func TestValidateIf(t *testing.T) {
	if err := validateIf("eth0"); err != nil {
		t.Fatal(err)
	}
	if err := validateIf("tun+"); err == nil {
		t.Fatal("wildcard accepted")
	}
	if err := validateIf(""); err == nil {
		t.Fatal("empty accepted")
	}
}

func join(rules [][]string) string {
	lines := make([]string, len(rules))
	for i, r := range rules {
		lines[i] = strings.Join(r, " ")
	}
	return strings.Join(lines, "\n")
}
