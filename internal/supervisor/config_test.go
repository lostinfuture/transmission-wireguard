package supervisor

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
)

func TestDefaults(t *testing.T) {
	cfg, err := LoadFrom(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dev != "wg0" || cfg.ConfigPath != "/etc/wireguard/wg0.conf" || cfg.Implementation != "kernel" {
		t.Fatalf("device %+v", cfg.Dev)
	}
	if cfg.HandshakeWait != 30*time.Second || !cfg.Kill || cfg.IPv6 || !cfg.PeerDNS || cfg.DropDefault {
		t.Fatalf("flags %+v", cfg)
	}
	if cfg.PUID != 1000 || cfg.PGID != 1000 || !cfg.ApplyPerms || cfg.Home != "/config/transmission-home" {
		t.Fatalf("identity %+v", cfg)
	}
	if cfg.OpenFiles != 8192 || !cfg.LogStdout || cfg.AllowUPnP || cfg.AllowScripts {
		t.Fatalf("transmission flags %+v", cfg)
	}
	if cfg.RPCUser != "" || cfg.RPCPassword != "" || cfg.RPCPort != 9091 || cfg.CacheMiB != nil {
		t.Fatal("rpc defaults")
	}
	if cfg.SelfHeal || cfg.Rustnet || cfg.RustnetRefresh != 5000 || cfg.RustnetPcap != "" || cfg.WebHome != "" {
		t.Fatalf("optional %+v", cfg)
	}
	if cfg.RootWarned || len(cfg.Local) != 0 || cfg.HealthHost != "" {
		t.Fatal("expected empty optional state")
	}
}

func TestDenylist(t *testing.T) {
	want := []string{
		"ENABLE_UFW",
		"UFW_EXTRA_PORTS",
		"UFW_ALLOW_GW_NET",
		"CREATE_TUN_DEVICE",
		"OPENVPN_PROVIDER",
		"OPENVPN_CONFIG",
		"OPENVPN_USERNAME",
		"OPENVPN_PASSWORD",
		"OPENVPN_OPTS",
		"OPENVPN_DCO",
		"VPN_CONFIG_SOURCE",
		"GITHUB_CONFIG_SOURCE_REPO",
		"GITHUB_CONFIG_SOURCE_REVISION",
		"PORT_FORWARD",
		"DISABLE_PORT_UPDATER",
		"PIA_TOKEN",
		"NORDVPN_COUNTRY",
		"NORDVPN_CATEGORY",
		"NORDVPN_PROTOCOL",
	}
	if strings.Join(want, ",") != strings.Join(denied, ",") {
		t.Fatalf("denylist = %v", denied)
	}
	for _, name := range want {
		t.Run(name, func(t *testing.T) {
			for _, val := range []string{"false", ""} {
				_, err := LoadFrom([]string{name + "=" + val})
				if err == nil || !strings.Contains(err.Error(), "unset "+name) {
					t.Fatalf("%s=%q: %v", name, val, err)
				}
			}
		})
	}
}

func TestWireGuardEnv(t *testing.T) {
	cfg, err := LoadFrom([]string{"WIREGUARD_CONFIG=", "WG_IMPLEMENTATION=kernel"})
	if err != nil || cfg.Dev != "wg0" || cfg.Implementation != "kernel" {
		t.Fatalf("%+v %v", cfg.Dev, err)
	}
	cfg, err = LoadFrom([]string{"WIREGUARD_CONFIG=wg1", "WG_HANDSHAKE_TIMEOUT=5"})
	if err != nil || cfg.Dev != "wg1" || cfg.ConfigPath != "/etc/wireguard/wg1.conf" || cfg.HandshakeWait != 5*time.Second {
		t.Fatalf("%s %s %s %v", cfg.Dev, cfg.ConfigPath, cfg.HandshakeWait, err)
	}
	cfg, err = LoadFrom([]string{"WG_HANDSHAKE_TIMEOUT=120"})
	if err != nil || cfg.HandshakeWait != 120*time.Second {
		t.Fatal(err)
	}
	for _, env := range []string{"WIREGUARD_CONFIG=../x", "WIREGUARD_CONFIG=wg0.conf", "WIREGUARD_CONFIG=" + strings.Repeat("a", 16)} {
		if _, err := LoadFrom([]string{env}); err == nil {
			t.Fatalf("%s accepted", env)
		}
	}
	_, err = LoadFrom([]string{"WG_IMPLEMENTATION=userspace"})
	if err == nil || err.Error() != "WG_IMPLEMENTATION=userspace is not in this release" {
		t.Fatal(err)
	}
	_, err = LoadFrom([]string{"WG_IMPLEMENTATION=Kernel"})
	if err == nil || !strings.Contains(err.Error(), "must be kernel or userspace") {
		t.Fatal(err)
	}
	for _, env := range []string{"WG_HANDSHAKE_TIMEOUT=4", "WG_HANDSHAKE_TIMEOUT=121", "WG_HANDSHAKE_TIMEOUT=fast"} {
		if _, err := LoadFrom([]string{env}); err == nil {
			t.Fatalf("%s accepted", env)
		}
	}
}

func TestLocalNetwork(t *testing.T) {
	cfg, err := LoadFrom([]string{"LOCAL_NETWORK=192.168.1.50/24, 10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Local) != 2 || cfg.Local[0].String() != "192.168.1.0/24" || cfg.Local[1].String() != "10.0.0.0/8" {
		t.Fatal(cfg.Local)
	}
	if _, err := LoadFrom([]string{"LOCAL_NETWORK=0.0.0.0/0"}); err == nil {
		t.Fatal("expected /0 rejection")
	}
	if _, err := LoadFrom([]string{"LOCAL_NETWORK=10.0.0.0/7"}); err == nil {
		t.Fatal("expected /7 rejection")
	}
	if _, err := LoadFrom([]string{"LOCAL_NETWORK=nope"}); err == nil {
		t.Fatal("expected parse rejection")
	}
	if _, err := LoadFrom([]string{"LOCAL_NETWORK=2001:db8::/64"}); err == nil || !strings.Contains(err.Error(), "ipv6 is disabled") {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"ENABLE_IPV6=true", "LOCAL_NETWORK=2001:db8::/64"})
	if err != nil || len(cfg.Local) != 1 || !cfg.IPv6 {
		t.Fatalf("%v %v", cfg.Local, err)
	}
	if _, err := LoadFrom([]string{"ENABLE_IPV6=true", "LOCAL_NETWORK=::/0"}); err == nil {
		t.Fatal("expected /0 rejection")
	}
}

func TestRPCAndCache(t *testing.T) {
	if _, err := LoadFrom([]string{"TRANSMISSION_RPC_USERNAME=u"}); err == nil {
		t.Fatal("expected one-sided username")
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_RPC_PASSWORD=p"}); err == nil {
		t.Fatal("expected one-sided password")
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_RPC_USER=u"}); err == nil {
		t.Fatal("expected one-sided alias")
	}
	cfg, err := LoadFrom([]string{"TRANSMISSION_RPC_USERNAME=a", "TRANSMISSION_RPC_USER=b", "TRANSMISSION_RPC_PASSWORD=c", "TRANSMISSION_RPC_PORT=9092"})
	if err != nil || cfg.RPCUser != "a" || cfg.RPCPassword != "c" || cfg.RPCPort != 9092 {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_RPC_USER=b", "TRANSMISSION_RPC_PASSWORD=c"})
	if err != nil || cfg.RPCUser != "b" || cfg.RPCPassword != "c" {
		t.Fatal(err)
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_RPC_PORT=0"}); err == nil {
		t.Fatal("expected port rejection")
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_RPC_PORT=65536"}); err == nil {
		t.Fatal("expected port rejection")
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_CACHE_SIZE_MIB=0"})
	if err != nil || cfg.CacheMiB == nil || *cfg.CacheMiB != 0 {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_CACHE_SIZE_MB=512", "TRANSMISSION_CACHE_SIZE_MIB=512"})
	if err != nil || cfg.CacheMiB == nil || *cfg.CacheMiB != 512 {
		t.Fatal(err)
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_CACHE_SIZE_MIB=512", "TRANSMISSION_CACHE_SIZE_MB=256"}); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatal(err)
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_CACHE_SIZE_MIB=-1"}); err == nil {
		t.Fatal("expected cache rejection")
	}
	if _, err := LoadFrom([]string{"TRANSMISSION_CACHE_SIZE_MB=nope"}); err == nil {
		t.Fatal("expected cache rejection")
	}
}

func TestOtherEnv(t *testing.T) {
	cfg, err := LoadFrom([]string{
		"TZ=US/Eastern",
		"TRANSMISSION_DOWNLOAD_DIRR=/x",
		"ENABLE_KILLSWITCH=false",
		"ENABLE_IPV6=off",
		"PEER_DNS=no",
		"DROP_DEFAULT_ROUTE=yes",
		"GLOBAL_APPLY_PERMISSIONS=0",
		"LOG_TO_STDOUT=FALSE",
		"ALLOW_UPNP=on",
		"ALLOW_TORRENT_SCRIPTS=1",
		"SELFHEAL=true",
		"ENABLE_RUSTNET=true",
		"RUSTNET_REFRESH_MS=1000",
		"RUSTNET_PCAP=/config/rustnet.pcap",
		"TRANSMISSION_HOME=/config",
		"OPEN_FILES_LIMIT=100",
		"HEALTH_CHECK_HOST=google.com",
		"PUID=0",
		"TRANSMISSION_WEB_UI=flood",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kill || cfg.IPv6 || cfg.PeerDNS || !cfg.DropDefault || cfg.ApplyPerms || cfg.LogStdout {
		t.Fatal("bool mismatch")
	}
	if !cfg.AllowUPnP || !cfg.AllowScripts || !cfg.SelfHeal || !cfg.Rustnet || cfg.RustnetRefresh != 1000 {
		t.Fatal("feature mismatch")
	}
	if cfg.RustnetPcap != "/config/rustnet.pcap" || cfg.Home != "/config" || cfg.OpenFiles != 100 {
		t.Fatal("path mismatch")
	}
	if cfg.HealthHost != "google.com" || cfg.PUID != 0 || cfg.PGID != 0 || !cfg.RootWarned {
		t.Fatal("id mismatch")
	}
	if cfg.WebHome != floodWebHome {
		t.Fatal(cfg.WebHome)
	}
	cfg, err = LoadFrom([]string{"PUID=4"})
	if err != nil || cfg.PUID != 4 || cfg.PGID != 4 {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"PGID=5"})
	if err != nil || cfg.PUID != 5 || cfg.PGID != 5 {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_WEB_UI=flood-for-transmission"})
	if err != nil || cfg.WebHome != floodWebHome {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_WEB_UI=transmissionic"})
	if err != nil || cfg.WebHome != transmissionicWebHome {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_WEB_UI=combustion", "TRANSMISSION_WEB_HOME=/opt/mine"})
	if err != nil || cfg.WebHome != "" {
		t.Fatal(err)
	}
	cfg, err = LoadFrom([]string{"TRANSMISSION_WEB_UI=stock"})
	if err != nil || cfg.WebHome != "" {
		t.Fatal(err)
	}
	for _, env := range []string{
		"ENABLE_KILLSWITCH=maybe",
		"TRANSMISSION_WEB_UI=combustion",
		"TRANSMISSION_WEB_UI=nope",
		"PUID=-1",
		"PGID=abc",
		"OPEN_FILES_LIMIT=0",
		"ENABLE_RUSTNET=maybe",
		"RUSTNET_REFRESH_MS=999",
		"RUSTNET_REFRESH_MS=fast",
		"RUSTNET_PCAP=/tmp/x.pcap",
		"RUSTNET_PCAP=relative.pcap",
		"SELFHEAL=maybe",
	} {
		if _, err := LoadFrom([]string{env}); err == nil {
			t.Fatalf("%s accepted", env)
		}
	}
}

func TestNoteRustnet(t *testing.T) {
	silent := captureLog(t, func() { NoteRustnet(false) })
	if silent != "" {
		t.Fatal(silent)
	}
	out := captureLog(t, func() { NoteRustnet(true) })
	if _, err := os.Stat("/usr/bin/rustnet"); err != nil {
		if !strings.Contains(out, "this arch has no Rustnet") {
			t.Fatal(out)
		}
		return
	}
	if out != "" {
		t.Fatal(out)
	}
}

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	logx.Capture(&buf, fn)
	return buf.String()
}
