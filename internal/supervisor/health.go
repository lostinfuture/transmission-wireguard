package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/firewall"
	"github.com/lostinfuture/transmission-wireguard/internal/wireguard"
)

var statusPath = "/run/wg-supervisor/status.json"

type status struct {
	Dev                 string `json:"dev"`
	WGIPv4              string `json:"wg_ipv4"`
	WGIPv6              string `json:"wg_ipv6,omitempty"`
	EndpointIP          string `json:"endpoint_ip"`
	HandshakeUnix       int64  `json:"handshake_unix"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	RPCPort             int    `json:"rpc_port"`
	PeerPort            int    `json:"peer_port"`
	WGEgressAccept      bool   `json:"wg_egress_accept"`
	TunnelUp            bool   `json:"tunnel_up"`
	KillSwitch          bool   `json:"kill_switch"`
	HealthHost          string `json:"health_host,omitempty"`
	TransmissionPID     int    `json:"transmission_pid"`
}

func keepOf(k *int) int {
	if k == nil || *k < 0 {
		return 0
	}
	return *k
}

func (s *Sup) writeStatus() error {
	s.mu.Lock()
	st := status{
		Dev:                 s.cfg.Dev,
		WGIPv4:              s.local,
		WGIPv6:              s.local6,
		HandshakeUnix:       s.handshake,
		PersistentKeepalive: keepOf(s.wg.Keepalive),
		RPCPort:             s.rpcPort,
		PeerPort:            s.peerPort,
		WGEgressAccept:      s.accepted,
		TunnelUp:            s.tunnelUp,
		KillSwitch:          s.cfg.Kill,
		HealthHost:          s.cfg.HealthHost,
	}
	if s.pin.IsValid() {
		st.EndpointIP = s.pin.String()
	}
	if s.tm != nil && s.tm.Process != nil {
		st.TransmissionPID = s.tm.Process.Pid
	}
	s.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o700); err != nil {
		return err
	}
	tmp := statusPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statusPath)
}

func validateStatus(st status) error {
	if !st.TunnelUp || st.Dev == "" || st.WGIPv4 == "" {
		return errors.New("tunnel is down")
	}
	return nil
}

// handshakeNeedsRefresh is true when the handshake is missing or older than 180s.
func handshakeNeedsRefresh(ts, now int64) bool {
	if ts <= 0 {
		return true
	}
	return now-ts > 180
}

// Healthcheck is the Docker HEALTHCHECK.
func Healthcheck() error {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return fmt.Errorf("no status: %w", err)
	}
	var st status
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if err := validateStatus(st); err != nil {
		return err
	}
	if err := addrOnDev(st.Dev, st.WGIPv4); err != nil {
		return err
	}
	if err := refreshIfStale(st.Dev, st.PersistentKeepalive); err != nil {
		return err
	}
	if st.KillSwitch {
		fw := firewall.Firewall{WGDev: st.Dev}
		if !fw.HasWGAccept() {
			return errors.New("wg egress accept is missing")
		}
		if err := sportInstalled(st.Dev, st.EndpointIP); err != nil {
			return err
		}
	}
	if st.RPCPort < 1 {
		return errors.New("rpc port is missing")
	}
	url := "http://127.0.0.1:" + strconv.Itoa(st.RPCPort) + "/transmission/web/"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case 200, 401, 409:
	default:
		return fmt.Errorf("rpc http %d", resp.StatusCode)
	}
	if st.HealthHost != "" {
		if err := dialTunHealth(st.WGIPv4, st.HealthHost); err != nil {
			return err
		}
	}
	return nil
}

func refreshIfStale(dev string, configured int) error {
	pub, ts, err := wireguard.PeerHandshake(dev)
	if err != nil {
		return err
	}
	if pub == "" {
		return errors.New("handshake is missing")
	}
	if !handshakeNeedsRefresh(ts, time.Now().Unix()) {
		return nil
	}
	return wireguard.ApplyKeepaliveEdge(func(n int) error {
		return wireguard.SetKeepalive(dev, pub, n)
	}, configured, func() bool {
		deadline := time.Now().Add(3 * time.Second)
		for {
			got, err := wireguard.Latest(dev, pub)
			if err == nil && got > ts && wireguard.Fresh(got, time.Now().Unix(), ts, true) {
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
}

func sportInstalled(dev, ip string) error {
	pub, _, err := wireguard.PeerHandshake(dev)
	if err != nil {
		return err
	}
	_, port, err := wireguard.ShowEndpoint(dev, pub)
	if err != nil {
		return err
	}
	out, err := exec.Command("iptables", "-w", "-S", "INPUT").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	text := string(out)
	if !strings.Contains(text, fmt.Sprintf("--sport %d", port)) {
		return errors.New("endpoint sport allow is missing")
	}
	if ip != "" && !strings.Contains(text, ip) {
		return errors.New("endpoint sport allow is missing")
	}
	return nil
}

func addrOnDev(dev, want string) error {
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr %s: %w", dev, err)
	}
	text := string(out)
	if !strings.Contains(text, want+"/") && !strings.Contains(text, " "+want+" ") && !strings.Contains(text, " "+want+"\n") {
		return fmt.Errorf("%s has no address %s", dev, want)
	}
	return nil
}

func dialTunHealth(local, host string) error {
	ip := net.ParseIP(local)
	if ip == nil {
		return fmt.Errorf("bind address %q", local)
	}
	d := &net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: &net.TCPAddr{IP: ip},
	}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return err
	}
	return conn.Close()
}
