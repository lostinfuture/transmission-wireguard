package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/firewall"
	"github.com/lostinfuture/transmission-wireguard/internal/logx"
	"github.com/lostinfuture/transmission-wireguard/internal/transmission"
	"github.com/lostinfuture/transmission-wireguard/internal/wireguard"
)

// Sup is one container run.
type Sup struct {
	cfg           Config
	wg            wireguard.Config
	pin           netip.Addr
	mtu           int
	gw4           netip.Addr
	gw6           netip.Addr
	have6         bool
	extif         string
	fw            firewall.Firewall
	installed     bool
	accepted      bool
	created       bool
	restore4      bool
	restore6      bool
	resolvSaved   []byte
	resolvTouched bool
	rpcPort       int
	peerPort      int
	dump          map[string]any
	user          map[string]any
	env           []string
	local         string
	local6        string
	handshake     int64

	mu          sync.Mutex
	cond        *sync.Cond
	closed      bool
	tornDown    bool
	starting    bool
	stopping    bool
	stoppedTM   bool
	died        bool
	startedPath bool
	tunnelUp    bool
	tm          *exec.Cmd
	tmCancel    context.CancelFunc
	tmExited    chan struct{}
	stopWait    chan struct{}
	unexp       chan struct{}
	reasserted  map[string]time.Time
}

// Run brings the tunnel up, starts Transmission, and blocks until stop.
func Run(cfg Config) error {
	NoteRustnet(cfg.Rustnet)
	s := &Sup{cfg: cfg, env: os.Environ(), unexp: make(chan struct{}, 1)}
	s.cond = sync.NewCond(&s.mu)
	if cfg.RootWarned {
		logx.Warn("supervisor", "PUID=0 runs Transmission as root; the kill switch is best-effort")
	}
	if !cfg.Kill {
		logx.Warn("supervisor", "ENABLE_KILLSWITCH=false disables the egress drop")
	}
	if cfg.SelfHeal {
		logx.Info("supervisor", "SELFHEAL is not implemented; the tunnel will not be restarted in-process")
	}
	if cfg.AllowUPnP {
		logx.Warn("supervisor", "ALLOW_UPNP=true lets Transmission map ports on the LAN")
	}
	if cfg.AllowScripts {
		logx.Warn("supervisor", "ALLOW_TORRENT_SCRIPTS=true lets RPC clients run scripts")
	}
	for _, p := range cfg.Local {
		if p.Bits() < 16 {
			logx.Warn("supervisor", "LOCAL_NETWORK is wider than /16", "cidr", p.String())
		}
	}
	wg, err := wireguard.Open(dirOf(cfg.ConfigPath), cfg.Dev, cfg.IPv6)
	if err != nil {
		return err
	}
	s.wg = wg
	pin, unused, err := wireguard.Resolve(wg.EndpointHost, cfg.IPv6)
	if err != nil {
		return err
	}
	s.pin = pin
	logx.Info("wireguard", "endpoint pinned", "ip", pin.String(), "port", strconv.Itoa(wg.EndpointPort), "unused", strconv.Itoa(unused))
	if v4, ok := firstAddr(wg.Addresses, true); ok {
		s.local = v4.String()
	} else {
		return errors.New("wireguard address needs an ipv4")
	}
	if v6, ok := firstAddr(wg.Addresses, false); ok {
		s.local6 = v6.String()
	}

	dump, err := transmission.DumpSettings(transBin)
	if err != nil {
		return err
	}
	user, err := readUserSettings(s.cfg.Home + "/settings.json")
	if err != nil {
		return err
	}
	s.dump, s.user = dump, user
	merged, err := s.merge("")
	if err != nil {
		return err
	}
	s.rpcPort = transmission.Int(merged, "rpc_port", cfg.RPCPort)
	s.peerPort = transmission.Int(merged, "peer_port", 51413)
	if s.rpcPort == s.peerPort {
		return fmt.Errorf("peer port %d equals rpc port", s.peerPort)
	}
	if err := os.MkdirAll(cfg.Home, 0o755); err != nil {
		return err
	}
	for _, dir := range []string{"/data/completed", "/data/incomplete", "/data/watch"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := s.ownFiles(); err != nil {
		return err
	}

	gw4, extif, err := firewall.ReadDefaultRoute4()
	if err != nil {
		return err
	}
	s.gw4, s.extif = gw4, extif
	if cfg.IPv6 && (pin.Is6() || any6(cfg.Local)) {
		gw6, dev6, err := firewall.ReadDefaultRoute6()
		if err != nil {
			return err
		}
		if dev6 != extif {
			return fmt.Errorf("ipv6 default dev %s does not match %s", dev6, extif)
		}
		s.gw6 = gw6
		s.have6 = true
	}
	extMTU, merr := firewall.LinkMTU(extif)
	mtu, note, err := wireguard.DeriveMTU(wg.MTU, extMTU, merr == nil, cfg.IPv6)
	if err != nil {
		return err
	}
	if note != "" {
		logx.Warn("wireguard", note, "dev", extif)
	}
	if !cfg.IPv6 && mtu < 1280 {
		logx.Info("wireguard", "mtu is below 1280 on an ipv4-only tunnel", "mtu", strconv.Itoa(mtu))
	}
	s.mtu = mtu
	logx.Info("wireguard", "mtu", "dev", cfg.Dev, "mtu", strconv.Itoa(mtu))

	s.fw = firewall.Firewall{
		ExtIf:        extif,
		WGDev:        cfg.Dev,
		RPCPort:      s.rpcPort,
		PeerPort:     s.peerPort,
		Local:        cfg.Local,
		Endpoint:     pin,
		EndpointPort: wg.EndpointPort,
		IPv6:         cfg.IPv6,
	}
	if cfg.Kill {
		if err := s.fw.Install(); err != nil {
			return err
		}
		s.installed = true
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	var once sync.Once
	requestStop := func() { once.Do(func() { close(stop) }) }
	go func() {
		select {
		case <-sig:
			requestStop()
		case <-done:
		}
	}()

	fail := func(err error) error {
		s.teardown()
		return err
	}
	if err := s.pinRoutes(); err != nil {
		return fail(err)
	}
	if err := s.runScript(context.Background(), "/scripts/wireguard-pre-start.sh", s.hookArgs("init")); err != nil {
		return fail(err)
	}
	if signaled(stop) {
		s.teardown()
		return nil
	}
	if err := wireguard.AddLink(cfg.Dev); err != nil {
		return fail(err)
	}
	s.created = true
	addrs := make([]fmt.Stringer, len(wg.Addresses))
	for i, a := range wg.Addresses {
		addrs[i] = a
	}
	if err := wireguard.ConfigureLink(cfg.Dev, addrs, mtu); err != nil {
		return fail(err)
	}
	endpoint := net.JoinHostPort(pin.String(), strconv.Itoa(wg.EndpointPort))
	if err := wireguard.Apply(cfg.Dev, wg, endpoint); err != nil {
		return fail(err)
	}
	if err := wireguard.LinkUp(cfg.Dev); err != nil {
		return fail(err)
	}
	keep := 0
	if wg.Keepalive != nil {
		keep = *wg.Keepalive
	}
	if keep <= 0 {
		if err := wireguard.Kick(cfg.Dev, wg.PublicKey); err != nil {
			return fail(err)
		}
	}
	if err := s.tunnelRoutes(); err != nil {
		return fail(err)
	}
	ts, err := s.waitHandshake(stop)
	if err != nil {
		if errors.Is(err, errStopped) {
			s.teardown()
			return nil
		}
		logx.Error("wireguard", "handshake timed out", "dev", cfg.Dev, "endpoint", pin.String())
		return fail(err)
	}
	s.handshake = ts
	if cfg.Kill {
		if err := s.fw.AllowWG(); err != nil {
			return fail(err)
		}
		s.accepted = true
	}
	s.mu.Lock()
	s.tunnelUp = true
	s.mu.Unlock()
	if err := s.applyDNS(); err != nil {
		return fail(err)
	}
	if err := s.dropOriginal(); err != nil {
		return fail(err)
	}
	if err := s.writeStatus(); err != nil {
		logx.Warn("supervisor", "status write failed", "error", err.Error())
	}
	logx.Info("supervisor", "tunnel up", "dev", cfg.Dev, "mtu", strconv.Itoa(mtu), "bind", s.local)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-stop:
			cancel()
		case <-done:
			cancel()
		}
	}()
	s.startTM(ctx)

	select {
	case <-stop:
		s.teardown()
		return nil
	case <-s.unexp:
		s.teardown()
		return errors.New("transmission exited")
	}
}

func (s *Sup) teardown() {
	s.mu.Lock()
	if s.tornDown {
		s.mu.Unlock()
		return
	}
	s.tornDown = true
	s.closed = true
	s.mu.Unlock()
	s.stopTM(true)
	if s.accepted && s.cfg.Kill {
		_ = s.fw.RevokeWG()
		s.accepted = false
	}
	if s.created {
		_ = wireguard.LinkDel(s.cfg.Dev)
		s.created = false
	}
	s.restoreResolv()
	if s.restore4 && s.gw4.IsValid() {
		_ = firewall.RestoreDefault(s.gw4, s.extif)
	}
	if s.restore6 && s.gw6.IsValid() {
		_ = firewall.RestoreDefault(s.gw6, s.extif)
	}
	if s.installed && s.cfg.Kill {
		s.fw.Cleanup()
		s.installed = false
	}
	s.mu.Lock()
	s.tunnelUp = false
	s.mu.Unlock()
	_ = s.writeStatus()
}

func (s *Sup) pinRoutes() error {
	for _, p := range s.cfg.Local {
		gw := s.gw4
		if p.Addr().Is6() {
			if !s.have6 {
				return fmt.Errorf("no ipv6 gateway for %s", p)
			}
			gw = s.gw6
		}
		if err := firewall.ReplaceVia(p, gw, s.extif); err != nil {
			return err
		}
	}
	gw := s.gw4
	bits := 32
	if s.pin.Is6() {
		if !s.have6 {
			return fmt.Errorf("no ipv6 gateway for %s", s.pin)
		}
		gw = s.gw6
		bits = 128
	}
	return firewall.ReplaceVia(netip.PrefixFrom(s.pin, bits), gw, s.extif)
}

func (s *Sup) tunnelRoutes() error {
	for _, p := range s.wg.AllowedIPs {
		if p.Addr().Is6() && !s.cfg.IPv6 {
			continue
		}
		if err := firewall.ReplaceDev(p, s.cfg.Dev); err != nil {
			return err
		}
		if p.Bits() == 0 && p.Addr().Is4() {
			s.restore4 = true
		}
		if p.Bits() == 0 && p.Addr().Is6() {
			s.restore6 = true
		}
	}
	return nil
}

func (s *Sup) dropOriginal() error {
	if !s.cfg.DropDefault {
		return nil
	}
	deleted := false
	if !s.restore4 && firewall.OriginalInstalled(s.gw4, s.extif) {
		if err := firewall.DelDefault(s.gw4, s.extif); err != nil {
			return err
		}
		s.restore4 = true
		deleted = true
	}
	if s.have6 && !s.restore6 && firewall.OriginalInstalled(s.gw6, s.extif) {
		if err := firewall.DelDefault(s.gw6, s.extif); err != nil {
			return err
		}
		s.restore6 = true
		deleted = true
	}
	if deleted {
		logx.Warn("supervisor", "DROP_DEFAULT_ROUTE removes the original default route; a later route add bypasses it; the OUTPUT drop does not")
	}
	return nil
}

func (s *Sup) waitHandshake(stop <-chan struct{}) (int64, error) {
	deadline := time.Now().Add(s.cfg.HandshakeWait)
	for {
		ts, err := wireguard.Latest(s.cfg.Dev, s.wg.PublicKey)
		if err == nil && wireguard.Fresh(ts, time.Now().Unix(), 0, false) {
			return ts, nil
		}
		if !time.Now().Before(deadline) {
			return 0, errors.New("handshake timed out")
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-stop:
			timer.Stop()
			return 0, errStopped
		case <-timer.C:
		}
	}
}

func signaled(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func firstAddr(ps []netip.Prefix, v4 bool) (netip.Addr, bool) {
	for _, p := range ps {
		if v4 && p.Addr().Is4() {
			return p.Addr(), true
		}
		if !v4 && p.Addr().Is6() {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

func any6(ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

func dirOf(path string) string {
	i := len(path) - 1
	for i >= 0 && path[i] != '/' {
		i--
	}
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
