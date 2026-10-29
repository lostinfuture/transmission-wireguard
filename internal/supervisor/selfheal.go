package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/firewall"
	"github.com/lostinfuture/transmission-wireguard/internal/logx"
	"github.com/lostinfuture/transmission-wireguard/internal/wireguard"
)

const healEvery = 30 * time.Second

var (
	errHealAbort = errors.New("heal aborted")
	errHealDone  = errors.New("heal finished without a handshake")
)

// healTick decides one watchdog sample.
// A down tunnel resets the dial-failure count and does not restart.
// A missing address or a stale handshake restarts on this sample, including
// when HEALTH_CHECK_HOST is empty. The third failed dial restarts and resets
// the count. Age is one sample: 180s has already expired the session.
func healTick(up, hasAddr, stale bool, host string, dialOK bool, fails int) (int, bool, string) {
	if !up {
		return 0, false, ""
	}
	if !hasAddr {
		return 0, true, "wg address is missing"
	}
	if stale {
		return 0, true, "handshake is stale"
	}
	if host == "" {
		return 0, false, ""
	}
	if dialOK {
		return 0, false, ""
	}
	fails++
	if fails >= 3 {
		return 0, true, "health dial failed three times"
	}
	return fails, false, ""
}

// considerHeal applies one sample. The dial runs only when a dial result can
// change the decision. A stale handshake does not spend the 3s dial.
func considerHeal(up, hasAddr, stale bool, host string, fails int, dial func() bool) (int, bool, string) {
	dialOK := true
	if up && hasAddr && !stale && host != "" && dial != nil {
		dialOK = dial()
	}
	return healTick(up, hasAddr, stale, host, dialOK, fails)
}

func endpointLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

func parseNameservers(b []byte) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out
}

// dnsHop is one temporary clearnet hop for a nameserver.
// Route is set when a host route must be added. Allow is the 53 destination.
type dnsHop struct {
	Route netip.Addr
	Allow netip.Addr
}

// planDNS chooses host routes and 53 allows for one lookup.
// A nameserver that already leaves via extif gets no host route.
// A loopback nameserver, including 127.0.0.11, gets no route. Its allow is
// the saved gateway, because filter OUTPUT runs after Docker's DNS DNAT.
// An IPv6 nameserver is skipped when IPv6 is off.
func planDNS(servers []netip.Addr, gw4, gw6 netip.Addr, extif string, ipv6, kill, have6 bool, devOf func(netip.Addr) (string, bool)) []dnsHop {
	var out []dnsHop
	loop4 := false
	loop6 := false
	for _, ns := range servers {
		if !ns.IsValid() {
			continue
		}
		ns = ns.Unmap()
		if ns.Is6() && !ipv6 {
			continue
		}
		if ns.IsLoopback() {
			if ns.Is4() && !loop4 {
				loop4 = true
				if kill && gw4.IsValid() && gw4.Is4() {
					out = append(out, dnsHop{Allow: gw4})
				}
			}
			if ns.Is6() && have6 && !loop6 {
				loop6 = true
				if kill && gw6.IsValid() && gw6.Is6() {
					out = append(out, dnsHop{Allow: gw6})
				}
			}
			continue
		}
		if ns.Is6() && !have6 {
			continue
		}
		hop := dnsHop{}
		dev, ok := devOf(ns)
		if !ok || dev != extif {
			hop.Route = ns
		}
		if kill {
			hop.Allow = ns
		}
		if hop.Route.IsValid() || hop.Allow.IsValid() {
			out = append(out, hop)
		}
	}
	return out
}

func hostPrefix(a netip.Addr) netip.Prefix {
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits)
}

// watchHealth samples the device every 30s. It does not count failures while
// the tunnel is down or while a heal is already running.
func (s *Sup) watchHealth(ctx context.Context, healCh chan<- string) {
	tick := time.NewTicker(healEvery)
	defer tick.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.mu.Lock()
			closed := s.closed
			healing := s.healing
			up := s.tunnelUp
			local := s.local
			dev := s.cfg.Dev
			host := s.cfg.HealthHost
			pub := s.wg.PublicKey
			s.mu.Unlock()
			if closed || healing {
				continue
			}
			hasAddr := false
			stale := false
			if up {
				hasAddr = dev != "" && local != "" && addrOnDev(dev, local) == nil
				if hasAddr {
					ts, err := wireguard.Latest(dev, pub)
					if err != nil {
						stale = true
					} else {
						stale = handshakeNeedsRefresh(ts, time.Now().Unix())
					}
				}
			}
			next, restart, reason := considerHeal(up, hasAddr, stale, host, fails, func() bool {
				return dialTunHealth(local, host) == nil
			})
			fails = next
			if !restart {
				continue
			}
			select {
			case healCh <- reason:
			default:
			}
		}
	}
}

// heal restarts the tunnel inside this process. Failure leaves Transmission
// down and leaves the process running. Rustnet is not restarted.
func (s *Sup) heal(ctx context.Context, stop <-chan struct{}, reason string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errStopped
	}
	s.healing = true
	dev := s.cfg.Dev
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.healing = false
		s.mu.Unlock()
	}()
	logx.Info("supervisor", "restarting wireguard", "reason", reason)

	recorded, err := wireguard.Latest(dev, s.wg.PublicKey)
	if err != nil {
		s.mu.Lock()
		recorded = s.handshake
		s.mu.Unlock()
	}
	s.stopTM(true)
	if s.cfg.Kill && s.accepted {
		if rerr := s.fw.RevokeWG(); rerr != nil {
			logx.Warn("supervisor", "revoke failed", "error", rerr.Error())
		}
		s.accepted = false
		if werr := s.writeStatus(); werr != nil {
			logx.Warn("supervisor", "status write failed", "error", werr.Error())
		}
	}
	if signaled(stop) {
		return errStopped
	}
	ok, err := s.attemptA(stop, recorded)
	if errors.Is(err, errStopped) {
		return err
	}
	if errors.Is(err, errHealAbort) {
		return nil
	}
	if ok {
		s.bringBack(ctx, false)
		return nil
	}
	if signaled(stop) {
		return errStopped
	}
	if endpointLiteral(s.wg.EndpointHost) {
		logx.Warn("wireguard", "literal endpoint was not looked up", "dev", dev, "endpoint", s.pin.String())
		return nil
	}
	ok, err = s.attemptB(stop, recorded)
	if errors.Is(err, errStopped) {
		return err
	}
	if errors.Is(err, errHealAbort) || errors.Is(err, errHealDone) {
		return nil
	}
	if err != nil {
		return err
	}
	if ok {
		s.bringBack(ctx, true)
		return nil
	}
	logx.Warn("wireguard", "handshake timed out", "dev", dev, "endpoint", s.pin.String())
	return nil
}

func (s *Sup) bringBack(ctx context.Context, reapplyDNS bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if s.cfg.Kill {
		if err := s.fw.AllowWG(); err != nil {
			logx.Error("supervisor", "wg accept failed", "error", err.Error())
			return
		}
		s.accepted = true
	}
	s.mu.Lock()
	s.tunnelUp = true
	s.mu.Unlock()
	if reapplyDNS {
		if err := s.applyDNS(); err != nil {
			logx.Warn("supervisor", "dns restore failed", "error", err.Error())
		}
	}
	if err := s.writeStatus(); err != nil {
		logx.Warn("supervisor", "status write failed", "error", err.Error())
	}
	s.startTM(ctx)
}

// attemptA re-handshakes the current pin. It does not resolve.
func (s *Sup) attemptA(stop <-chan struct{}, recorded int64) (bool, error) {
	if err := wireguard.RemovePeer(s.cfg.Dev, s.wg.PublicKey); err != nil {
		logx.Warn("wireguard", "peer remove failed", "error", err.Error())
		return false, errHealAbort
	}
	endpoint := net.JoinHostPort(s.pin.String(), strconv.Itoa(s.wg.EndpointPort))
	if err := wireguard.ReaddPeer(s.cfg.Dev, s.wg, endpoint); err != nil {
		logx.Warn("wireguard", "peer add failed", "error", err.Error())
		return false, errHealAbort
	}
	if err := wireguard.Provoke(s.cfg.Dev, s.wg.PublicKey, keepOf(s.wg.Keepalive)); err != nil {
		logx.Warn("wireguard", "keepalive provoke failed", "error", err.Error())
		return false, errHealAbort
	}
	ts, err := s.waitFresh(stop, recorded, true)
	if errors.Is(err, errStopped) {
		return false, err
	}
	if err != nil {
		return false, nil
	}
	s.mu.Lock()
	s.handshake = ts
	s.mu.Unlock()
	return true, nil
}

// attemptB looks the hostname up, then handshakes only when the address changed.
// The temporary resolver path is closed before any wg set.
func (s *Sup) attemptB(stop <-chan struct{}, recorded int64) (bool, error) {
	raw, err := s.resolverBytes()
	if err != nil {
		logx.Warn("supervisor", "resolver read failed", "error", err.Error())
		return false, errHealDone
	}
	closeDNS := s.installResolver(parseNameservers(raw))
	defer closeDNS()
	next, unused, err := wireguard.Resolve(s.wg.EndpointHost, s.cfg.IPv6)
	closeDNS()
	if signaled(stop) {
		return false, errStopped
	}
	if err != nil {
		logx.Warn("wireguard", "endpoint lookup failed", "error", err.Error())
		return false, errHealDone
	}
	if next == s.pin {
		logx.Warn("wireguard", "endpoint lookup returned the current pin", "ip", next.String())
		return false, errHealDone
	}
	if err := s.moveEndpoint(next); err != nil {
		logx.Warn("wireguard", "endpoint move failed", "error", err.Error())
		return false, errHealDone
	}
	logx.Info("wireguard", "endpoint pinned", "ip", next.String(), "port", strconv.Itoa(s.wg.EndpointPort), "unused", strconv.Itoa(unused))
	return s.attemptA(stop, recorded)
}

func (s *Sup) resolverBytes() ([]byte, error) {
	if s.resolvTouched {
		saved := append([]byte(nil), s.resolvSaved...)
		s.restoreResolv()
		return saved, nil
	}
	return os.ReadFile(resolvPath)
}

// installResolver opens the temporary DNS path. The returned function is
// idempotent so a defer and the explicit close before wg set agree.
func (s *Sup) installResolver(servers []netip.Addr) func() {
	hops := planDNS(servers, s.gw4, s.gw6, s.extif, s.cfg.IPv6, s.cfg.Kill, s.have6, func(a netip.Addr) (string, bool) {
		dev, err := firewall.RouteGet(a)
		return dev, err == nil
	})
	var routes []netip.Prefix
	var allows []netip.Addr
	for _, h := range hops {
		if h.Route.IsValid() {
			p := hostPrefix(h.Route)
			gw := s.gw4
			if h.Route.Is6() {
				gw = s.gw6
			}
			if err := firewall.ReplaceVia(p, gw, s.extif); err != nil {
				logx.Warn("supervisor", "resolver route failed", "ip", h.Route.String(), "error", err.Error())
			} else {
				routes = append(routes, p)
			}
		}
		if h.Allow.IsValid() {
			if err := s.fw.AllowResolver(h.Allow); err != nil {
				logx.Warn("supervisor", "resolver allow failed", "ip", h.Allow.String(), "error", err.Error())
			} else {
				allows = append(allows, h.Allow)
			}
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, p := range routes {
				gw := s.gw4
				if p.Addr().Is6() {
					gw = s.gw6
				}
				if err := firewall.DelHostVia(p, gw, s.extif); err != nil {
					logx.Warn("supervisor", "resolver route remained", "route", p.String(), "error", err.Error())
				}
			}
			for _, a := range allows {
				_ = s.fw.RevokeResolver(a)
			}
		})
	}
}

func (s *Sup) moveEndpoint(next netip.Addr) error {
	old := s.pin
	if !old.IsValid() || !next.IsValid() {
		return errors.New("endpoint address is required")
	}
	if old.Is4() != next.Is4() {
		return errors.New("route family mismatch")
	}
	if next.Is6() && !s.have6 {
		return errors.New("no ipv6 gateway")
	}
	gw := s.gw4
	if next.Is6() {
		gw = s.gw6
	}
	nextP := hostPrefix(next)
	if err := firewall.ReplaceVia(nextP, gw, s.extif); err != nil {
		return err
	}
	if err := s.fw.ReplaceEndpoint(old, next, s.wg.EndpointPort); err != nil {
		_ = firewall.DelHostVia(nextP, gw, s.extif)
		return err
	}
	oldGw := s.gw4
	if old.Is6() {
		oldGw = s.gw6
	}
	if err := firewall.DelHostVia(hostPrefix(old), oldGw, s.extif); err != nil {
		logx.Warn("supervisor", "old endpoint route remained", "error", err.Error())
	}
	s.mu.Lock()
	s.pin = next
	s.fw.Endpoint = next
	s.mu.Unlock()
	return nil
}
