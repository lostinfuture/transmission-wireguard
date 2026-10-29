package supervisor

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
)

var resolvPath = "/etc/resolv.conf"

func writeResolv(path string, servers, search []string) error {
	var b strings.Builder
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	for _, s := range servers {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("dns address %q", s)
		}
		fmt.Fprintf(&b, "nameserver %s\n", addr)
	}
	if b.Len() == 0 {
		return fmt.Errorf("no nameservers")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(b.String())
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func (s *Sup) applyDNS() error {
	if !s.cfg.PeerDNS {
		logx.Info("supervisor", "Docker DNS was left in place")
		return nil
	}
	if len(s.wg.DNS) == 0 {
		logx.Warn("supervisor", "WireGuard file has no DNS=; leaving Docker DNS in place")
		return nil
	}
	b, err := os.ReadFile(resolvPath)
	if err != nil {
		return err
	}
	s.resolvSaved = append([]byte(nil), b...)
	servers := make([]string, len(s.wg.DNS))
	for i, addr := range s.wg.DNS {
		servers[i] = addr.String()
	}
	if err := writeResolv(resolvPath, servers, s.wg.Search); err != nil {
		return err
	}
	s.resolvTouched = true
	return nil
}

func (s *Sup) restoreResolv() {
	if !s.resolvTouched || s.resolvSaved == nil {
		return
	}
	f, err := os.OpenFile(resolvPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		logx.Warn("supervisor", "resolv.conf restore failed", "error", err.Error())
		return
	}
	_, werr := f.Write(s.resolvSaved)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		logx.Warn("supervisor", "resolv.conf restore failed")
		return
	}
	s.resolvTouched = false
}
