package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
	"github.com/lostinfuture/transmission-wireguard/internal/transmission"
)

const (
	transBin      = "transmission-daemon"
	transKill     = 10 * time.Second
	reassertEvery = 30 * time.Second
)

var scriptKeys = []string{
	"script_torrent_done_enabled",
	"script_torrent_done_seeding_enabled",
	"script_torrent_added_enabled",
}

func (s *Sup) merge(tunIP string) (map[string]any, error) {
	return transmission.Merge(s.dump, s.user, s.env, transmission.Options{
		AllowUPnP:    s.cfg.AllowUPnP,
		AllowScripts: s.cfg.AllowScripts,
		RPCUser:      s.cfg.RPCUser,
		RPCPassword:  s.cfg.RPCPassword,
		TunIPv4:      tunIP,
	})
}

func (s *Sup) startTM(ctx context.Context) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	s.starting = true
	s.startedPath = true
	s.tmCancel = cancel
	s.mu.Unlock()
	finish := func() {
		s.mu.Lock()
		s.starting = false
		s.cond.Broadcast()
		s.mu.Unlock()
	}
	args := s.hookArgs("up")
	if err := s.runScript(ctx, "/scripts/transmission-pre-start.sh", args); err != nil {
		logx.Error("supervisor", "pre-start script failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	merged, err := s.merge(s.local)
	if err != nil {
		logx.Error("supervisor", "settings merge failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	if s.cfg.IPv6 && s.local6 != "" {
		merged["bind_address_ipv6"] = s.local6
	}
	if err := writeSettings(filepath.Join(s.cfg.Home, "settings.json"), merged, s.cfg.PUID, s.cfg.PGID); err != nil {
		logx.Error("supervisor", "settings write failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	targs := []string{
		"--foreground",
		"--config-dir", s.cfg.Home,
		"--bind-address-ipv4", s.local,
		"--rpc-bind-address", "0.0.0.0",
		"--port", strconv.Itoa(s.rpcPort),
		"--peerport", strconv.Itoa(s.peerPort),
		"--no-lpd",
	}
	if s.cfg.IPv6 && s.local6 != "" {
		targs = append(targs, "--bind-address-ipv6", s.local6)
	}
	if !s.cfg.AllowUPnP {
		targs = append(targs, "--no-portmap")
	}
	if !s.cfg.LogStdout {
		targs = append(targs, "--logfile", filepath.Join(s.cfg.Home, "transmission.log"))
	}
	var cmd *exec.Cmd
	if s.cfg.PUID == 0 {
		cmd = exec.Command(transBin, targs...)
		cmd.Env = s.transmissionEnv()
	} else {
		self, err := os.Executable()
		if err != nil {
			self = "/usr/bin/wg-supervisor"
		}
		argv := []string{"drop-exec", "--uid", strconv.Itoa(s.cfg.PUID), "--gid", strconv.Itoa(s.cfg.PGID), "--nofile", strconv.Itoa(s.cfg.OpenFiles), "--", transBin}
		argv = append(argv, targs...)
		cmd = exec.Command(self, argv...)
		cmd.Env = s.transmissionEnv()
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logx.Error("supervisor", "transmission pipe", "error", err.Error())
		cancel()
		finish()
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		logx.Error("supervisor", "transmission pipe", "error", err.Error())
		cancel()
		finish()
		return
	}
	s.mu.Lock()
	if s.closed || ctx.Err() != nil {
		s.mu.Unlock()
		cancel()
		finish()
		return
	}
	s.mu.Unlock()
	if err := cmd.Start(); err != nil {
		logx.Error("supervisor", "transmission start failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	exited := make(chan struct{})
	s.mu.Lock()
	if s.closed || ctx.Err() != nil {
		s.mu.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		finish()
		return
	}
	s.tm = cmd
	s.tmExited = exited
	s.starting = false
	s.cond.Broadcast()
	s.mu.Unlock()
	go s.pump(stdout, "transmission")
	go s.pump(stderr, "transmission")
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		stopping := s.stopping || s.closed
		s.mu.Unlock()
		close(exited)
		if stopping {
			return
		}
		s.mu.Lock()
		if s.stopping || s.closed {
			s.mu.Unlock()
			return
		}
		s.died = true
		s.mu.Unlock()
		if err != nil {
			logx.Error("supervisor", "transmission exited", "error", err.Error())
		} else {
			logx.Error("supervisor", "transmission exited")
		}
		select {
		case s.unexp <- struct{}{}:
		default:
		}
	}()
	logx.Info("supervisor", "transmission started", "pid", strconv.Itoa(cmd.Process.Pid), "bind", s.local)
	_ = s.writeStatus()
	if err := waitRPC(ctx, s.rpcPort); err != nil {
		if ctx.Err() != nil {
			return
		}
		logx.Error("supervisor", "transmission rpc did not come up", "error", err.Error())
		s.stopTM(true)
		return
	}
	if err := s.runScript(ctx, "/scripts/transmission-post-start.sh", args); err != nil {
		logx.Warn("supervisor", "post-start script failed", "error", err.Error())
	}
	go s.reassert(ctx)
}

// stopTM stops Transmission. pre is false when the process has already exited.
func (s *Sup) stopTM(pre bool) {
	s.mu.Lock()
	if s.stopWait != nil {
		ch := s.stopWait
		s.mu.Unlock()
		<-ch
		return
	}
	if s.stoppedTM || (!s.starting && s.tm == nil && !s.died && !s.startedPath) {
		s.mu.Unlock()
		return
	}
	ch := make(chan struct{})
	s.stopWait = ch
	s.stoppedTM = true
	s.stopping = true
	cancel := s.tmCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.mu.Lock()
	for s.starting {
		s.cond.Wait()
	}
	cmd := s.tm
	exited := s.tmExited
	died := s.died
	dev := s.cfg.Dev
	local := s.local
	mtu := strconv.Itoa(s.mtu)
	ep := ""
	if s.pin.IsValid() {
		ep = s.pin.String()
	}
	s.mu.Unlock()

	args := []string{dev, mtu, "", local, ep, "stop"}
	if pre && !died {
		_ = s.runScript(context.Background(), "/scripts/transmission-pre-stop.sh", args)
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			if exited != nil {
				select {
				case <-exited:
				case <-time.After(transKill):
					_ = cmd.Process.Kill()
					<-exited
				}
			}
		}
	}
	_ = s.runScript(context.Background(), "/scripts/transmission-post-stop.sh", args)
	s.mu.Lock()
	s.tm = nil
	s.tmCancel = nil
	s.tmExited = nil
	s.stopping = false
	if s.stopWait == ch {
		s.stopWait = nil
	}
	s.mu.Unlock()
	close(ch)
	_ = s.writeStatus()
}

func (s *Sup) reassert(ctx context.Context) {
	if !s.canReassert() {
		logx.Warn("supervisor", "RPC authentication is required and TRANSMISSION_RPC_PASSWORD is unset; a hashed settings password cannot be sent")
		return
	}
	c := &transmission.Client{
		URL:      "http://127.0.0.1:" + strconv.Itoa(s.rpcPort) + "/transmission/rpc",
		User:     s.cfg.RPCUser,
		Password: s.cfg.RPCPassword,
	}
	s.correct(c)
	tick := time.NewTicker(reassertEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.correct(c)
		}
	}
}

func (s *Sup) canReassert() bool {
	merged, err := s.merge(s.local)
	if err != nil {
		return false
	}
	auth, _ := merged["rpc_authentication_required"].(bool)
	pass, _ := merged["rpc_password"].(string)
	return rpcAuthUsable(auth, pass, s.cfg.RPCPassword)
}

// rpcAuthUsable reports whether this process can call RPC.
// When auth is on, only TRANSMISSION_RPC_PASSWORD is sent.
func rpcAuthUsable(auth bool, filePass, envPass string) bool {
	if !auth {
		return true
	}
	if envPass != "" {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(filePass), "{") {
		return false
	}
	return false
}

func (s *Sup) correct(c *transmission.Client) {
	got, err := c.SessionGet()
	if err != nil {
		logx.Warn("supervisor", "session_get failed", "error", err.Error())
		return
	}
	pf, scripts := reassertTargets(s.cfg.AllowUPnP, s.cfg.AllowScripts, got)
	if pf {
		s.warnOnce("port_forwarding_enabled")
		if err := c.SetPortForwardingEnabled(false); err != nil {
			logx.Warn("supervisor", "session_set failed", "error", err.Error())
		}
	}
	if scripts {
		for _, key := range scriptKeys {
			if b, ok := got[key].(bool); ok && b {
				s.warnOnce(key)
			}
		}
		if err := c.SetScriptsDisabled(); err != nil {
			logx.Warn("supervisor", "session_set failed", "error", err.Error())
		}
	}
}

func reassertTargets(allowUPnP, allowScripts bool, got map[string]any) (pf, scripts bool) {
	if !allowUPnP {
		if b, ok := got["port_forwarding_enabled"].(bool); ok && b {
			pf = true
		}
	}
	if !allowScripts {
		for _, key := range scriptKeys {
			if b, ok := got[key].(bool); ok && b {
				scripts = true
			}
		}
	}
	return pf, scripts
}

func (s *Sup) warnOnce(key string) {
	s.mu.Lock()
	if s.reasserted == nil {
		s.reasserted = map[string]time.Time{}
	}
	if !s.reasserted[key].IsZero() && time.Since(s.reasserted[key]) <= time.Minute {
		s.mu.Unlock()
		return
	}
	s.reasserted[key] = time.Now()
	s.mu.Unlock()
	if key == "port_forwarding_enabled" {
		logx.Warn("supervisor", "turning port forwarding back off", "key", key)
		return
	}
	logx.Warn("supervisor", "turning torrent script back off", "key", key)
}

func waitRPC(ctx context.Context, port int) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out dialing %s", addr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// errStopped is returned when a signal arrives during the handshake wait.
var errStopped = errors.New("stopped")
