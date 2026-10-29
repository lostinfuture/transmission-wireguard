package supervisor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
)

const (
	userspaceBin   = "/usr/bin/wireguard-go"
	userspaceReady = 5 * time.Second
	userspaceKill  = 5 * time.Second
)

// userspaceProc is the foreground wireguard-go child. Kernel mode leaves it nil.
type userspaceProc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// userspaceArgs is wireguard-go's foreground form. Without -f it daemonizes.
func userspaceArgs(dev string) []string {
	return []string{"-f", dev}
}

// startUserspace runs wireguard-go and waits until the interface exists.
// It does not create a kernel WireGuard device. A name that already exists
// is left in place.
func (s *Sup) startUserspace(stop <-chan struct{}) error {
	if _, err := os.Stat(userspaceBin); err != nil {
		return errors.New("this arch has no wireguard-go")
	}
	if linkExists(s.cfg.Dev) {
		return fmt.Errorf("interface %s already exists", s.cfg.Dev)
	}
	logx.Info("wireguard", "userspace dataplane", "dev", s.cfg.Dev)
	cmd := exec.Command(userspaceBin, userspaceArgs(s.cfg.Dev)...)
	cmd.Env = childEnv(os.Environ())
	stdout := newLineLog(s, "wg")
	stderr := newLineLog(s, "wg")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	p := &userspaceProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		stdout.flush()
		stderr.flush()
		close(p.done)
	}()
	s.mu.Lock()
	s.userspace = p
	s.mu.Unlock()
	logx.Info("wireguard", "wireguard-go started", "pid", fmt.Sprintf("%d", cmd.Process.Pid), "dev", s.cfg.Dev)

	deadline := time.NewTimer(userspaceReady)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if linkExists(s.cfg.Dev) {
			s.created = true
			return nil
		}
		select {
		case <-stop:
			if linkExists(s.cfg.Dev) {
				s.created = true
			}
			return errStopped
		case <-p.done:
			if linkExists(s.cfg.Dev) {
				s.created = true
			}
			if p.err != nil {
				return fmt.Errorf("wireguard-go exited: %v", p.err)
			}
			return errors.New("wireguard-go exited")
		case <-deadline.C:
			if linkExists(s.cfg.Dev) {
				s.created = true
				return nil
			}
			return errors.New("wireguard-go did not create the interface")
		case <-tick.C:
		}
	}
}

// stopUserspace sends SIGTERM, then SIGKILL after 5s. It is safe to call twice.
func (s *Sup) stopUserspace() {
	s.mu.Lock()
	p := s.userspace
	s.userspace = nil
	s.mu.Unlock()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(userspaceKill):
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		<-p.done
	}
}

func linkExists(dev string) bool {
	cmd := exec.Command("ip", "link", "show", "dev", dev)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

type lineLog struct {
	mu        sync.Mutex
	buf       []byte
	component string
	redact    func(string) string
}

func newLineLog(s *Sup, component string) *lineLog {
	return &lineLog{component: component, redact: s.redact}
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	l.drain()
	return len(p), nil
}

func (l *lineLog) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.drain()
	if len(l.buf) == 0 {
		return
	}
	l.emit(string(l.buf))
	l.buf = nil
}

func (l *lineLog) drain() {
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			return
		}
		line := strings.TrimRight(string(l.buf[:i]), "\r")
		l.buf = append([]byte(nil), l.buf[i+1:]...)
		if line != "" {
			l.emit(line)
		}
	}
}

func (l *lineLog) emit(line string) {
	if l.redact != nil {
		line = l.redact(line)
	}
	logx.Child(l.component, line)
}
