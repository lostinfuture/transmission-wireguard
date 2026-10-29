package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
)

const (
	rustnetBin    = "/usr/bin/rustnet"
	rustnetWindow = 10 * time.Minute
	rustnetMax    = 5
	rustnetKill   = 5 * time.Second
)

// rustnetArgs is the fixed headless argv. kubernetes, log files, uid-drop,
// sandbox, and duration are not options this image passes.
func rustnetArgs(refresh int, pcap string) []string {
	args := []string{
		"--headless", "--output", "jsonl", "--interface", "any",
		"--no-resolve-dns", "--no-geoip",
		"--refresh-interval", strconv.Itoa(refresh),
	}
	if pcap != "" {
		args = append(args, "--pcap-export", pcap)
	}
	return args
}

func prepareRustnetPcap(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	flags := os.O_WRONLY | syscall.O_NOFOLLOW
	st, err := os.Lstat(path)
	switch {
	case err == nil:
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("rustnet pcap %s must be a regular file", path)
		}
	case os.IsNotExist(err):
		flags |= os.O_CREATE | os.O_EXCL
	default:
		return err
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	err = f.Chmod(0o600)
	cerr := f.Close()
	if err != nil {
		return err
	}
	return cerr
}

// rustnetPlan schedules one restart after an exit.
// prev holds exit times already counted. Five exits inside ten minutes
// use up the restarts; the next exit gives up. The tunnel is not involved.
func rustnetPlan(prev []time.Time, now time.Time) (wait time.Duration, giveUp bool, kept []time.Time) {
	for _, t := range prev {
		if now.Sub(t) < rustnetWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rustnetMax {
		return 0, true, kept
	}
	shift := len(kept)
	if shift > 4 {
		shift = 4
	}
	wait = time.Second << shift
	kept = append(kept, now)
	return wait, false, kept
}

// startRustnet runs the monitor when the binary exists. A missing binary
// is the armv7 image: log once and keep going. An exit does not take the tunnel down.
func (s *Sup) startRustnet(ctx context.Context) {
	if !s.cfg.Rustnet {
		return
	}
	if _, err := os.Stat(rustnetBin); err != nil {
		NoteRustnet(true)
		return
	}
	if err := prepareRustnetPcap(s.cfg.RustnetPcap); err != nil {
		logx.Error("rustnet", "pcap file", "error", err.Error())
		return
	}
	go s.runRustnet(ctx)
}

func (s *Sup) runRustnet(ctx context.Context) {
	args := rustnetArgs(s.cfg.RustnetRefresh, s.cfg.RustnetPcap)
	var exits []time.Time
	for {
		if ctx.Err() != nil {
			return
		}
		cmd := exec.Command(rustnetBin, args...)
		cmd.Env = childEnv(os.Environ())
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			if s.rustnetFailed(ctx, &exits, err) {
				return
			}
			continue
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			if s.rustnetFailed(ctx, &exits, err) {
				return
			}
			continue
		}
		if err := cmd.Start(); err != nil {
			if s.rustnetFailed(ctx, &exits, err) {
				return
			}
			continue
		}
		go s.pumpRaw(stdout, "rustnet")
		go s.pumpRaw(stderr, "rustnet")
		logx.Info("rustnet", "started", "pid", strconv.Itoa(cmd.Process.Pid))
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()
		select {
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitCh:
			case <-time.After(rustnetKill):
				_ = cmd.Process.Kill()
				<-waitCh
			}
			return
		case err := <-waitCh:
			if ctx.Err() != nil {
				return
			}
			if s.rustnetFailed(ctx, &exits, err) {
				return
			}
		}
	}
}

// rustnetFailed records one exit. It returns true when the monitor should stay down.
func (s *Sup) rustnetFailed(ctx context.Context, exits *[]time.Time, err error) bool {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	logx.Warn("rustnet", "exited", "error", msg)
	wait, giveUp, kept := rustnetPlan(*exits, time.Now())
	*exits = kept
	if giveUp {
		logx.Error("rustnet", "giving up after repeated exits")
		return true
	}
	return !sleepCtx(ctx, wait)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
