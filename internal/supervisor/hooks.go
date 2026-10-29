package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
)

const scriptKill = 10 * time.Second

func (s *Sup) runScript(ctx context.Context, path string, args []string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := scriptDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%s: %w", filepath.Dir(path), err)
	}
	if err := scriptFile(st); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	cctx, cancel := context.WithTimeout(ctx, scriptKill)
	defer cancel()
	bin := path
	argv := args
	if st.Mode()&0o111 == 0 {
		bin = "/bin/sh"
		argv = append([]string{path}, args...)
	}
	cmd := exec.CommandContext(cctx, bin, argv...)
	cmd.Env = childEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		logx.Child("script", s.redact(line))
	}
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func (s *Sup) hookArgs(ctxName string) []string {
	ip := ""
	if s.pin.IsValid() {
		ip = s.pin.String()
	}
	return []string{s.cfg.Dev, fmt.Sprintf("%d", s.mtu), "", s.local, ip, ctxName}
}

func scriptDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	if !st.IsDir() {
		return errors.New("not a directory")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return errors.New("not owned by root")
	}
	if st.Mode()&0o022 != 0 {
		return errors.New("writable by group or other")
	}
	return nil
}

func scriptFile(st os.FileInfo) error {
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a file")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return errors.New("not owned by root")
	}
	if st.Mode()&0o022 != 0 {
		return errors.New("writable by group or other")
	}
	return nil
}

func (s *Sup) ownFiles() error {
	if err := chownTree(s.cfg.Home, s.cfg.PUID, s.cfg.PGID); err != nil {
		return err
	}
	if s.cfg.ApplyPerms {
		if err := chownTree("/data", s.cfg.PUID, s.cfg.PGID); err != nil {
			return err
		}
	}
	return nil
}

func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}

func writeSettings(path string, m map[string]any, uid, gid int) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	okWrite := false
	defer func() {
		if !okWrite {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chown(uid, gid); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	okWrite = true
	return nil
}

func readUserSettings(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		bad := path + ".bad"
		_ = os.Rename(path, bad)
		logx.Warn("supervisor", "settings.json is not a JSON object; starting from defaults", "saved", bad)
		return map[string]any{}, nil
	}
	return m, nil
}

func (s *Sup) transmissionEnv() []string {
	env := childEnv(os.Environ())
	if s.cfg.WebHome != "" {
		env = append(env, "TRANSMISSION_WEB_HOME="+s.cfg.WebHome)
	}
	return env
}

func (s *Sup) redact(line string) string {
	line = redactSecret(line, s.cfg.RPCPassword)
	line = redactSecret(line, s.wg.PrivateKey)
	line = redactSecret(line, s.wg.PresharedKey)
	return line
}

func redactSecret(line, secret string) string {
	if len(secret) < 3 {
		return line
	}
	return strings.ReplaceAll(line, secret, "[redacted]")
}

func childEnv(env []string) []string {
	var out []string
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if secretEnvName(k) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func secretEnvName(k string) bool {
	lk := strings.ToLower(k)
	lk = strings.ReplaceAll(lk, "-", "")
	lk = strings.ReplaceAll(lk, "_", "")
	return strings.Contains(lk, "pass") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "credential") || strings.Contains(lk, "privatekey") || strings.Contains(lk, "preshared") || strings.Contains(lk, "psk")
}

func (s *Sup) pump(r io.Reader, component string) {
	// Transmission lines are logged after secret redaction.
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		for {
			i := strings.IndexByte(string(buf), '\n')
			if i < 0 {
				break
			}
			line := string(buf[:i])
			buf = buf[i+1:]
			line = strings.TrimRight(line, "\r")
			if line == "" {
				continue
			}
			logx.Child(component, s.redact(line))
		}
		if err != nil {
			if len(buf) > 0 {
				logx.Child(component, s.redact(string(buf)))
			}
			return
		}
	}
}
