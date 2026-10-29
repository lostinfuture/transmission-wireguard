//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	prCapbsetDrop        uintptr = 24
	prSetSecurebits      uintptr = 28
	prSetNoNewPrivs      uintptr = 38
	prCapAmbient         uintptr = 47
	prCapAmbientClearAll uintptr = 4
	// SECBIT_NOROOT|NOROOT_LOCKED|NO_SETUID_FIXUP|NO_SETUID_FIXUP_LOCKED.
	secbitsNoRoot uintptr = 15
)

// dropExec is the re-exec trampoline. os/exec cannot call PR_CAPBSET_DROP.
// LockOSThread, then drop the bounding set, then setuid on this thread and execve.
// execve keeps the calling thread's credentials and destroys every other thread.
// boundingSetClear refuses to exec unless CapBnd is 0000000000000000.
func dropExec(args []string) error {
	uid, gid, nofile, cmd, err := parseDrop(args)
	if err != nil {
		return err
	}
	path := cmd[0]
	if !strings.Contains(path, "/") {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return err
		}
		path = resolved
	}
	runtime.LockOSThread()
	if nofile > 0 {
		lim := syscall.Rlimit{Cur: uint64(nofile), Max: uint64(nofile)}
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
	last, err := capLast()
	if err != nil {
		return err
	}
	for cap := 0; cap <= last; cap++ {
		err := prctl(prCapbsetDrop, uintptr(cap), 0, 0, 0)
		if errors.Is(err, syscall.EINVAL) {
			continue
		}
		if err != nil {
			return fmt.Errorf("drop capability %d: %w", cap, err)
		}
	}
	if err := prctl(prSetSecurebits, secbitsNoRoot, 0, 0, 0); err != nil {
		return fmt.Errorf("securebits: %w", err)
	}
	if err := prctl(prCapAmbient, prCapAmbientClearAll, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient caps: %w", err)
	}
	if err := prctl(prSetNoNewPrivs, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := boundingSetClear(); err != nil {
		return err
	}
	if err := setIDs(uid, gid); err != nil {
		return err
	}
	return syscall.Exec(path, cmd, os.Environ())
}

func parseDrop(args []string) (uid, gid, nofile int, cmd []string, err error) {
	var uidSet, gidSet, nofileSet bool
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if i+1 >= len(args) {
			return 0, 0, 0, nil, fmt.Errorf("missing value for %s", a)
		}
		n, nerr := strconv.Atoi(args[i+1])
		if nerr != nil || n < 0 {
			return 0, 0, 0, nil, fmt.Errorf("%s %q", a, args[i+1])
		}
		switch a {
		case "--uid":
			uid, uidSet = n, true
		case "--gid":
			gid, gidSet = n, true
		case "--nofile":
			nofile, nofileSet = n, true
		default:
			return 0, 0, 0, nil, fmt.Errorf("unknown flag %s", a)
		}
		i += 2
	}
	if !uidSet || !gidSet || !nofileSet {
		return 0, 0, 0, nil, errors.New("need --uid, --gid, and --nofile")
	}
	if uid == 0 {
		return 0, 0, 0, nil, errors.New("drop-exec refuses uid 0")
	}
	if i >= len(args) {
		return 0, 0, 0, nil, errors.New("need a command after --")
	}
	return uid, gid, nofile, args[i:], nil
}

func capLast() (int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 || n > 63 {
		return 0, fmt.Errorf("cap_last_cap %q", strings.TrimSpace(string(b)))
	}
	return n, nil
}

func prctl(opt, a2, a3, a4, a5 uintptr) error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, opt, a2, a3, a4, a5, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func setIDs(uid, gid int) error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGROUPS, 0, 0, 0); errno != 0 {
		return fmt.Errorf("setgroups: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); errno != 0 {
		return fmt.Errorf("setgid: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); errno != 0 {
		return fmt.Errorf("setuid: %w", errno)
	}
	return nil
}

func boundingSetClear() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapBnd:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("unexpected %s", line)
		}
		if strings.Trim(fields[1], "0") != "" {
			return fmt.Errorf("bounding set still %s", fields[1])
		}
		return nil
	}
	return errors.New("CapBnd missing from /proc/self/status")
}
