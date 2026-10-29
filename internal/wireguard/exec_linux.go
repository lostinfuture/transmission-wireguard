//go:build linux

package wireguard

import "os/exec"

func combined(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}
