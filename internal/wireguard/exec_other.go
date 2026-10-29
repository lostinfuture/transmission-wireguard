//go:build !linux

package wireguard

import "fmt"

func combined(name string, args ...string) ([]byte, error) {
	return nil, fmt.Errorf("%s is only used on linux", name)
}
