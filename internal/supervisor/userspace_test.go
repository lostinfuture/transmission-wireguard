package supervisor

import (
	"os"
	"strings"
	"testing"
)

func TestUserspaceArgs(t *testing.T) {
	got := strings.Join(userspaceArgs("wg0"), " ")
	if got != "-f wg0" {
		t.Fatal(got)
	}
}

func TestStartUserspaceMissingBinary(t *testing.T) {
	if _, err := os.Stat(userspaceBin); err == nil {
		t.Skip(userspaceBin + " is installed")
	}
	s := &Sup{cfg: Config{Dev: "wg0", Implementation: "userspace"}}
	err := s.startUserspace(make(chan struct{}))
	if err == nil || err.Error() != "this arch has no wireguard-go" {
		t.Fatal(err)
	}
}
