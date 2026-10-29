package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lostinfuture/transmission-wireguard/internal/logx"
)

func TestRunMissingConfig(t *testing.T) {
	_, stderr := capture(t, func() {
		if got := run(nil, nil); got != 1 {
			t.Fatalf("run exit = %d, want 1", got)
		}
	})
	if strings.Contains(stderr, "wireguard is not implemented") {
		t.Fatal(stderr)
	}
	if !strings.Contains(stderr, "no such file") && !strings.Contains(stderr, "wireguard") {
		t.Fatal(stderr)
	}
	if got := run([]string{"list-providers"}, nil); got != 2 {
		t.Fatalf("unknown exit = %d, want 2", got)
	}
	_, stderr = capture(t, func() {
		if got := run([]string{"drop-exec"}, nil); got != 1 {
			t.Fatalf("drop-exec exit = %d", got)
		}
	})
	if !strings.Contains(stderr, "--uid") {
		t.Fatal(stderr)
	}
}

func TestRunRejectsOpenVPNEnv(t *testing.T) {
	_, stderr := capture(t, func() {
		if got := run([]string{"run"}, []string{"OPENVPN_PROVIDER=custom"}); got != 1 {
			t.Fatalf("exit = %d", got)
		}
	})
	if !strings.Contains(stderr, "unset OPENVPN_PROVIDER") {
		t.Fatal(stderr)
	}
	if strings.Contains(stderr, "wireguard is not implemented") {
		t.Fatal(stderr)
	}
}

func capture(t *testing.T, fn func()) (string, string) {
	t.Helper()
	er, ew, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldErr := os.Stderr
	os.Stderr = ew
	defer func() { os.Stderr = oldErr }()
	var stdout bytes.Buffer
	logx.Capture(&stdout, fn)
	ew.Close()
	os.Stderr = oldErr
	var stderr bytes.Buffer
	if _, err := io.Copy(&stderr, er); err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String()
}
