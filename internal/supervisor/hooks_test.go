package supervisor

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingScriptOK(t *testing.T) {
	s := &Sup{}
	if err := s.runScript(context.Background(), filepath.Join(t.TempDir(), "wireguard-pre-start.sh"), nil); err != nil {
		t.Fatal(err)
	}
}

func TestScriptFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transmission-pre-start.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	err = scriptFile(st)
	if os.Geteuid() != 0 {
		if err == nil || !strings.Contains(err.Error(), "not owned by root") {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	st, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	err = scriptFile(st)
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	st, err = os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := scriptFile(st); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
}

func TestWriteAndRestoreResolv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.11\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := resolvPath
	resolvPath = path
	t.Cleanup(func() { resolvPath = old })
	s := &Sup{cfg: Config{PeerDNS: true}}
	s.wg.DNS = []netip.Addr{netip.MustParseAddr("10.64.0.1")}
	s.wg.Search = []string{"lan"}
	if err := s.applyDNS(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "search lan\nnameserver 10.64.0.1\n" {
		t.Fatalf("%q", got)
	}
	s.restoreResolv()
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "nameserver 127.0.0.11\n" {
		t.Fatalf("restored %q", got)
	}
}
