package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRustnetArgs(t *testing.T) {
	args := rustnetArgs(5000, "")
	got := strings.Join(args, " ")
	for _, want := range []string{
		"--headless", "--output jsonl", "--interface any",
		"--no-resolve-dns", "--no-geoip", "--refresh-interval 5000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
	for _, banned := range []string{"kubernetes", "--log-level", "--no-uid-drop", "--no-sandbox", "--duration", "--pcap-export"} {
		if strings.Contains(got, banned) {
			t.Fatalf("argv must not contain %s: %s", banned, got)
		}
	}
	with := strings.Join(rustnetArgs(1000, "/config/rustnet.pcap"), " ")
	if !strings.Contains(with, "--pcap-export /config/rustnet.pcap") {
		t.Fatal(with)
	}
}

func TestRustnetPcap(t *testing.T) {
	got, err := rustnetPcap("  /config/captures/now.pcap  ")
	if err != nil || got != "/config/captures/now.pcap" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = rustnetPcap("/config/../config/ok.pcap")
	if err != nil || got != "/config/ok.pcap" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := rustnetPcap("/tmp/x.pcap"); err == nil {
		t.Fatal("expected path outside /config to fail")
	}
	if _, err := rustnetPcap("/config/../etc/passwd"); err == nil {
		t.Fatal("expected escaped path to fail")
	}
	if _, err := rustnetPcap("capture.pcap"); err == nil {
		t.Fatal("expected relative path to fail")
	}
	if got, err := rustnetPcap(""); err != nil || got != "" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestPrepareRustnetPcapRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "cap.pcap")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareRustnetPcap(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "keep" {
		t.Fatalf("target = %q %v", body, err)
	}
}

func TestRustnetPlan(t *testing.T) {
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	wait, giveUp, kept := rustnetPlan(nil, now)
	if giveUp || wait != time.Second || len(kept) != 1 {
		t.Fatalf("first exit: %s %v %d", wait, giveUp, len(kept))
	}
	prev := kept
	for i := 1; i < 5; i++ {
		wait, giveUp, prev = rustnetPlan(prev, now.Add(time.Duration(i)*time.Second))
		if giveUp {
			t.Fatalf("restart %d gave up", i+1)
		}
	}
	if wait != 16*time.Second || len(prev) != 5 {
		t.Fatalf("fifth exit: %s %d", wait, len(prev))
	}
	_, giveUp, kept = rustnetPlan(prev, now.Add(6*time.Second))
	if !giveUp || len(kept) != 5 {
		t.Fatalf("sixth exit should give up: %v %d", giveUp, len(kept))
	}
	old := []time.Time{now.Add(-11 * time.Minute)}
	wait, giveUp, kept = rustnetPlan(old, now)
	if giveUp || wait != time.Second || len(kept) != 1 {
		t.Fatalf("expired exit should not count: %s %v %d", wait, giveUp, len(kept))
	}
}
