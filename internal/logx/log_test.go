package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	stdout := capture(t, func() {
		Info("supervisor", "loaded",
			"privatekey", "hidden-private",
			"private_key", "hidden-private-2",
			"preshared", "hidden-psk",
			"psk", "hidden-short",
			"password", "hidden-pass",
			"dev", "wg0",
			"endpoint", "203.0.113.10:51820",
		)
	})
	for _, leak := range []string{"hidden-private", "hidden-private-2", "hidden-psk", "hidden-short", "hidden-pass"} {
		if strings.Contains(stdout, leak) {
			t.Fatalf("log leaked %q in %s", leak, stdout)
		}
	}
	if !strings.Contains(stdout, "dev=wg0") || !strings.Contains(stdout, "endpoint=203.0.113.10:51820") {
		t.Fatal(stdout)
	}
	if strings.Count(stdout, "[redacted]") != 5 {
		t.Fatal(stdout)
	}
}

func TestEscapeQuotes(t *testing.T) {
	stdout := capture(t, func() {
		Warn("supervisor", "has space", "note", `say "hi"`)
	})
	if !strings.Contains(stdout, `msg="has space"`) || !strings.Contains(stdout, "note=\"say 'hi'\"") {
		t.Fatal(stdout)
	}
}

func TestChildLines(t *testing.T) {
	stdout := capture(t, func() {
		Error("supervisor", "failed", "dev", "wg0")
		Child("transmission", "hello \"there\"")
		ChildRaw("rustnet", "not \"rewritten\"\nnext")
	})
	if !strings.Contains(stdout, "level=error") || !strings.Contains(stdout, "dev=wg0") {
		t.Fatal(stdout)
	}
	if !strings.Contains(stdout, `msg="hello 'there'"`) {
		t.Fatal(stdout)
	}
	if !strings.Contains(stdout, `msg=not "rewritten" next`) {
		t.Fatal(stdout)
	}
}

func capture(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	Capture(&buf, fn)
	return buf.String()
}
