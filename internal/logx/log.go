// Package logx writes the supervisor's one-line stdout records.
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	outMu sync.Mutex
	out   io.Writer = os.Stdout
	capMu sync.Mutex
)

// Capture sends log lines to w for the duration of fn.
// Overlapping calls run one at a time.
func Capture(w io.Writer, fn func()) {
	capMu.Lock()
	defer capMu.Unlock()
	outMu.Lock()
	old := out
	out = w
	outMu.Unlock()
	defer func() {
		outMu.Lock()
		out = old
		outMu.Unlock()
	}()
	fn()
}

func writer() io.Writer {
	outMu.Lock()
	defer outMu.Unlock()
	if out == nil {
		return os.Stdout
	}
	return out
}

// Info writes one supervisor record. Keys matching the password regex are redacted.
func Info(component, msg string, kv ...string) {
	write("info", component, msg, kv...)
}

// Warn writes one supervisor record at warning level.
func Warn(component, msg string, kv ...string) {
	write("warn", component, msg, kv...)
}

// Error writes one supervisor record at error level.
func Error(component, msg string, kv ...string) {
	write("error", component, msg, kv...)
}

// Child writes one line from a child process. The line is not parsed as key/value pairs.
func Child(component, line string) {
	fmt.Fprintf(writer(), "time=%s level=info component=%s msg=%s\n", time.Now().UTC().Format(time.RFC3339), component, escape(line))
}

// ChildRaw writes a child line without rewriting quotes. Rustnet JSONL uses this.
func ChildRaw(component, line string) {
	line = strings.ReplaceAll(line, "\n", " ")
	fmt.Fprintf(writer(), "time=%s level=info component=%s msg=%s\n", time.Now().UTC().Format(time.RFC3339), component, line)
}

func write(level, component, msg string, kv ...string) {
	var b strings.Builder
	fmt.Fprintf(&b, "time=%s level=%s component=%s msg=%s", time.Now().UTC().Format(time.RFC3339), level, component, escape(msg))
	for i := 0; i+1 < len(kv); i += 2 {
		val := kv[i+1]
		if secretKey(kv[i]) {
			val = "[redacted]"
		}
		fmt.Fprintf(&b, " %s=%s", kv[i], escape(val))
	}
	fmt.Fprintln(writer(), b.String())
}

func secretKey(key string) bool {
	k := strings.ToLower(key)
	k = strings.Map(func(r rune) rune {
		if r == '-' || r == '_' {
			return -1
		}
		return r
	}, k)
	return strings.Contains(k, "pass") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "credential") ||
		strings.Contains(k, "privatekey") ||
		strings.Contains(k, "preshared") ||
		strings.Contains(k, "psk")
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `'`) + `"`
	}
	return s
}
