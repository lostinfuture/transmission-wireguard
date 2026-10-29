package transmission

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRPCSessionAndConflict(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		if r.Header.Get("X-Transmission-Session-Id") == "" {
			w.Header().Set("X-Transmission-Session-Id", "abc")
			w.WriteHeader(http.StatusConflict)
			return
		}
		if !strings.Contains(string(b), `"jsonrpc":"2.0"`) || !strings.Contains(string(b), `"method":"session_get"`) {
			t.Errorf("body = %s", b)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"script_torrent_done_enabled":true},"id":1}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	got, err := c.SessionGet()
	if err != nil {
		t.Fatal(err)
	}
	if got["script_torrent_done_enabled"] != true {
		t.Fatalf("got %#v", got)
	}
	if len(seen) != 2 {
		t.Fatalf("attempts = %d", len(seen))
	}
}

func TestRPCLegacyFallback(t *testing.T) {
	step := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		step++
		w.Header().Set("Content-Type", "application/json")
		if step == 1 {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"},"id":1}`))
			return
		}
		if !strings.Contains(string(b), "session-set") || !strings.Contains(string(b), "arguments") {
			t.Errorf("legacy body = %s", b)
		}
		_, _ = w.Write([]byte(`{"result":"success","arguments":{}}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	if err := c.SetScriptsDisabled(); err != nil {
		t.Fatal(err)
	}
}

func TestSetPeerPort(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{},"id":1}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	if err := c.SetPeerPort(47047); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"peer_port":47047`) || !strings.Contains(bodies[0], `"method":"session_set"`) {
		t.Fatal(bodies)
	}
	if strings.Contains(bodies[0], "peer-port") {
		t.Fatal(bodies[0])
	}
}

func TestSetPeerPortLegacy(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		if len(bodies) == 1 {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"},"id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":"success","arguments":{}}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	if err := c.SetPeerPort(47047); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatal(bodies)
	}
	if !strings.Contains(bodies[1], `"method":"session-set"`) || !strings.Contains(bodies[1], `"peer-port":47047`) || !strings.Contains(bodies[1], `"arguments"`) {
		t.Fatal(bodies[1])
	}
	if strings.Contains(bodies[1], "peer_port") {
		t.Fatal(bodies[1])
	}
}
