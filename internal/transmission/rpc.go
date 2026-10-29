package transmission

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client speaks Transmission's JSON-RPC 2.0, then the legacy body if 2.0 is rejected.
type Client struct {
	URL      string
	User     string
	Password string
	HTTP     *http.Client
	session  string
	legacy   bool
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 5 * time.Second}
}

// SessionGet returns the session object.
func (c *Client) SessionGet() (map[string]any, error) {
	raw, err := c.call("session_get", "session-get", map[string]any{})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// SetScriptsDisabled writes the torrent-script enables back to false.
// It does not change port forwarding.
func (c *Client) SetScriptsDisabled() error {
	args := map[string]any{
		"script_torrent_done_enabled":         false,
		"script_torrent_done_seeding_enabled": false,
		"script_torrent_added_enabled":        false,
	}
	_, err := c.call("session_set", "session-set", args)
	return err
}

// SetPortForwardingEnabled writes only the UPnP session key.
func (c *Client) SetPortForwardingEnabled(on bool) error {
	_, err := c.call("session_set", "session-set", map[string]any{
		"port_forwarding_enabled": on,
	})
	return err
}

// SetPeerPort sets the listen port. JSON-RPC uses peer_port. The legacy retry uses peer-port.
func (c *Client) SetPeerPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("peer port %d", port)
	}
	if !c.legacy {
		_, err := c.post("session_set", map[string]any{"peer_port": port})
		if err == nil {
			return nil
		}
		if !rpcRejected(err) {
			return err
		}
		c.legacy = true
	}
	_, err := c.post("session-set", map[string]any{"peer-port": port})
	return err
}

func rpcRejected(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "method") || strings.Contains(msg, "jsonrpc") || strings.Contains(msg, "peer_port") || strings.Contains(msg, "peer-port")
}

func (c *Client) call(modern, legacy string, args map[string]any) (map[string]any, error) {
	method := modern
	if c.legacy {
		method = legacy
	}
	body, err := c.post(method, args)
	if err != nil && !c.legacy && (strings.Contains(err.Error(), "method") || strings.Contains(err.Error(), "jsonrpc")) {
		c.legacy = true
		return c.post(legacy, args)
	}
	return body, err
}

func (c *Client) post(method string, args map[string]any) (map[string]any, error) {
	payload := map[string]any{"method": method, "id": 1}
	if c.legacy || !strings.Contains(method, "_") {
		payload["arguments"] = args
	} else {
		payload["jsonrpc"] = "2.0"
		payload["params"] = args
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, c.URL, bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.session != "" {
			req.Header.Set("X-Transmission-Session-Id", c.session)
		}
		if c.User != "" || c.Password != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Password)))
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return nil, err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusConflict {
			c.session = resp.Header.Get("X-Transmission-Session-Id")
			last = fmt.Errorf("session id retry")
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("rpc unauthorized")
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("rpc status %d", resp.StatusCode)
		}
		var decoded map[string]any
		if err := json.Unmarshal(b, &decoded); err != nil {
			return nil, err
		}
		if errObj, ok := decoded["error"].(map[string]any); ok && errObj != nil {
			msg, _ := errObj["message"].(string)
			return nil, fmt.Errorf("rpc: %s", msg)
		}
		if result, ok := decoded["result"].(map[string]any); ok {
			return result, nil
		}
		if arguments, ok := decoded["arguments"].(map[string]any); ok {
			return arguments, nil
		}
		if result, ok := decoded["result"].(string); ok && result != "" && result != "success" {
			return nil, fmt.Errorf("rpc: %s", result)
		}
		return map[string]any{}, nil
	}
	if last == nil {
		last = fmt.Errorf("rpc failed")
	}
	return nil, last
}
