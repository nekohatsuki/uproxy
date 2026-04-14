package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

type HTTPDialer struct {
	ProxyAddr string
	User      *url.Userinfo
	Forward   ContextDialer // Allows proxy chaining
}

func NewHTTPDialer(proxyAddr string, user *url.Userinfo, forward ContextDialer) *HTTPDialer {
	if forward == nil {
		forward = &net.Dialer{}
	}
	return &HTTPDialer{
		ProxyAddr: proxyAddr,
		User:      user,
		Forward:   forward,
	}
}

func (h *HTTPDialer) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	// Dial the proxy server
	conn, err := h.Forward.DialContext(ctx, network, h.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy failed: %w", err)
	}

	// Prepare the CONNECT request
	req, err := http.NewRequestWithContext(ctx, "CONNECT", "http://"+targetAddr, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if h.User != nil {
		password, _ := h.User.Password()
		auth := h.User.Username() + ":" + password
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Proxy-Authorization", basicAuth)
	}

	// Send CONNECT request
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Read the proxy's response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading proxy response failed: %s", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy refused connection: %s", resp.Status)
	}

	// Warp the connection
	return &bufferedConn{
		Conn: conn,
		r:    br,
	}, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
