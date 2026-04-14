package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

type SOCKS4Dialer struct {
	ProxyAddr string
	User      *url.Userinfo
	Forward   ContextDialer
}

func NewSOCKS4Dialer(proxyAddr string, user *url.Userinfo, forward ContextDialer) *SOCKS4Dialer {
	if forward == nil {
		forward = &net.Dialer{}
	}
	return &SOCKS4Dialer{ProxyAddr: proxyAddr, User: user, Forward: forward}
}

func (s *SOCKS4Dialer) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	conn, err := s.Forward.DialContext(ctx, network, s.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks4 proxy connection failed: %w", err)
	}

	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
		defer conn.SetDeadline(time.Time{})
	}

	if err := s.handshake(conn, targetAddr); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (s *SOCKS4Dialer) handshake(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	portInt, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	req := []byte{0x04, 0x01} // VER (4), CMD (1 = CONNECT)

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	req = append(req, portBytes...)

	ip := net.ParseIP(host)
	isIPv4 := ip != nil && ip.To4() != nil

	if isIPv4 {
		// SOCKS4 standard (IP explicitly known)
		req = append(req, ip.To4()...)
	} else {
		if ip != nil && ip.To4() == nil {
			return fmt.Errorf("socks4 does not support IPv6: %s", host)
		}
		// SOCKS4a extension (Invalid IP block 0.0.0.x tells proxy to resolve domain)
		req = append(req, []byte{0, 0, 0, 1}...)
	}

	// User ID (Auth)
	if s.User != nil {
		req = append(req, []byte(s.User.Username())...)
	}
	req = append(req, 0x00) // NULL terminator for User ID

	// If using SOCKS4a, append the domain name
	if !isIPv4 {
		req = append(req, []byte(host)...)
		req = append(req, 0x00) // NULL terminator for Domain
	}

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	// Read response (exactly 8 bytes)
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}

	// resp[0] is a null byte
	// resp[1] is the status code: 0x5a (90) = granted, 0x5b (91) = rejected
	if resp[1] != 0x5a {
		return fmt.Errorf("socks4 connection rejected: code %x", resp[1])
	}

	return nil
}
