package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

type SOCKS5Dialer struct {
	ProxyAddr string
	User      *url.Userinfo
	Forward   ContextDialer
}

func NewSOCKS5Dialer(proxyAddr string, user *url.Userinfo, forward ContextDialer) *SOCKS5Dialer {
	if forward == nil {
		forward = &net.Dialer{}
	}
	return &SOCKS5Dialer{
		ProxyAddr: proxyAddr,
		User:      user,
		Forward:   forward,
	}
}

func (s *SOCKS5Dialer) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	conn, err := s.Forward.DialContext(ctx, network, s.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 proxy connection failed: %w", err)
	}

	// Apply context deadline to the handshake
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
		defer conn.SetDeadline(time.Time{}) // Clear deadline after handshake
	}

	if err := s.handshake(conn, targetAddr); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (s *SOCKS5Dialer) handshake(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	portInt, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

	// 1. Greet the server and negotiate authentication
	authMethods := []byte{0x00} // NO AUTHENTICATION REQUIRED
	if s.User != nil {
		authMethods = append(authMethods, 0x02) // USERNAME/PASSWORD
	}

	req := []byte{0x05, byte(len(authMethods))}
	req = append(req, authMethods...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("unsupported socks version: %x", resp[0])
	}

	// 2. Perform Authentication if required
	if resp[1] == 0x02 && s.User != nil {
		if err := s.authenticate(conn); err != nil {
			return err
		}
	} else if resp[1] != 0x00 {
		return errors.New("unsupported authentication method required by proxy")
	}

	// 3. Send CONNECT request
	req = []byte{0x05, 0x01, 0x00} // VER, CMD (CONNECT), RSV
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01) // IPv4
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04) // IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03) // Domain Name
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	// 4. Read CONNECT response
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}
	if respHdr[0] != 0x05 {
		return fmt.Errorf("unsupported response socks version: %x", respHdr[0])
	}
	if respHdr[1] != 0x00 {
		return fmt.Errorf("proxy connection rejected: code %x", respHdr[1])
	}

	// Skip the bound address and port (we don't typically need them for an outgoing dial)
	var addrLen int
	switch respHdr[3] {
	case 0x01: // IPv4
		addrLen = 4 + 2
	case 0x04: // IPv6
		addrLen = 16 + 2
	case 0x03: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		addrLen = int(lenByte[0]) + 2
	default:
		return fmt.Errorf("unknown address type: %x", respHdr[3])
	}

	if _, err := io.CopyN(io.Discard, conn, int64(addrLen)); err != nil {
		return err
	}

	return nil
}

func (s *SOCKS5Dialer) authenticate(conn net.Conn) error {
	username := s.User.Username()
	password, _ := s.User.Password()

	req := []byte{0x01, byte(len(username))}
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp[1] != 0x00 {
		return errors.New("socks5 authentication failed")
	}
	return nil
}
