package proxy

import (
	"fmt"
	"net"
	"net/url"
)

// FromURL creates a ContextDialer from a URL.
// The `forward` parameter allows proxy chaining (pass nil for direct connection).
func FromURL(proxyURL string, forward ContextDialer) (ContextDialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	if forward == nil {
		forward = &net.Dialer{}
	}

	switch u.Scheme {
	case "http", "https":
		return NewHTTPDialer(u.Host, u.User, forward), nil
	case "socks5":
		return NewSOCKS5Dialer(u.Host, u.User, forward), nil
	case "socks4", "socks4a":
		return NewSOCKS4Dialer(u.Host, u.User, forward), nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", u.Scheme)
	}
}
