package proxy

import (
	"context"
	"net"
)

// ContextDialer is the uniform interface for all proxy protocols.
// It supports context for modern Go network dialing (cancellations/timeouts).
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
