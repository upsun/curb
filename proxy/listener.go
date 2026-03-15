package proxy

import (
	"errors"
	"net"
	"sync"
)

// ConnListener is a net.Listener backed by a channel of net.Conn.
// It allows injecting connections (e.g. from fd-passing) into an http.Server.
type ConnListener struct {
	ch     chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

// NewConnListener creates a ConnListener with the given address label.
func NewConnListener(addr net.Addr) *ConnListener {
	return &ConnListener{
		ch:     make(chan net.Conn, 64),
		addr:   addr,
		closed: make(chan struct{}),
	}
}

// Enqueue adds a connection to the listener for processing by http.Server.Serve.
// Returns an error if the listener is closed.
func (cl *ConnListener) Enqueue(conn net.Conn) error {
	// Check closed first to avoid nondeterministic select behavior when both
	// the closed channel and the buffered send are ready.
	select {
	case <-cl.closed:
		return errors.New("listener closed")
	default:
	}
	select {
	case <-cl.closed:
		return errors.New("listener closed")
	case cl.ch <- conn:
		return nil
	}
}

// Accept implements net.Listener.
func (cl *ConnListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-cl.ch:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return conn, nil
	case <-cl.closed:
		return nil, errors.New("listener closed")
	}
}

// Close implements net.Listener.
func (cl *ConnListener) Close() error {
	cl.once.Do(func() {
		close(cl.closed)
	})
	return nil
}

// Addr implements net.Listener.
func (cl *ConnListener) Addr() net.Addr {
	return cl.addr
}
