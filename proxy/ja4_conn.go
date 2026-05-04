package proxy

import (
	"net"
	"sync"
)

type ja4ConnContextKey struct{}

type ja4Listener struct {
	net.Listener
}

func (l ja4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &ja4Conn{Conn: conn}, nil
}

type ja4Conn struct {
	net.Conn

	mu  sync.RWMutex
	ja4 string
}

func (c *ja4Conn) SetJA4(ja4 string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ja4 = ja4
}

func (c *ja4Conn) JA4() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.ja4
}
