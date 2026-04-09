package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"flowguard/middleware"
)

func TestServerStartReturnsBindErrorsSynchronously(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupied.Close()

	_, port, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	server := NewServer(&ServerConfig{
		scheme:     "http",
		bindAddr:   "127.0.0.1",
		bindPort:   port,
		middleware: middleware.NewChain(),
	})

	if err := server.Start(nil, make(chan error, 1)); err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

func TestServerStartServesAndShutsDown(t *testing.T) {
	server := NewServer(&ServerConfig{
		scheme:     "http",
		bindAddr:   "127.0.0.1",
		bindPort:   "0",
		middleware: middleware.NewChain(),
	})

	errChan := make(chan error, 1)
	if err := server.Start(nil, errChan); err != nil {
		t.Fatalf("start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server.Shutdown(ctx)

	select {
	case err := <-errChan:
		t.Fatalf("unexpected serve error: %v", err)
	default:
	}
}
