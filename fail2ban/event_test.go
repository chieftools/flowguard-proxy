package fail2ban

import (
	"net"
	"testing"
	"time"
)

type closedEventListener struct{}

func (closedEventListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (closedEventListener) Close() error              { return nil }
func (closedEventListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestEventServerCloseWaitsForAcceptedHandlers(t *testing.T) {
	events := make(chan Event, 1)
	acceptDone := make(chan struct{})
	close(acceptDone)
	server := &eventServer{
		listener: closedEventListener{},
		events:   events,
		done:     acceptDone,
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	server.startHandler(serverConn)

	if _, err := clientConn.Write([]byte(`{"operation":"ban","jail":"request-limit",`)); err != nil {
		t.Fatalf("write partial event: %v", err)
	}
	closed := make(chan struct{})
	go func() {
		server.close("")
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("event server closed before the accepted handler finished")
	case <-time.After(25 * time.Millisecond):
	}

	if _, err := clientConn.Write([]byte(`"address":"198.51.100.211"}` + "\n")); err != nil {
		t.Fatalf("finish event: %v", err)
	}
	var response [32]byte
	if _, err := clientConn.Read(response[:]); err != nil {
		t.Fatalf("read event response: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("event server did not close after the handler finished")
	}

	select {
	case event := <-events:
		if event.Operation != "ban" || event.Jail != "request-limit" || event.Address != "198.51.100.211" {
			t.Fatalf("unexpected event: %#v", event)
		}
	default:
		t.Fatal("accepted handler did not enqueue its event before close returned")
	}
}
