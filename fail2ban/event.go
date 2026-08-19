package fail2ban

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"flowguard/iplist"
)

const DefaultEventSocketPath = "/run/flowguard/fail2ban.sock"

type Event struct {
	Operation string `json:"operation"`
	Jail      string `json:"jail"`
	Address   string `json:"address"`
}

func (e Event) validate() error {
	if e.Operation != "ban" && e.Operation != "unban" {
		return fmt.Errorf("unsupported operation %q", e.Operation)
	}
	if e.Jail == "" {
		return fmt.Errorf("jail is required")
	}
	if _, err := iplist.ParsePrefix(e.Address); err != nil {
		return err
	}
	return nil
}

// SendEvent delivers a best-effort runtime action notification to FlowGuard.
func SendEvent(socketPath string, event Event) error {
	if err := event.validate(); err != nil {
		return err
	}

	conn, err := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	if err := json.NewEncoder(conn).Encode(event); err != nil {
		return err
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("FlowGuard rejected Fail2Ban event")
	}
	return nil
}

type eventServer struct {
	listener net.Listener
	events   chan<- Event
	done     chan struct{}
	handlers sync.WaitGroup
	socket   os.FileInfo
}

func startEventServer(socketPath string, events chan<- Event) (*eventServer, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, fmt.Errorf("create Fail2Ban runtime directory: %w", err)
	}

	if info, err := os.Lstat(socketPath); err == nil {
		conn, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("Fail2Ban event socket is already in use")
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale Fail2Ban event socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect Fail2Ban event socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on Fail2Ban event socket: %w", err)
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		// Removal is handled below using the socket inode so closing an old
		// listener cannot unlink a replacement created by another process.
		unixListener.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("secure Fail2Ban event socket: %w", err)
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil {
		listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("inspect created Fail2Ban event socket: %w", err)
	}

	server := &eventServer{listener: listener, events: events, done: make(chan struct{}), socket: socketInfo}
	go server.serve()
	return server, nil
}

func (s *eventServer) serve() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.startHandler(conn)
	}
}

func (s *eventServer) startHandler(conn net.Conn) {
	s.handlers.Go(func() {
		s.handle(conn)
	})
}

func (s *eventServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))

	var event Event
	ok := json.NewDecoder(bufio.NewReader(conn)).Decode(&event) == nil && event.validate() == nil
	if ok {
		select {
		case s.events <- event:
		default:
			ok = false
		}
	}
	_ = json.NewEncoder(conn).Encode(struct {
		OK bool `json:"ok"`
	}{OK: ok})
}

func (s *eventServer) close(socketPath string) {
	if s == nil {
		return
	}
	_ = s.listener.Close()
	<-s.done
	s.handlers.Wait()
	if s.ownsSocketPath(socketPath) {
		_ = os.Remove(socketPath)
	}
}

func (s *eventServer) ownsSocketPath(socketPath string) bool {
	if s == nil || s.socket == nil {
		return false
	}
	info, err := os.Lstat(socketPath)
	return err == nil && info.Mode()&os.ModeSocket != 0 && os.SameFile(s.socket, info)
}
