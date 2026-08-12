package server

import (
	"sort"
	"sync"
	"testing"
)

// The peer registry is what the panel's "is anything connected?" light is wired
// to, so the counting has to be exactly right: one client opens several
// connections (one per conf.Transport.Conn), and the client is only gone when
// the last of them closes. Undercount and a live tunnel goes dark; overcount and
// the light stays on forever, which is the bug this replaced.

func newTestServer() *Server {
	return &Server{peers: make(map[string]int)}
}

func TestPeerIsReportedWhileAnyConnectionIsOpen(t *testing.T) {
	s := newTestServer()
	const addr = "203.0.113.9:41234"

	if got := s.Peers(); len(got) != 0 {
		t.Fatalf("a server with no clients reported %v", got)
	}

	// One client, three connections — the shape a real client makes.
	s.addPeer(addr)
	s.addPeer(addr)
	s.addPeer(addr)
	if got := s.Peers(); len(got) != 1 || got[0] != addr {
		t.Fatalf("three connections from one client reported %v, want one entry for %s", got, addr)
	}

	// Losing some of them is not losing the client.
	s.removePeer(addr)
	s.removePeer(addr)
	if got := s.Peers(); len(got) != 1 {
		t.Fatalf("the client was dropped while it still had a connection open: %v", got)
	}

	// Losing the last one is.
	s.removePeer(addr)
	if got := s.Peers(); len(got) != 0 {
		t.Errorf("the client stayed listed after its last connection closed: %v — the panel would show green forever", got)
	}
}

func TestPeersListsEveryConnectedClient(t *testing.T) {
	s := newTestServer()
	s.addPeer("198.51.100.1:1111")
	s.addPeer("203.0.113.2:2222")

	got := s.Peers()
	sort.Strings(got)
	want := []string{"198.51.100.1:1111", "203.0.113.2:2222"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// Accept runs in the listener goroutine and every connection closes in its own,
// so the registry is written from many goroutines at once.
func TestPeerRegistryIsSafeUnderConcurrency(t *testing.T) {
	s := newTestServer()
	const addr = "203.0.113.9:41234"
	const n = 200

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.addPeer(addr)
			_ = s.Peers()
			s.removePeer(addr)
		}()
	}
	wg.Wait()

	if got := s.Peers(); len(got) != 0 {
		t.Errorf("after equal adds and removes the registry still holds %v", got)
	}
}
