package mimic

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/securestream"
)

// TestSSHMimicInterfaceRoundTrip drives the SSH mimic through the ServerMimic /
// ClientMimic interfaces end-to-end.
func TestSSHMimicInterfaceRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const token = "iface-secret"
	var srv ServerMimic = &SSHMimic{Token: token, Filter: securestream.NewReplayFilter(0)}
	var cli ClientMimic = &SSHClient{Token: token}
	if srv.Name() != "ssh" || cli.Name() != "ssh" {
		t.Fatalf("names: %q %q", srv.Name(), cli.Name())
	}

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		authed, _, err := srv.Accept(conn)
		if err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(authed, buf); err != nil {
			srvErr <- err
			return
		}
		_, err = authed.Write(buf) // echo
		srvErr <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	authed, err := cli.Dial(conn)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	if _, err := authed.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(authed, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestSSHMimicProxyDecoy checks a failed auth is forwarded to the sshd decoy with
// the decoy's own banner consumed (so the peer never sees two banners).
func TestSSHMimicProxyDecoy(t *testing.T) {
	// Fake decoy sshd: send a banner, then echo everything.
	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer decoyLn.Close()
	go func() {
		c, err := decoyLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("SSH-2.0-decoyd\r\n"))
		io.Copy(c, c)
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m := &SSHMimic{Token: "server-token", Filter: securestream.NewReplayFilter(0), DecoyAddr: decoyLn.Addr().String()}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if _, replay, err := m.Accept(conn); err != nil {
			m.ProxyDecoy(replay)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(conn)
	if banner, _ := br.ReadString('\n'); len(banner) < 8 {
		t.Fatalf("mimic banner too short: %q", banner)
	}
	// Client SSH banner + a marker + enough padding that the securestream handshake
	// fails fast (needs ~52 bytes) rather than blocking on its deadline.
	payload := []byte("SSH-2.0-testclient\r\nDECOYMARK")
	payload = append(payload, make([]byte, 64)...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	echo := make([]byte, len(payload))
	n, _ := io.ReadFull(br, echo)
	got := echo[:n]
	if !bytes.Contains(got, []byte("DECOYMARK")) {
		t.Fatalf("decoy did not echo our data: %q", got)
	}
	if bytes.Contains(got, []byte("decoyd")) {
		t.Fatal("decoy's own banner leaked (should have been consumed)")
	}
}
