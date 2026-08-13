package mimic

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/securestream"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/tlscert"
)

// This is the regression guard for the single most important low-level stealth
// property: every mimic's FIRST bytes on the wire must be "protocol-shaped" (a
// printable-ASCII protocol prefix such as an SSH banner / SMTP-IMAP greeting, or a
// TLS record header 0x16 0x03). The GFW's fully-encrypted-traffic heuristic
// (USENIX Security 2023) inspects the first ~6 bytes and BLOCKS flows that look
// random; a mimic that ever emitted a high-entropy prefix would be instantly
// blockable. If a future change makes any mimic write a random prefix first, this
// test fails.

// firstWriteTap records the first bytes a side writes to the wire (up to 16).
type firstWriteTap struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (t *firstWriteTap) Write(p []byte) (int, error) {
	t.mu.Lock()
	if len(t.buf) < 16 {
		t.buf = append(t.buf, p...)
		if len(t.buf) > 16 {
			t.buf = t.buf[:16]
		}
	}
	t.mu.Unlock()
	return t.Conn.Write(p)
}

func (t *firstWriteTap) first() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := make([]byte, len(t.buf))
	copy(b, t.buf)
	return b
}

// protocolShaped implements the GFW exemption test: the prefix is a TLS record
// (0x16 0x03 ...) OR its first up-to-6 bytes are all printable ASCII.
func protocolShaped(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03 {
		return true // TLS record header (ClientHello / ServerHello)
	}
	n := len(b)
	if n > 6 {
		n = 6
	}
	for _, c := range b[:n] {
		if c < 0x20 || c > 0x7e { // strictly printable ASCII
			return false
		}
	}
	return true
}

func tlsFirstByteServer(t *testing.T, token string) *TLSMimic {
	t.Helper()
	cert, err := tlscert.LoadOrCreate(t.TempDir(), "example")
	if err != nil {
		t.Fatal(err)
	}
	return &TLSMimic{
		Token:          token,
		Filter:         securestream.NewReplayFilter(0),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
	}
}

// TestMimicFirstBytesProtocolShaped drives every mimic's real client+server over a
// loopback connection and asserts BOTH directions' first wire bytes are
// protocol-shaped (never a high-entropy prefix).
func TestMimicFirstBytesProtocolShaped(t *testing.T) {
	const token = "first-byte-secret"

	cases := []struct {
		name string
		srv  ServerMimic
		cli  ClientMimic
	}{
		{"ssh", &SSHMimic{Token: token, Filter: securestream.NewReplayFilter(0)}, &SSHClient{Token: token}},
		{"tls", tlsFirstByteServer(t, token), &TLSClient{Token: token, ServerName: "example"}},
		{"smtp", &StartTLSMimic{Proto: "smtp", TLS: tlsFirstByteServer(t, token)}, &StartTLSClient{Proto: "smtp", TLS: &TLSClient{Token: token, ServerName: "example"}}},
		{"imap", &StartTLSMimic{Proto: "imap", TLS: tlsFirstByteServer(t, token)}, &StartTLSClient{Proto: "imap", TLS: &TLSClient{Token: token, ServerName: "example"}}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			sfCh := make(chan []byte, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					sfCh <- nil
					return
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				tap := &firstWriteTap{Conn: conn}
				authed, replay, _ := tc.srv.Accept(tap)
				_, _ = authed, replay
				sfCh <- tap.first()
			}()

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			ctap := &firstWriteTap{Conn: conn}
			_, _ = tc.cli.Dial(ctap)

			clientFirst := ctap.first()
			var serverFirst []byte
			select {
			case serverFirst = <-sfCh:
			case <-time.After(6 * time.Second):
				t.Fatal("server side did not produce first bytes")
			}

			if !protocolShaped(clientFirst) {
				t.Fatalf("%s: client first bytes are NOT protocol-shaped: %q (%v)", tc.name, clientFirst, clientFirst)
			}
			if !protocolShaped(serverFirst) {
				t.Fatalf("%s: server first bytes are NOT protocol-shaped: %q (%v)", tc.name, serverFirst, serverFirst)
			}
		})
	}
}

// TestProtocolShapedHelper locks the exemption predicate itself.
func TestProtocolShapedHelper(t *testing.T) {
	good := [][]byte{
		[]byte("SSH-2.0-OpenSSH_8.9"),  // SSH banner
		[]byte("220 mail ESMTP"),       // SMTP greeting
		[]byte("* OK [CAPABILITY"),     // IMAP greeting
		{0x16, 0x03, 0x01, 0x00, 0x05}, // TLS record
	}
	for _, b := range good {
		if !protocolShaped(b) {
			t.Errorf("should be protocol-shaped: %q", b)
		}
	}
	bad := [][]byte{
		{0x9f, 0x2c, 0xe1, 0x77, 0x04, 0xbb}, // high-entropy
		{},                                   // empty
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, // non-printable, non-TLS
	}
	for _, b := range bad {
		if protocolShaped(b) {
			t.Errorf("should NOT be protocol-shaped: %v", b)
		}
	}
}
