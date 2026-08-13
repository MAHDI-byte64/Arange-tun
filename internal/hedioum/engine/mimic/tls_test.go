package mimic

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/securestream"
	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/tlscert"
)

func newTLSServer(t *testing.T, token string) (*TLSMimic, net.Listener) {
	t.Helper()
	cert, err := tlscert.LoadOrCreate(t.TempDir(), "example")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &TLSMimic{
		Token:          token,
		Filter:         securestream.NewReplayFilter(0),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
	}
	return m, ln
}

// TestTLSMimicRoundTrip: uTLS client ↔ stdlib server, channel-bound auth, data echo.
func TestTLSMimicRoundTrip(t *testing.T) {
	const token = "tls-round-trip-secret"
	srv, ln := newTLSServer(t, token)
	defer ln.Close()

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
		buf := make([]byte, 5)
		if _, err := io.ReadFull(authed, buf); err != nil {
			srvErr <- err
			return
		}
		_, err = authed.Write(buf)
		srvErr <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cli := &TLSClient{Token: token, ServerName: "example"}
	authed, err := cli.Dial(conn)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	if _, err := authed.Write([]byte("howdy")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(authed, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "howdy" {
		t.Fatalf("echo mismatch: %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestTLSMimicALPNIsHTTP11 guards the ALPN fix: a client offering h2 + http/1.1 must
// negotiate http/1.1 (never h2), because the decoys speak HTTP/1.1 — negotiating h2
// left real browsers with an empty page (found in live testing).
func TestTLSMimicALPNIsHTTP11(t *testing.T) {
	srv, ln := newTLSServer(t, "server-token")
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if _, replay, err := srv.Accept(conn); err != nil {
			srv.ProxyDecoy(replay)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "example", NextProtos: []string{"h2", "http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated ALPN = %q, want http/1.1 (h2 breaks the decoy)", got)
	}
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	tc.SetReadDeadline(time.Now().Add(4 * time.Second))
	got, _ := io.ReadAll(tc)
	if !bytes.Contains(got, []byte("200 OK")) {
		t.Fatalf("decoy did not respond over the negotiated protocol: %q", got)
	}
}

// TestTLSMimicWrongTokenToWebDecoy: a wrong token (or a browser) gets the web page.
func TestTLSMimicWebDecoy(t *testing.T) {
	srv, ln := newTLSServer(t, "server-token")
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if _, replay, err := srv.Accept(conn); err != nil {
			srv.ProxyDecoy(replay) // DecoyAddr == "" -> built-in page
		}
	}()

	// A "browser": real TLS (accept self-signed) then a plain HTTP GET.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "example"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	tc.SetReadDeadline(time.Now().Add(4 * time.Second))
	// The Apache default page spans several KB / TLS records; drain until the
	// connection closes so the assertions don't race a partial first read.
	got, _ := io.ReadAll(tc)
	for _, want := range []string{"200 OK", "Server: Apache", "It works", "Apache2 Ubuntu Default Page"} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("web decoy response missing %q: %q", want, got)
		}
	}
}
