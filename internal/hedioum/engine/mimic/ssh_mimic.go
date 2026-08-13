package mimic

import (
	"io"
	"net"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/securestream"
)

// SSHMimic disguises the tunnel as SSH: an SSH-2.0 banner exchange followed by
// the securestream AEAD handshake. Unauthenticated peers are routed to a real
// sshd decoy. It wraps the (battle-tested) PerformServerHandshake.
type SSHMimic struct {
	Token     string
	Filter    *securestream.ReplayFilter
	DecoyAddr string
	// Banner returns the SSH banner to present; it should mirror the real decoy
	// sshd so a genuine SSH client routed to the decoy completes key exchange. If
	// nil or "", a synthesized banner is used.
	Banner func() string
}

func (m *SSHMimic) Accept(conn net.Conn) (net.Conn, net.Conn, error) {
	banner := ""
	if m.Banner != nil {
		banner = m.Banner()
	}
	return PerformServerHandshake(conn, m.Token, m.Filter, banner)
}

// ProxyDecoy bridges an unauthorized peer to the real sshd. Because our mimic
// already sent the peer an SSH banner, we consume the decoy's own banner first
// so the peer does not receive two banners (which would corrupt its SSH session).
func (m *SSHMimic) ProxyDecoy(replay net.Conn) {
	defer replay.Close()

	decoyConn, err := net.DialTimeout("tcp", m.DecoyAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer decoyConn.Close()

	_ = ConsumeDecoyServerBanner(decoyConn)

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(decoyConn, replay); errCh <- err }()
	go func() { _, err := io.Copy(replay, decoyConn); errCh <- err }()
	<-errCh
}

func (m *SSHMimic) Name() string { return "ssh" }

// SSHClient is the client side of the SSH mimic.
type SSHClient struct {
	Token string
}

func (c *SSHClient) Dial(conn net.Conn) (net.Conn, error) {
	return PerformClientHandshake(conn, c.Token)
}

func (c *SSHClient) Name() string { return "ssh" }
