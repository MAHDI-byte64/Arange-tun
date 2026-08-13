package mimic

import (
	"errors"
	"net"
	"strings"
	"time"
)

// errNoStartTLS means the peer did not perform the expected STARTTLS handshake
// (e.g. a probe speaking a different protocol) — the caller routes it to a decoy.
var errNoStartTLS = errors.New("mimic: peer did not request STARTTLS")

// STARTTLS mimics (SMTP, IMAP): a short plaintext protocol prologue that upgrades
// to TLS via STARTTLS, after which the TLS mimic (real TLS + channel-bound token
// auth) takes over. So on the wire the link looks like a mail server negotiating
// STARTTLS, with no domain required.

const starttlsTimeout = 8 * time.Second

// StartTLSMimic is the server side; it wraps a TLSMimic for the post-STARTTLS half.
type StartTLSMimic struct {
	Proto string // "smtp" | "imap"
	TLS   *TLSMimic
}

func (m *StartTLSMimic) Accept(conn net.Conn) (net.Conn, net.Conn, error) {
	if err := serverStartTLSPrologue(conn, m.Proto); err != nil {
		return nil, conn, err // not our client / bad prologue
	}
	return m.TLS.Accept(conn) // TLS handshake + channel auth begins on conn
}

func (m *StartTLSMimic) ProxyDecoy(replay net.Conn) { m.TLS.ProxyDecoy(replay) }
func (m *StartTLSMimic) Name() string               { return m.Proto }

// StartTLSClient is the client side; it wraps a TLSClient.
type StartTLSClient struct {
	Proto string
	TLS   *TLSClient
}

func (c *StartTLSClient) Dial(conn net.Conn) (net.Conn, error) {
	if err := clientStartTLSPrologue(conn, c.Proto); err != nil {
		return nil, err
	}
	return c.TLS.Dial(conn)
}

func (c *StartTLSClient) Name() string { return c.Proto }

// --- prologue exchanges (line-based, byte-by-byte so the TLS ClientHello that
// follows STARTTLS is never over-read) ---

func stReadLine(conn net.Conn) (string, error) {
	var b []byte
	buf := make([]byte, 1)
	for i := 0; i < 2048; i++ {
		if _, err := conn.Read(buf); err != nil {
			return "", err
		}
		b = append(b, buf[0])
		if buf[0] == '\n' {
			break
		}
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func stWrite(conn net.Conn, line string) error {
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

func serverStartTLSPrologue(conn net.Conn, proto string) error {
	_ = conn.SetDeadline(time.Now().Add(starttlsTimeout))
	defer conn.SetDeadline(time.Time{})

	switch proto {
	case "smtp":
		if err := stWrite(conn, "220 mail ESMTP"); err != nil {
			return err
		}
		if _, err := stReadLine(conn); err != nil { // EHLO/HELO
			return err
		}
		_ = stWrite(conn, "250-mail")
		_ = stWrite(conn, "250-STARTTLS")
		if err := stWrite(conn, "250 OK"); err != nil {
			return err
		}
		line, err := stReadLine(conn)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "STARTTLS") {
			return errNoStartTLS
		}
		return stWrite(conn, "220 2.0.0 Ready to start TLS")

	case "imap":
		if err := stWrite(conn, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready"); err != nil {
			return err
		}
		// Real IMAP clients (Thunderbird, openssl s_client -starttls imap, ...) issue
		// CAPABILITY and/or NOOP before STARTTLS. Answer those and keep reading until
		// STARTTLS, so a genuine client/probe is not bounced to the decoy after one
		// command. Our own client sends "<tag> STARTTLS" directly and matches on the
		// first iteration. Bounded to avoid an unbounded plaintext dialogue.
		for i := 0; i < 5; i++ {
			line, err := stReadLine(conn)
			if err != nil {
				return err
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return errNoStartTLS
			}
			tag, cmd := fields[0], strings.ToUpper(fields[1])
			switch cmd {
			case "STARTTLS":
				return stWrite(conn, tag+" OK Begin TLS negotiation now")
			case "CAPABILITY":
				_ = stWrite(conn, "* CAPABILITY IMAP4rev1 STARTTLS")
				if err := stWrite(conn, tag+" OK CAPABILITY completed"); err != nil {
					return err
				}
			case "NOOP":
				if err := stWrite(conn, tag+" OK NOOP completed"); err != nil {
					return err
				}
			default:
				return errNoStartTLS
			}
		}
		return errNoStartTLS

	default:
		return errNoStartTLS
	}
}

func clientStartTLSPrologue(conn net.Conn, proto string) error {
	_ = conn.SetDeadline(time.Now().Add(starttlsTimeout))
	defer conn.SetDeadline(time.Time{})

	switch proto {
	case "smtp":
		if _, err := stReadLine(conn); err != nil { // 220 greeting
			return err
		}
		if err := stWrite(conn, "EHLO hedioum"); err != nil {
			return err
		}
		for { // read 250 lines until the final one ("250 " with a space)
			l, err := stReadLine(conn)
			if err != nil {
				return err
			}
			if strings.HasPrefix(l, "250 ") {
				break
			}
		}
		if err := stWrite(conn, "STARTTLS"); err != nil {
			return err
		}
		_, err := stReadLine(conn) // 220 ready
		return err

	case "imap":
		if _, err := stReadLine(conn); err != nil { // * OK greeting
			return err
		}
		if err := stWrite(conn, "a1 STARTTLS"); err != nil {
			return err
		}
		_, err := stReadLine(conn) // a1 OK
		return err

	default:
		return errNoStartTLS
	}
}
