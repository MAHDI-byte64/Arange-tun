// Package socksproxy is a minimal SOCKS5 proxy whose outbound connections are
// made through a caller-supplied dialer. It is shared by the tunnels that expose
// a local SOCKS5 for a panel outbound — WireGuard (dialing through the userspace
// netstack) and SSH (dialing through the SSH connection). The bind is always
// loopback, so offering no authentication is not an exposure, and the relay
// counts the bytes that cross the tunnel into the per-tunnel metrics.
package socksproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/metrics"

	"github.com/sirupsen/logrus"
)

// DialFunc dials a target through some network — a tunnel's own transport.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Serve runs the SOCKS5 proxy on ln until ctx ends: no authentication, CONNECT
// only, every target dialed through dial.
func Serve(ctx context.Context, ln net.Listener, dial DialFunc, logger *logrus.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handle(ctx, conn, dial, logger)
	}
}

func handle(ctx context.Context, client net.Conn, dial DialFunc, logger *logrus.Logger) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: version, method count, methods. We only offer "no auth" (0x00).
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: version, command, reserved, address type, address, port.
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		_ = writeReply(client, 0x07)
		return
	}

	host, err := readAddr(client, req[3])
	if err != nil {
		_ = writeReply(client, 0x08) // address type not supported
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(client, portBuf[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf[:]))))

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	remote, err := dial(dctx, "tcp", target)
	cancel()
	if err != nil {
		if logger != nil {
			logger.Debugf("socks5: cannot reach %s: %v", target, err)
		}
		_ = writeReply(client, 0x05) // connection refused
		return
	}
	defer remote.Close()

	if err := writeReply(client, 0x00); err != nil { // success
		return
	}
	_ = client.SetDeadline(time.Time{})

	relay(client, remote)
}

// readAddr reads the destination host for the given address type.
func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

// writeReply sends a reply with the given status and a zero bound address.
func writeReply(w io.Writer, status byte) error {
	_, err := w.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// relay splices the SOCKS client and the tunnelled remote, counting the traffic
// that crossed the tunnel: bytes from the remote are traffic in, bytes to it are
// traffic out.
func relay(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyCounted(client, remote, true) // remote → client (in)
		client.Close()
		remote.Close()
	}()
	go func() {
		defer wg.Done()
		copyCounted(remote, client, false) // client → remote (out)
		remote.Close()
		client.Close()
	}()
	wg.Wait()
}

func copyCounted(dst io.Writer, src io.Reader, inbound bool) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if inbound {
				metrics.AddBytes(uint64(n), 0)
			} else {
				metrics.AddBytes(0, uint64(n))
			}
		}
		if rerr != nil {
			return
		}
	}
}
