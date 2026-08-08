package frp

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/utils"
)

// freeTCPPort returns a port that was free a moment ago. There is an inherent
// race between closing the probe listener and the engine rebinding it, but on a
// loopback test host nothing else is competing for it.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestFRPRoundTripTCP brings up a server and client and checks that a byte
// stream sent to an exposed port is echoed back by a TCP service behind the
// client.
func TestFRPRoundTripTCP(t *testing.T) {
	// A local echo service the client will forward to.
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	svcPort := svc.Addr().(*net.TCPAddr).Port

	ctlPort := freeTCPPort(t)
	expPort := freeTCPPort(t)
	log := utils.NewLogger("error")

	sc := config.ServerConfig{
		BindAddr:  fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport: "frp",
		Token:     "test-token-123",
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "frp",
		Token:      "test-token-123",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunServer(ctx, &sc, log, false)
	go RunClient(ctx, &cc, log)

	// The exposed port refuses connections until a client session exists, so
	// retry the dial until the tunnel is wired up.
	deadline := time.Now().Add(5 * time.Second)
	var conn net.Conn
	for {
		conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", expPort))
		if err == nil {
			// A connection is not proof the far end is ready — write and see if
			// it echoes; on a not-yet-ready tunnel the write is dropped.
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			if _, werr := conn.Write([]byte("ping")); werr == nil {
				buf := make([]byte, 4)
				if _, rerr := conn.Read(buf); rerr == nil && string(buf) == "ping" {
					break
				}
			}
			conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("tunnel did not carry traffic within the timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("hello-frp")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 9)
	if _, err := net.Conn(conn).Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-frp" {
		t.Fatalf("echo mismatch: got %q", buf)
	}
}

// TestFRPRoundTripStealth runs the TCP round trip with the Noise stealth layer
// on, so the whole connection is wrapped and obfuscated.
func TestFRPRoundTripStealth(t *testing.T) {
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	svcPort := svc.Addr().(*net.TCPAddr).Port

	ctlPort := freeTCPPort(t)
	expPort := freeTCPPort(t)
	log := utils.NewLogger("error")

	sc := config.ServerConfig{
		BindAddr:  fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport: "frp",
		Token:     "stealth-token",
		Stealth:   true,
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "frp",
		Token:      "stealth-token",
		Stealth:    true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunServer(ctx, &sc, log, false)
	go RunClient(ctx, &cc, log)

	deadline := time.Now().Add(6 * time.Second)
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", expPort))
		if err == nil {
			conn.SetDeadline(time.Now().Add(700 * time.Millisecond))
			if _, werr := conn.Write([]byte("hello-stealth")); werr == nil {
				buf := make([]byte, 13)
				if _, rerr := io.ReadFull(conn, buf); rerr == nil && string(buf) == "hello-stealth" {
					conn.Close()
					return
				}
			}
			conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("stealth tunnel did not carry traffic within the timeout")
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// TestFRPRoundTripUDP is the same round trip over the UDP mode: a datagram sent
// to an exposed UDP port is echoed back by a UDP service behind the client.
func TestFRPRoundTripUDP(t *testing.T) {
	// A local UDP echo service.
	svc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := svc.ReadFrom(buf)
			if err != nil {
				return
			}
			svc.WriteTo(buf[:n], addr)
		}
	}()
	svcPort := svc.LocalAddr().(*net.UDPAddr).Port

	ctlPort := freeTCPPort(t)
	expPort := freeUDPPort(t)
	log := utils.NewLogger("error")

	sc := config.ServerConfig{
		BindAddr:  fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport: "frpu",
		Token:     "test-token-udp",
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "frpu",
		Token:      "test-token-udp",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunServer(ctx, &sc, log, true)
	go RunClient(ctx, &cc, log)

	uconn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", expPort))
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()

	// UDP has no connection setup, so the only way to know the tunnel is ready
	// is to send and watch for the echo, retrying until it comes back.
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 16)
	for {
		uconn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := uconn.Write([]byte("hello-udp")); err != nil {
			t.Fatal(err)
		}
		uconn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := uconn.Read(buf)
		if err == nil && string(buf[:n]) == "hello-udp" {
			return // success
		}
		if time.Now().After(deadline) {
			t.Fatal("udp tunnel did not echo within the timeout")
		}
	}
}
