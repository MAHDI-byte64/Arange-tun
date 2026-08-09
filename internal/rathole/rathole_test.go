package rathole

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

// TestRatholeRoundTripTCP brings up a rathole server and client and checks a
// byte stream is echoed back by a TCP service behind the client — exercising the
// control handshake, a data channel, and TCP forwarding.
func TestRatholeRoundTripTCP(t *testing.T) {
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
		Transport: "rathole",
		Token:     "test-token-rh",
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "rathole",
		Token:      "test-token-rh",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunServer(ctx, &sc, log, false)
	go RunClient(ctx, &cc, log)

	deadline := time.Now().Add(6 * time.Second)
	var conn net.Conn
	for {
		conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", expPort))
		if err == nil {
			conn.SetDeadline(time.Now().Add(700 * time.Millisecond))
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
		time.Sleep(150 * time.Millisecond)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("hello-rathole")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 13)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-rathole" {
		t.Fatalf("echo mismatch: got %q", buf)
	}
}

// TestRatholeRoundTripStealth runs the TCP round trip with the Noise stealth
// layer on, wrapping the control channel and each data channel.
func TestRatholeRoundTripStealth(t *testing.T) {
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
		Transport: "rathole",
		Token:     "stealth-rh",
		Stealth:   true,
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "rathole",
		Token:      "stealth-rh",
		Stealth:    true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunServer(ctx, &sc, log, false)
	go RunClient(ctx, &cc, log)

	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", expPort))
		if err == nil {
			conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
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

// TestRatholeRoundTripTLS runs the TCP round trip with the uTLS obfuscation
// mode on, wrapping the control channel and each data channel in TLS.
func TestRatholeRoundTripTLS(t *testing.T) {
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
		Transport: "rathole",
		Token:     "tls-rh",
		Obfs:      "tls",
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "rathole",
		Token:      "tls-rh",
		Obfs:       "tls",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunServer(ctx, &sc, log, false)
	go RunClient(ctx, &cc, log)

	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", expPort))
		if err == nil {
			conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
			if _, werr := conn.Write([]byte("hello-tls-xxxx")); werr == nil {
				buf := make([]byte, 14)
				if _, rerr := io.ReadFull(conn, buf); rerr == nil && string(buf) == "hello-tls-xxxx" {
					conn.Close()
					return
				}
			}
			conn.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("tls tunnel did not carry traffic within the timeout")
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// TestRatholeRoundTripUDP is the same round trip over the UDP mode.
func TestRatholeRoundTripUDP(t *testing.T) {
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
		Transport: "ratholeu",
		Token:     "test-token-rh-udp",
		Ports:     []string{fmt.Sprintf("%d=127.0.0.1:%d", expPort, svcPort)},
	}
	cc := config.ClientConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", ctlPort),
		Transport:  "ratholeu",
		Token:      "test-token-rh-udp",
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

	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 16)
	for {
		uconn.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := uconn.Write([]byte("hello-udp")); err != nil {
			t.Fatal(err)
		}
		uconn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, err := uconn.Read(buf)
		if err == nil && string(buf[:n]) == "hello-udp" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("udp tunnel did not echo within the timeout")
		}
	}
}
