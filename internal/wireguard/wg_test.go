package wireguard

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/utils"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestWireGuardClientSocks brings up a userspace WireGuard peer to act as the
// "server", runs our client against it, and proves that a SOCKS5 CONNECT through
// the client reaches a TCP service living on the server's tunnel address — i.e.
// traffic really egresses through WireGuard.
func TestWireGuardClientSocks(t *testing.T) {
	srvPriv, srvPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cliPriv, cliPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	srvPort := freeUDPPort(t)
	socksPort := freeTCPPort(t)

	// --- The WireGuard "server" peer (userspace), hosting an echo service on
	// 10.0.0.1:5555 inside the tunnel. ---
	srvTun, srvNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	srvDev := device.NewDevice(srvTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "srv "))
	spHex, _ := keyHex(srvPriv)
	cpubHex, _ := keyHex(cliPub)
	if err := srvDev.IpcSet(
		"private_key=" + spHex + "\n" +
			"listen_port=" + strconv.Itoa(srvPort) + "\n" +
			"public_key=" + cpubHex + "\n" +
			"allowed_ip=10.0.0.2/32\n"); err != nil {
		t.Fatal(err)
	}
	if err := srvDev.Up(); err != nil {
		t.Fatal(err)
	}
	defer srvDev.Close()

	echoLn, err := srvNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5555})
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
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

	// --- Our client: WireGuard in userspace + SOCKS5 on socksPort. ---
	wc := &config.WireGuardConfig{
		Role:             "client",
		ClientPrivateKey: cliPriv,
		ClientAddress:    "10.0.0.2/32",
		PeerPublicKey:    srvPub,
		Endpoint:         "127.0.0.1:" + strconv.Itoa(srvPort),
		AllowedIPs:       "10.0.0.1/32",
		SocksBind:        "127.0.0.1",
		SocksPort:        socksPort,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunClient(ctx, wc, utils.NewLogger("error"))

	// --- Drive it: SOCKS5 CONNECT to the service on the server's tunnel IP. ---
	proxy := "127.0.0.1:" + strconv.Itoa(socksPort)
	deadline := time.Now().Add(8 * time.Second)
	for {
		if c := socks5Connect(proxy, "10.0.0.1", 5555); c != nil {
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write([]byte("hello-wg")); err == nil {
				buf := make([]byte, 8)
				if _, err := io.ReadFull(c, buf); err == nil && string(buf) == "hello-wg" {
					c.Close()
					return // success
				}
			}
			c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("SOCKS5-over-WireGuard did not carry traffic within the timeout")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// socks5Connect performs a no-auth SOCKS5 CONNECT to host:port and returns the
// established connection, or nil on any failure.
func socks5Connect(proxy, host string, port int) net.Conn {
	c, err := net.DialTimeout("tcp", proxy, time.Second)
	if err != nil {
		return nil
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0x00 {
		c.Close()
		return nil
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		c.Close()
		return nil
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
		c.Close()
		return nil
	}
	c.SetDeadline(time.Time{})
	return c
}
