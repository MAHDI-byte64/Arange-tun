package egress

import (
	"net"
	"testing"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/tunproto"
)

func TestSpeedtestDownload(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	done := make(chan struct{})
	go func() { handleSpeedtestStream(s); s.Close(); close(done) }()

	// dir + u16 seconds (the stream-type byte is consumed by the dispatcher).
	if _, err := c.Write([]byte{tunproto.SpeedDown, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, speedtestChunk)
	total := 0
	for {
		n, err := c.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	if total == 0 {
		t.Fatal("download produced no data")
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("handler did not stop near the deadline")
	}
}

func TestSpeedtestUploadDrains(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	done := make(chan struct{})
	go func() { handleSpeedtestStream(s); s.Close(); close(done) }()

	if _, err := c.Write([]byte{tunproto.SpeedUp, 0x00, 0x01}); err != nil {
		t.Fatal(err)
	}
	// Push data for ~1s; the egress should drain it without error until its deadline.
	buf := make([]byte, speedtestChunk)
	c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	sent := 0
	for {
		n, err := c.Write(buf)
		sent += n
		if err != nil {
			break // egress closed at its deadline
		}
	}
	if sent == 0 {
		t.Fatal("upload sent no data")
	}
	<-done
}
