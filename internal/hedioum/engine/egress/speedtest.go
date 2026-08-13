package egress

import (
	"encoding/binary"
	mrand "math/rand/v2"
	"net"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/hedioum/engine/tunproto"
)

const (
	speedtestMaxSeconds = 30
	speedtestChunk      = 64 * 1024
)

// handleSpeedtestStream measures raw tunnel capacity: on a download it streams
// random data for the requested (capped) duration; on an upload it drains. It is
// intentionally NOT rate-shaped — it reports the pipe's true throughput.
func handleSpeedtestStream(stream net.Conn) {
	dir, seconds, err := tunproto.ReadSpeedtestHeader(stream)
	if err != nil {
		return
	}
	if seconds == 0 || seconds > speedtestMaxSeconds {
		seconds = speedtestMaxSeconds
	}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)

	switch dir {
	case tunproto.SpeedDown:
		buf := make([]byte, speedtestChunk)
		fillPseudoRandom(buf)
		for time.Now().Before(deadline) {
			if _, err := stream.Write(buf); err != nil {
				return
			}
		}
	case tunproto.SpeedUp:
		_ = stream.SetReadDeadline(deadline)
		buf := make([]byte, speedtestChunk)
		for {
			if _, err := stream.Read(buf); err != nil {
				return
			}
		}
	}
}

// fillPseudoRandom fills b with non-compressible bytes (fast, non-crypto).
func fillPseudoRandom(b []byte) {
	for i := 0; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], mrand.Uint64())
	}
}
