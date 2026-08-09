package forward

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/pkg/buffer"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

func (f *Forward) serveUDP(ctx context.Context, conn *net.UDPConn) {
	flog.Infof("UDP forwarder listening on %s -> %s", f.listenAddr, f.targetAddr)

	buf := make([]byte, buffer.UPool)
	for {
		n, cAddr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		f.handleUDPConn(ctx, conn, cAddr, buf[:n])
	}
}

func (f *Forward) handleUDPConn(ctx context.Context, conn *net.UDPConn, cAddr netip.AddrPort, buf []byte) {
	strm, new, k, err := f.client.UDP(ctx, cAddr.String(), f.targetAddr)
	if err != nil {
		flog.Errorf("failed to establish UDP stream for %s -> %s: %v", cAddr, f.targetAddr, err)
		return
	}

	strm.SetWriteDeadline(time.Now().Add(8 * time.Second))
	_, err = strm.Write(buf)
	strm.SetWriteDeadline(time.Time{})
	if err != nil {
		flog.Errorf("failed to forward bytes from %s -> %s: %v", cAddr, f.targetAddr, err)
		f.client.CloseUDP(k)
		return
	}

	if new {
		flog.Infof("accepted UDP connection %d for %s -> %s", strm.SID(), cAddr, f.targetAddr)
		go func() {
			defer f.client.CloseUDP(k)
			f.handleUDPStrm(ctx, strm, conn, cAddr)
		}()
	}
}

func (f *Forward) handleUDPStrm(ctx context.Context, strm tnet.Strm, conn *net.UDPConn, cAddr netip.AddrPort) {
	stop := context.AfterFunc(ctx, func() { strm.Close() })
	defer stop()

	buf := make([]byte, buffer.UPool)
	for {
		strm.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := strm.Read(buf)
		strm.SetReadDeadline(time.Time{})
		if err != nil {
			flog.Errorf("UDP stream %d read failed for %s -> %s: %v", strm.SID(), cAddr, f.targetAddr, err)
			return
		}
		_, err = conn.WriteToUDPAddrPort(buf[:n], cAddr)
		if err != nil {
			flog.Errorf("UDP stream %d write failed for %s -> %s: %v", strm.SID(), cAddr, f.targetAddr, err)
			return
		}
	}
}
