package spoof

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/unix"
)

// Carriers: the inner (already-encrypted) frame is smuggled inside a UDP, TCP or
// ICMP packet whose SOURCE IP is forged. The choice only changes which packet
// type the firewall sees; the payload is the same sealed frame either way.
const (
	carrierUDP  = "udp"
	carrierTCP  = "tcp"
	carrierICMP = "icmp"
)

// sender injects packets with a forged source IP through a raw IP socket
// (IP_HDRINCL: we build the whole IP header, so the kernel keeps our source
// address instead of substituting the real one).
type sender struct {
	fd        int
	srcIP     net.IP // forged source
	dstIP     net.IP // the peer's real IP
	srcPort   uint16
	dstPort   uint16
	transport string

	mu  sync.Mutex
	buf gopacket.SerializeBuffer
}

func newSender(transport string, srcIP, dstIP net.IP, srcPort, dstPort uint16) (*sender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w (need root)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}
	return &sender{
		fd: fd, srcIP: srcIP.To4(), dstIP: dstIP.To4(),
		srcPort: srcPort, dstPort: dstPort, transport: transport,
		buf: gopacket.NewSerializeBuffer(),
	}, nil
}

func (s *sender) send(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: uint16(rand.Intn(65535)),
		SrcIP: s.srcIP, DstIP: s.dstIP,
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	s.buf.Clear()

	var err error
	switch s.transport {
	case carrierTCP:
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(s.srcPort), DstPort: layers.TCPPort(s.dstPort),
			PSH: true, ACK: true, Window: 65535,
			Seq: rand.Uint32(), Ack: rand.Uint32(),
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(s.buf, opts, ip, tcp, gopacket.Payload(frame))
	case carrierICMP:
		ip.Protocol = layers.IPProtocolICMPv4
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       s.srcPort, Seq: uint16(rand.Intn(65535)),
		}
		err = gopacket.SerializeLayers(s.buf, opts, ip, icmp, gopacket.Payload(frame))
	default: // UDP
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(s.srcPort), DstPort: layers.UDPPort(s.dstPort)}
		_ = udp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(s.buf, opts, ip, udp, gopacket.Payload(frame))
	}
	if err != nil {
		return err
	}

	var addr unix.SockaddrInet4
	copy(addr.Addr[:], s.dstIP)
	return unix.Sendto(s.fd, s.buf.Bytes(), 0, &addr)
}

func (s *sender) close() {
	if s.fd >= 0 {
		unix.Close(s.fd)
		s.fd = -1
	}
}

// receiver captures the peer's forged packets with libpcap. A BPF filter keeps
// only packets of our carrier, aimed at our receive port, and — when known —
// from the peer's forged source IP, so almost nothing but our frames reaches
// user space; the AEAD drops anything that still slips through.
type receiver struct {
	handle    *pcap.Handle
	transport string
}

func newReceiver(iface, transport string, recvPort uint16, peerSpoofIP net.IP) (*receiver, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open %s: %w", iface, err)
	}
	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		// not fatal — some setups don't support it
		_ = err
	}
	var filter string
	src := ""
	if peerSpoofIP != nil {
		src = " and src host " + peerSpoofIP.String()
	}
	switch transport {
	case carrierTCP:
		filter = fmt.Sprintf("tcp and dst port %d%s", recvPort, src)
	case carrierICMP:
		filter = fmt.Sprintf("icmp and icmp[icmptype]=icmp-echo%s", src)
	default:
		filter = fmt.Sprintf("udp and dst port %d%s", recvPort, src)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("bpf %q: %w", filter, err)
	}
	return &receiver{handle: handle, transport: transport}, nil
}

// recv returns the next carried frame, or an error. It skips non-matching or
// empty packets rather than returning them.
func (r *receiver) recv() ([]byte, error) {
	for {
		data, _, err := r.handle.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return nil, err
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		payload := r.extract(p)
		if len(payload) == 0 {
			continue
		}
		return payload, nil
	}
}

func (r *receiver) extract(p gopacket.Packet) []byte {
	switch r.transport {
	case carrierTCP:
		if l := p.Layer(layers.LayerTypeTCP); l != nil {
			return l.(*layers.TCP).Payload
		}
	case carrierICMP:
		if l := p.Layer(layers.LayerTypeICMPv4); l != nil {
			return l.(*layers.ICMPv4).Payload
		}
	default:
		if l := p.Layer(layers.LayerTypeUDP); l != nil {
			return l.(*layers.UDP).Payload
		}
	}
	return nil
}

func (r *receiver) close() {
	if r.handle != nil {
		r.handle.Close()
	}
}

// randPort returns a random high source port for the forged packets.
func randPort() uint16 {
	return uint16(1024 + rand.Intn(64000))
}

func init() { rand.Seed(time.Now().UnixNano()) }
