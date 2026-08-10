package spoof

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ExpandIPs turns a comma/space/newline list of specs into concrete IPv4
// addresses. Each spec is one of:
//   - a single IP          "1.2.3.4"
//   - a hyphen range       "1.2.3.4-1.2.3.20"  or  "1.2.3.4-20"
//   - a CIDR block         "1.2.3.0/24"
//
// The result is capped so a wide CIDR cannot blow up into millions of entries.
func ExpandIPs(spec string, max int) ([]string, error) {
	if max <= 0 {
		max = 4096
	}
	var out []string
	seen := map[string]bool{}
	add := func(ip string) bool {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
		return len(out) < max
	}

	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r'
	})
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		switch {
		case strings.Contains(f, "/"):
			ips, err := expandCIDR(f)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !add(ip) {
					return out, nil
				}
			}
		case strings.Contains(f, "-"):
			ips, err := expandRange(f)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !add(ip) {
					return out, nil
				}
			}
		default:
			ip := net.ParseIP(f)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("invalid IPv4 %q", f)
			}
			if !add(ip.To4().String()) {
				return out, nil
			}
		}
	}
	return out, nil
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 CIDR is supported: %q", cidr)
	}
	start := binary.BigEndian.Uint32(ipnet.IP.To4())
	ones, bits := ipnet.Mask.Size()
	count := uint32(1) << uint(bits-ones)
	var out []string
	for i := uint32(0); i < count; i++ {
		out = append(out, uint32ToIP(start+i))
	}
	return out, nil
}

func expandRange(r string) ([]string, error) {
	lo, hi, ok := strings.Cut(r, "-")
	if !ok {
		return nil, fmt.Errorf("invalid range %q", r)
	}
	lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
	loIP := net.ParseIP(lo)
	if loIP == nil || loIP.To4() == nil {
		return nil, fmt.Errorf("invalid range start %q", lo)
	}
	start := binary.BigEndian.Uint32(loIP.To4())

	var end uint32
	if strings.Contains(hi, ".") {
		hiIP := net.ParseIP(hi)
		if hiIP == nil || hiIP.To4() == nil {
			return nil, fmt.Errorf("invalid range end %q", hi)
		}
		end = binary.BigEndian.Uint32(hiIP.To4())
	} else {
		// "1.2.3.4-20": the end shares the first three octets.
		var last uint32
		if _, err := fmt.Sscanf(hi, "%d", &last); err != nil || last > 255 {
			return nil, fmt.Errorf("invalid range end %q", hi)
		}
		end = (start &^ 0xff) | last
	}
	if end < start {
		return nil, fmt.Errorf("range end before start: %q", r)
	}
	var out []string
	for ip := start; ip <= end; ip++ {
		out = append(out, uint32ToIP(ip))
	}
	return out, nil
}

func uint32ToIP(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b).String()
}
