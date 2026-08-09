package conf

import (
	"fmt"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
)

type PCAP struct {
	Sockbuf int `yaml:"sockbuf"`
}

func (p *PCAP) setDefaults(role string) {
	if p.Sockbuf == 0 {
		if role == "server" {
			p.Sockbuf = 8 * 1024 * 1024
		} else {
			p.Sockbuf = 4 * 1024 * 1024
		}
	}
}

func (p *PCAP) validate() []error {
	var errors []error

	if p.Sockbuf < 1024 {
		errors = append(errors, fmt.Errorf("PCAP sockbuf must be >= 1024 bytes"))
	}

	if p.Sockbuf > 100*1024*1024 {
		errors = append(errors, fmt.Errorf("PCAP sockbuf too large (max 100MB)"))
	}

	// Should be power of 2 for optimal performance, but not required
	if p.Sockbuf&(p.Sockbuf-1) != 0 {
		flog.Warnf("PCAP sockbuf (%d bytes) is not a power of 2 - consider using values like 4MB, 8MB, or 16MB for better performance", p.Sockbuf)
	}

	return errors
}
