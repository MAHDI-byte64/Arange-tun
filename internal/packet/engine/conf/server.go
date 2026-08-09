package conf

import (
	"net"
)

type Server struct {
	Addr_ string       `yaml:"addr"`
	Addr  *net.UDPAddr `yaml:"-"`
}

func (s *Server) setDefaults() {}
func (s *Server) validate() []error {
	var errors []error
	addr, err := validateAddr(s.Addr_, true)
	if err != nil {
		errors = append(errors, err)
	}
	s.Addr = addr

	// if s.Timeout < 1 || s.Timeout > 3600 {
	// 	errors = append(errors, fmt.Errorf("server timeout must be between 1-3600 seconds"))
	// }
	// if s.Keepalive < 1 || s.Keepalive > 7200 {
	// 	errors = append(errors, fmt.Errorf("server keepalive must be between 1-7200 seconds"))
	// }

	return errors
}
