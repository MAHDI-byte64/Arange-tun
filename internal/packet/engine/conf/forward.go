package conf

import (
	"net"
)

type Forward struct {
	Listen_  string       `yaml:"listen"`
	Target   string       `yaml:"target"`
	Protocol string       `yaml:"protocol"`
	Listen   *net.UDPAddr `yaml:"-"`
}

func (c *Forward) setDefaults() {}
func (c *Forward) validate() []error {
	var errors []error
	l, err := validateAddr(c.Listen_, true)
	if err != nil {
		errors = append(errors, err)
	}
	c.Listen = l

	if err := validateHostPort(c.Target, true); err != nil {
		errors = append(errors, err)
	}

	return errors
}
