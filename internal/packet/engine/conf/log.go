package conf

import (
	"fmt"
)

type Log struct {
	Level_ string `yaml:"level"`

	Level int `yaml:"-"`
}

func (l *Log) setDefaults() {
	if l.Level_ == "" {
		l.Level_ = "none"
	}
}

func (l *Log) validate() []error {
	var errors []error
	switch l.Level_ {
	case "none":
		l.Level = -1
	case "debug":
		l.Level = 0
	case "info":
		l.Level = 1
	case "warn":
		l.Level = 2
	case "error":
		l.Level = 3
	case "fatal":
		l.Level = 4
	default:
		errors = append(errors, fmt.Errorf("invalid logging level '%s': must be one of none, debug, info, warn, error, fatal", l.Level_))
	}
	return errors
}
