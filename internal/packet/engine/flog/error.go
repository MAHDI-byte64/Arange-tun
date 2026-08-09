package flog

import (
	"errors"
	"io"
	"net"
	"syscall"
)

func WErr(err error) error {
	if minLevel == 0 {
		return err
	}
	if err == nil {
		return err
	}

	if errors.Is(err, io.EOF) {
		// return NormalClosure
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EPIPE) {
		// return PipeError
		return nil
	}

	if errors.Is(err, syscall.ECONNRESET) {
		// return ConnectionReset
		return nil
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// return NetworkTimeout
		return nil
	}

	// Handle wrapped errors
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return WErr(opErr.Err)
	}

	return err
}
