package errors

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
)

func _(err error) bool {
	if err == nil || err == io.EOF {
		return false
	}

	// Don't retry on context errors, these should cancel immediately
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for recoverable network errors, all net.Error types are potentially recoverable
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		errno := syscallErr.Err
		return errno == syscall.ECONNRESET ||
			errno == syscall.EPIPE ||
			errno == syscall.ECONNABORTED ||
			errno == syscall.ETIMEDOUT ||
			errno == syscall.ECONNREFUSED || // Still worth retrying
			errno == syscall.EHOSTUNREACH || // Network might recover
			errno == syscall.ENETUNREACH // Network might recover
	}

	return true
}
