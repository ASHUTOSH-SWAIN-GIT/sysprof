//go:build !linux

package sockbypass

import (
	"fmt"
	"runtime"
)

// NewKernel is only functional on Linux.
func NewKernel() (Bypass, error) {
	return nil, fmt.Errorf("sockmap is not available on %s", runtime.GOOS)
}
