//go:build !linux

package shield

import (
	"fmt"
	"io"
	"runtime"
)

// NewKernel is only functional on Linux.
func NewKernel() (Shield, error) {
	return nil, fmt.Errorf("BPF LSM is not available on %s", runtime.GOOS)
}

// RunVictim is only functional on Linux.
func RunVictim(w io.Writer) error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}
