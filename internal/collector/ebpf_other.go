//go:build !linux

package collector

import (
	"fmt"
	"runtime"
)

// NewEBPF is only functional on Linux.
func NewEBPF() (Collector, error) {
	return nil, fmt.Errorf("eBPF is not available on %s, use --fake or run inside a Linux VM", runtime.GOOS)
}
