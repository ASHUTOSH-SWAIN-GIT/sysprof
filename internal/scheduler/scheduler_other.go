//go:build !linux

package scheduler

import (
	"fmt"
	"runtime"
)

// NewKernel is only functional on Linux.
func NewKernel() (Scheduler, error) {
	return nil, fmt.Errorf("scheduler control is not available on %s", runtime.GOOS)
}
